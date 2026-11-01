"""The validation matrix (design/lab.md §2.4): every row applied, scanned, attacked and validated, then compared.

A cell counts as proven only when the CA's decision line carries the expected reason, the HTTP-01 perspectives
were answered by the expected hosts, the data plane was in the expected state during the attack, and the scanner's
collected record holds the facts its label rests on. Everything the verdict uses is written to
lab/logs/<timestamp>-matrix/ (latest-matrix links to the newest run).
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import check
import console
import labctl
from console import log
from render import SCENARIOS
from render.topology import FRR_IMAGE, LAB, LAB_IMAGE

from hijackscan.collect.resolver_check import passes

# scenario, attack mode, expected scanner label, expected CA decision for the attacker, regex the decision line
# must match, host (X-Lab-Host) that must have answered each HTTP-01 perspective (None: no HTTP-01 may run),
# data-plane state during the attack (who answers at the victim's web and nameserver addresses).
Row = tuple[str, str, str, str, str, dict[str, str] | None, dict[str, str]]
HIJACKED = {"primary": "attacker", "r1": "attacker", "r2": "attacker", "r3": "victim", "r4": "attacker"}
FILTERED = {"primary": "victim", "r1": "victim", "r2": "attacker", "r3": "victim", "r4": "victim"}
WEB = {"web": "attacker", "ns": "victim"}
BOTH = {"web": "attacker", "ns": "attacker"}
NONE = {"web": "victim", "ns": "victim"}
ROWS: list[Row] = [
    ("baseline", "web", "open-web", "ISSUED", r"ISSUED", HIJACKED, WEB),
    ("tight-maxlength", "web", "contested", "REFUSED", r"domain control not demonstrated", FILTERED, NONE),
    ("caa-unsigned", "web", "caa-erasable", "REFUSED", r"accounturi pins https://ca\.lab/acct/legit", None, WEB),
    ("caa-unsigned", "web+ns", "caa-erasable", "ISSUED", r"ISSUED", HIJACKED, BOTH),
    ("caa-signed", "web+ns", "closed", "REFUSED", r"reachable but bogus", None, BOTH),
]
ALL_VICTIM = {p: "victim" for p in HIJACKED}  # the control run, attack off

# What each row proves, in one sentence for the reader: the configuration, what the forged route does to it, and
# what the CA's decision therefore has to be. Shown under the row banner; the evidence follows.
ROW_WHY: dict[tuple[str, str], str] = {
    ("baseline", "web"): "loose ROA (/24, maxLength 28), no CAA, unsigned zone: the forged /28 is RPKI-valid, so "
    "every CA perspective except the victim's own AS lands on the attacker, and the attacker gets the certificate.",
    ("tight-maxlength", "web"): "one change, ROA maxLength 24: the same forged /28 is now RPKI-invalid, both transits "
    "drop it, the CA's checks reach the real host, and the attacker is refused for lack of domain control.",
    ("caa-unsigned", "web"): "CAA with accounturi, only the web address hijacked: the real nameserver still serves "
    "the CAA record, the account pin refuses the attacker before any HTTP-01 runs.",
    ("caa-unsigned", "web+ns"): "the same CAA, nameserver hijacked too: the zone is unsigned, so the forged "
    "nameserver answers 'no CAA' unchallenged and the attacker gets the certificate (caa-erasable).",
    ("caa-signed", "web+ns"): "the same CAA in a signed zone, both addresses hijacked: the forged nameserver cannot "
    "sign, the validating resolver answers SERVFAIL, the CA fails closed. The project's central claim.",
}

CA_LEGEND = [
    ("[request  ]", "what is asked: the domain, the ACME account (attacker or legit), the method"),
    ("[dns      ]", "one lookup through the validating resolver: rcode and AD flag (ad=1 validated, SERVFAIL bogus)"),
    ("[caa      ]", "the CAA walk victim.rs -> rs -> . (RFC 8659) and what the issue tag allows (RFC 8657)"),
    ("[http-01  ]", "one perspective: behind which AS it sits and which host answered (attacker = hijacked route)"),
    ("[quorum   ]", "CA/B MPIC rule: the primary and at least 3 of 4 remotes must corroborate"),
    ("[decision ]", "ISSUED or REFUSED and the reason; this line is what the matrix checks"),
    ("attack ...", "control plane (paths at the collector) and data plane (who answers the web and ns addresses)"),
]


def scan_evidence(build: Path, sc: dict, log_to: Path) -> tuple[str, list[str]]:
    """The risk label from the scanner's summary line `victim.rs  CRITICAL 10.0  open-web`, and every way the
    collected record fails to hold the facts the label rests on (empty: the evidence is in place)."""
    r = labctl.scan(build, sc, True, capture=True)
    log_to.write_text(r.stdout + (f"\n--- stderr ---\n{r.stderr}" if r.stderr else ""))
    m = re.search(rf"^{re.escape(sc['domain'])}\s+(\S+)\s+(\S+)\s+(\S+)", r.stdout, re.M)
    label = f"{m.group(3)} ({m.group(1)} {m.group(2)})" if m else "?"
    collected = build / "data" / "collected" / f"{sc['domain']}.json"
    if not collected.exists():
        return label, [f"no collected record at {collected} (scanner exit {r.returncode})"]
    rec = json.loads(collected.read_text())
    problems = []
    if rec["errors"]:
        problems.append(f"errors non-empty: {rec['errors']}")
    web = rec["addresses"].get(sc["victim"]["web"], {})
    if web.get("prefix") != sc["victim"]["prefix"]:
        problems.append(
            f"prefix mismatch: {sc['victim']['web']} seen in {web.get('prefix')}, not {sc['victim']['prefix']}"
        )
    if web.get("rpki_state") != "valid":
        problems.append(f"rpki_state {web.get('rpki_state')!r}, not 'valid'")
    want_max = sc["roas"][0]["max_length"]
    if not any(roa["max_length"] == want_max for roa in web.get("roas", [])):
        problems.append(f"no covering ROA with max_length {want_max}: {web.get('roas')}")
    if not passes(rec["resolver_check"]):
        problems.append(f"resolver_check not passing: {rec['resolver_check']}")
    return label, problems


HTTP01 = re.compile(
    r"^\[http-01  \] (\S+)\s+behind AS\d+ \(\S+\) -> \S+: (.*?): (?:corroborates|does NOT corroborate)$", re.M
)


def decision(account: str, log_to: Path | None = None, show: bool = False) -> tuple[str, str, dict[str, str]]:
    """(ISSUED|REFUSED|?, the full decision line, {perspective: host that answered its HTTP-01, '?' if none}).
    With show, the CA's transcript is logged line by line as it is the evidence the jury should see."""
    r = subprocess.run(
        ["docker", "exec", f"clab-{LAB}-ca", "python3", "/lab/ca.py", "--config", "/lab/ca.json", "--account", account],
        capture_output=True,
        text=True,
        check=False,
    )
    if log_to:
        log_to.write_text(r.stdout + (f"\n--- stderr ---\n{r.stderr}" if r.stderr else ""))
    if show:
        for ln in r.stdout.splitlines():
            console.transcript(ln)
    m = re.search(r"^\[decision \] ((ISSUED|REFUSED).*)$", r.stdout, re.M)
    hosts = {}
    for name, detail in HTTP01.findall(r.stdout):
        h = re.search(r"from host '([^']*)'", detail)
        hosts[name] = h.group(1) if h else "?"
    return (m.group(2), m.group(1), hosts) if m else ("?", "", hosts)


def selected(rows: list[str] | None) -> list[Row]:
    """`--rows x` keeps the rows named x: a scenario, `scenario/mode` or `scenario-mode`."""
    if not rows:
        return ROWS
    return [r for r in ROWS if any(x in (r[0], f"{r[0]}/{r[1]}", f"{r[0]}-{r[1]}") for x in rows)]


def manifest(start: datetime, end: datetime) -> dict:
    def out(*cmd: str) -> str:
        r = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return (r.stdout or r.stderr).strip()

    dockerfile = (labctl.LAB_DIR / "image" / "Dockerfile").read_text()
    images = [FRR_IMAGE, LAB_IMAGE, *re.findall(r"^FROM\s+(\S+)", dockerfile, re.M)]
    return {
        "started": start.isoformat(timespec="seconds"),
        "finished": end.isoformat(timespec="seconds"),
        "git_head": out("git", "-C", str(labctl.ROOT), "rev-parse", "HEAD"),
        "git_dirty": out("git", "-C", str(labctl.ROOT), "status", "--porcelain", "--", "src", "lab") != "",
        "scenarios": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(SCENARIOS.glob("*.yml"))},
        "images": {img: out("docker", "image", "inspect", "-f", "{{.Id}}", img) for img in images},
        "containerlab": " ".join(re.findall(r"(?:version|commit): \S+", out("containerlab", "version"))),
        "ldns_signzone": out("ldns-signzone", "-v"),
    }


def run_matrix(build: Path, rows: list[str] | None = None) -> int:
    """Every selected row; exit 1 when any row or containment check fails. A full run applies every scenario;
    a `--rows` run reuses the deployed lab when it already runs that scenario, so a hand-made state survives."""
    start = datetime.now(UTC)
    logs = labctl.run_dir("matrix")  # outside build/, which every render wipes
    results = []
    check_bad: list[str] = []
    applied = labctl.deployed(build) if rows else None
    sc = labctl.current_scenario(build) if applied else None
    if applied:
        console.note(f"reusing the deployed scenario {applied} (containers up): no apply for its rows")
    console.stage("how to read a row")
    console.explain(
        "Each row: deploy one scenario, scan it with the real scanner, announce the forged route, let the CA try to "
        "issue to the attacker, withdraw the route, let the owner's account try (the control). The scanner's label "
        "must predict the CA's decision; the row's expectation is in its banner."
    )
    console.legend("the lines of evidence", CA_LEGEND)
    for scenario, mode, want_label, want_ca, want_reason, want_hosts, want_plane in selected(rows):
        console.stage(f"row: {scenario} / attack {mode}  (expect scanner {want_label}, CA -> attacker {want_ca})")
        if why := ROW_WHY.get((scenario, mode)):
            console.explain(why)
        if scenario != applied:
            sc = labctl.render(SCENARIOS / f"{scenario}.yml", build)
            labctl.deploy(build)
            bad = check.run()
            (logs / f"{scenario}-check.log").write_text("\n".join(bad) + ("\n" if bad else "containment: OK\n"))
            for b in bad:
                console.fail("containment VIOLATION", b)
            check_bad += [f"{scenario}: {b}" for b in bad]
            labctl.attack("off", sc)
            applied = scenario
        tag = f"{scenario}-{mode}"
        label, problems = scan_evidence(build, sc, logs / f"{tag}-scan.log")
        log.info(f"scanner says {label}" + (f"; evidence problems: {problems}" if problems else "; evidence complete"))
        atk = labctl.attack(mode, sc)
        (logs / f"{tag}-attack.log").write_text(atk["text"])
        console.stage("CA: the attacker's account asks for a certificate during the hijack")
        console.explain(
            f"Expect {want_ca}. Watch the [http-01] hosts (attacker = the forged route won that perspective) and "
            "the [decision] line."
            if want_hosts
            else f"Expect {want_ca} before any HTTP-01 runs: the [caa] or [dns] lines stop it."
        )
        ca_a, reason_a, hosts_a = decision("attacker", logs / f"{tag}-attacker.log", show=True)
        off = labctl.attack("off", sc)
        (logs / f"{tag}-attack.log").write_text(atk["text"] + off["text"])
        console.stage("CA: the legitimate account asks for a certificate, attack off (control)")
        console.explain("Expect ISSUED with every perspective answered by the victim: the lab itself is sound.")
        ca_l, reason_l, hosts_l = decision("legit", logs / f"{tag}-legit.log", show=True)
        fails = []
        if not label.startswith(want_label):
            fails.append(f"scanner label {label}, expected {want_label}")
        fails += [f"scanner evidence: {p}" for p in problems]
        if atk["got"] != atk["want"]:
            fails.append(f"data plane {atk['got']} differs from what the scenario implies {atk['want']}")
        if atk["got"] != want_plane:
            fails.append(f"data plane {atk['got']}, row expects {want_plane}")
        if ca_a != want_ca:
            fails.append(f"CA -> attacker {ca_a}, expected {want_ca}")
        if not re.search(want_reason, reason_a):
            fails.append(f"decision line {reason_a!r} does not match /{want_reason}/")
        if hosts_a != (want_hosts or {}):
            fails.append(f"HTTP-01 answered by {hosts_a}, expected {want_hosts or 'no HTTP-01 at all'}")
        if ca_l != "ISSUED":
            fails.append(f"CA -> legit (attack off) {ca_l}: {reason_l}")
        if hosts_l != ALL_VICTIM:
            fails.append(f"control HTTP-01 answered by {hosts_l}, expected the victim everywhere")
        plane = f"web={atk['got'].get('web', '?')} ns={atk['got'].get('ns', '?')}"
        hosts = " ".join(f"{k}={v}" for k, v in hosts_a.items()) or "-"
        results.append(
            (scenario, mode, plane, label, problems, ca_a, reason_a, hosts, ca_l, want_label, want_ca, fails)
        )
        summary(scenario, mode, plane, label, problems, reason_a or ca_a, hosts, ca_l, want_label, want_ca, fails)
    end = datetime.now(UTC)
    table = [
        "| scenario | attack | data plane | scanner | evidence | CA → attacker | HTTP-01 hosts "
        "| CA → legit (attack off) | expected | ok |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for scenario, mode, plane, label, problems, ca_a, reason_a, hosts, ca_l, want_label, want_ca, fails in results:
        evidence = "complete" if not problems else "; ".join(problems)
        verdict = "yes" if not fails else "NO: " + "; ".join(fails)
        table.append(
            f"| {scenario} | {mode} | {plane} | {label} | {evidence} | {reason_a or ca_a} | {hosts} | {ca_l} "
            f"| {want_label} / {want_ca} | {verdict} |"
        )
    if check_bad:
        table += ["", "Containment violations:", *(f"- {b}" for b in check_bad)]
    (logs / "matrix.md").write_text("\n".join(table) + "\n")
    (logs / "manifest.json").write_text(json.dumps(manifest(start, end), indent=1) + "\n")
    console.stage("matrix: results")
    for scenario, mode, plane, label, problems, ca_a, reason_a, hosts, ca_l, want_label, want_ca, fails in results:
        summary(scenario, mode, plane, label, problems, reason_a or ca_a, hosts, ca_l, want_label, want_ca, fails)
    for b in check_bad:
        console.fail("containment VIOLATION", b)
    ok = bool(results) and not check_bad and all(not r[-1] for r in results)
    n_ok, n = sum(not r[-1] for r in results), len(results)
    (console.ok if ok else console.fail)(f"matrix: {n_ok}/{n} rows ok" + ("" if ok else " -> FAILED"))
    log.info(f"logs: {logs}  (markdown table: {logs / 'matrix.md'})")
    if ok and rows is None:
        write_demo(logs)
    return 0 if ok else 1


def summary(
    scenario: str,
    mode: str,
    plane: str,
    label: str,
    problems: list[str],
    ca_attacker: str,
    hosts: str,
    ca_legit: str,
    want_label: str,
    want_ca: str,
    fails: list[str],
) -> None:
    """One row as a borderless block: a verdict line, then aligned `key  value` lines (no table to truncate)."""
    (console.ok if not fails else console.fail)(f"{scenario} / attack {mode}", f"expected {want_label} / {want_ca}")
    console.kv(
        [
            ("scanner", label + ("" if not problems else "  evidence: " + "; ".join(problems))),
            ("data plane", plane),
            ("CA -> attacker", ca_attacker),
            ("HTTP-01 hosts", hosts),
            ("CA -> legit (off)", ca_legit),
        ]
    )
    for f in fails:
        console.fail("FAIL", f)


DEMO_LOGS = {  # placeholder -> log file; the demo's prose lives in demo_template.md, every transcript comes from logs/
    "RESULTS_TABLE": "matrix.md",
    "BASELINE_WEB_LOG": "baseline-web-attacker.log",
    "TIGHT_MAXLENGTH_WEB_LOG": "tight-maxlength-web-attacker.log",
    "CAA_UNSIGNED_WEB_LOG": "caa-unsigned-web-attacker.log",
    "CAA_UNSIGNED_WEB_NS_LOG": "caa-unsigned-web+ns-attacker.log",
    "CAA_SIGNED_WEB_NS_LOG": "caa-signed-web+ns-attacker.log",
    "CHECK_LOG": "baseline-check.log",
    "CONTROLS_LOG": "controls.log",
}


def _cells(matrix_md: str) -> list[list[str]]:
    """The cells of every data row of a matrix.md table (header and rule skipped)."""
    rows = []
    for line in matrix_md.splitlines():
        if not line.startswith("|") or line.startswith("|---") or line.startswith("| scenario |"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 10:
            rows.append(cells)
    return rows


def compact_table(matrix_md: str) -> str:
    """The five columns of matrix.md a reader needs first: what the scanner said, what the CA did, proven or not.
    The full table stays in matrix.md and under the fold of demo.md."""
    out = ["| scenario | attack | scanner says | CA to the attacker | expected | proven |", "|---|---|---|---|---|---|"]
    for scenario, mode, _plane, label, _ev, ca_a, _hosts, _ca_l, expected, ok, *_ in _cells(matrix_md):
        proven = "✔ yes" if ok == "yes" else f"✘ {ok}"
        out.append(f"| {scenario} | {mode} | {label} | {ca_a.split(':')[0]} | {expected} | {proven} |")
    return "\n".join(out)


EXPECTATION = re.compile(r"^\s*\[(ok  |MISS)\] (.*?)(?:  ->  (.*))?$", re.M)


def controls_summary(controls_log: str) -> str:
    """One row per expectation in a controls.log (`[ok  ] A1 what  ->  observed`), in the order checked."""
    out = ["| | expectation | observed |", "|---|---|---|"]
    for m in EXPECTATION.finditer(controls_log):
        mark = "✔" if m.group(1) == "ok  " else "✘ MISS"
        what, seen = (x.replace("|", "\\|") if x else "" for x in (m.group(2), m.group(3)))
        out.append(f"| {mark} | {what} | {seen} |")
    return "\n".join(out) if len(out) > 2 else "(no expectations found in controls.log: run labctl controls)"


def write_demo(logs: Path) -> Path:
    """Regenerate lab/demo.md from demo_template.md, this matrix run's logs and the latest controls run's log;
    never edit demo.md by hand. Two placeholders are derived from the logs rather than copied: RESULTS_COMPACT
    (the short form of matrix.md) and CONTROLS_SUMMARY (the expectation lines of controls.log as a table)."""
    lab = Path(__file__).resolve().parent
    text = (lab / "demo_template.md").read_text()
    for key, name in DEMO_LOGS.items():
        f = (logs.parent / "latest-controls" if key == "CONTROLS_LOG" else logs) / name
        found = f.exists()
        body = f.read_text().rstrip("\n") if found else f"({name} not found: run labctl controls / matrix)"
        text = text.replace("{{" + key + "}}", body)
        if key == "RESULTS_TABLE":
            text = text.replace("{{RESULTS_COMPACT}}", compact_table(body) if found else body)
        if key == "CONTROLS_LOG":
            text = text.replace("{{CONTROLS_SUMMARY}}", controls_summary(body) if found else body)
    out = lab / "demo.md"
    out.write_text(text)
    log.info(f"demo written: {out}")
    return out
