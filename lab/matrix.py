"""The validation matrix (design/lab.md §2.4): every row applied, scanned, attacked and validated, then compared.

A cell counts as proven only when the CA's decision line carries the expected reason, the HTTP-01 perspectives
were answered by the expected hosts, the data plane was in the expected state during the attack, and the scanner's
collected record holds the facts its label rests on. Everything the verdict uses is written to lab/logs/.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import check
import labctl
from render import SCENARIOS
from render.topology import FRR_IMAGE, LAB, LAB_IMAGE, NODES

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


def decision(account: str, log_to: Path | None = None) -> tuple[str, str, dict[str, str]]:
    """(ISSUED|REFUSED|?, the full decision line, {perspective: host that answered its HTTP-01, '?' if none})."""
    r = subprocess.run(
        ["docker", "exec", f"clab-{LAB}-ca", "python3", "/lab/ca.py", "--config", "/lab/ca.json", "--account", account],
        capture_output=True,
        text=True,
        check=False,
    )
    if log_to:
        log_to.write_text(r.stdout + (f"\n--- stderr ---\n{r.stderr}" if r.stderr else ""))
    m = re.search(r"^\[decision \] ((ISSUED|REFUSED).*)$", r.stdout, re.M)
    hosts = {}
    for name, detail in HTTP01.findall(r.stdout):
        h = re.search(r"from host '([^']*)'", detail)
        hosts[name] = h.group(1) if h else "?"
    return (m.group(2), m.group(1), hosts) if m else ("?", "", hosts)


def deployed(build: Path) -> str | None:
    """The scenario name the running lab was rendered from, or None when the build or any container is missing."""
    f = build / "scenario.json"
    if not f.exists():
        return None
    for name in NODES:
        r = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Status}}", f"clab-{LAB}-{name}"], capture_output=True, text=True
        )
        if r.stdout.strip() != "running":
            return None
    return json.loads(f.read_text())["name"]


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
    logs = build.parent / "logs"  # outside build/, which every render wipes
    logs.mkdir(exist_ok=True)
    results = []
    check_bad: list[str] = []
    applied = deployed(build) if rows else None
    sc = labctl.current_scenario(build) if applied else None
    if applied:
        print(f"reusing the deployed scenario {applied} (containers up): no apply for its rows", flush=True)
    for scenario, mode, want_label, want_ca, want_reason, want_hosts, want_plane in selected(rows):
        print(f"\n=== {scenario} / attack {mode}", flush=True)
        if scenario != applied:
            sc = labctl.render(SCENARIOS / f"{scenario}.yml", build)
            labctl.deploy(build)
            bad = check.run()
            (logs / f"{scenario}-check.log").write_text("\n".join(bad) + ("\n" if bad else "containment: OK\n"))
            for b in bad:
                print(f"containment VIOLATION: {b}", flush=True)
            check_bad += [f"{scenario}: {b}" for b in bad]
            labctl.attack("off", sc)
            applied = scenario
        tag = f"{scenario}-{mode}"
        label, problems = scan_evidence(build, sc, logs / f"{tag}-scan.log")
        atk = labctl.attack(mode, sc)
        (logs / f"{tag}-attack.log").write_text(atk["text"])
        ca_a, reason_a, hosts_a = decision("attacker", logs / f"{tag}-attacker.log")
        off = labctl.attack("off", sc)
        (logs / f"{tag}-attack.log").write_text(atk["text"] + off["text"])
        ca_l, reason_l, hosts_l = decision("legit", logs / f"{tag}-legit.log")
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
        print(f"scanner {label} ({len(problems)} evidence problems); data plane {plane}", flush=True)
        print(f"CA attacker {reason_a or '?'} via {hosts}; CA legit {ca_l}", flush=True)
        for f in fails:
            print(f"FAIL: {f}", flush=True)
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
    print("\n" + "\n".join(table))
    (logs / "matrix.md").write_text("\n".join(table) + "\n")
    (logs / "manifest.json").write_text(json.dumps(manifest(start, end), indent=1) + "\n")
    ok = bool(results) and not check_bad and all(not r[-1] for r in results)
    print(f"\nmatrix: {sum(not r[-1] for r in results)}/{len(results)} rows ok" + ("" if ok else " -> FAILED"))
    if ok and rows is None:
        write_demo(logs)
    return 0 if ok else 1


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


def write_demo(logs: Path) -> Path:
    """Regenerate lab/demo.md from demo_template.md and the logs of the last full run; never edit demo.md by hand."""
    lab = Path(__file__).resolve().parent
    text = (lab / "demo_template.md").read_text()
    for key, name in DEMO_LOGS.items():
        f = logs / name
        body = f.read_text().rstrip("\n") if f.exists() else f"({name} not found: run labctl controls / matrix)"
        text = text.replace("{{" + key + "}}", body)
    out = lab / "demo.md"
    out.write_text(text)
    print(f"demo written: {out}")
    return out
