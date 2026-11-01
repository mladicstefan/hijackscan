"""hijackscan validation lab: render, deploy, attack, scan, validate (design/lab.md).

uv run lab/labctl.py render [scenario.yml]     write every node's config to lab/build/
uv run lab/labctl.py apply  [scenario.yml]     render + (re)deploy + wait for BGP + attack off
uv run lab/labctl.py deploy | destroy          containerlab up / down on the rendered topology
uv run lab/labctl.py check                     containment: ASNs, neighbours, routes, masquerade, egress
uv run lab/labctl.py attack off|web|web+ns     origin2 (AS65010) announces the forged more-specific(s)
uv run lab/labctl.py scan [--details]          the real scanner against the lab (pre-attack state)
uv run lab/labctl.py ca legit|attacker         the CA tries to issue for that account
uv run lab/labctl.py matrix [--rows ROW ...]   every row of the validation matrix, with expected results
uv run lab/labctl.py controls                  negative controls: each verdict flips when its mechanism is removed

Every wait is a condition poll with a timeout, never a fixed sleep; a timeout is logged, never hidden. Between
steps the resolver's cache is flushed over unbound-control (see flush_resolver). `--measure-lockout` (or
LAB_MEASURE_LOCKOUT=1) makes `attack off` first time how long the resolver keeps the bogus verdict before flushing.
"""

from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import console  # noqa: E402
from console import log  # noqa: E402
from render import SCENARIOS, load_scenario, render_all  # noqa: E402
from render.dns import SIGNED_ZONE  # noqa: E402
from render.topology import FEED_PORT, LAB, LAB_IMAGE, NODES  # noqa: E402

LAB_DIR = Path(__file__).resolve().parent
ROOT = LAB_DIR.parent
BUILD = LAB_DIR / "build"
# `attack off` times the resolver's bogus lockout (up to 90 s) before flushing; off by default (--measure-lockout)
MEASURE_LOCKOUT = os.environ.get("LAB_MEASURE_LOCKOUT") == "1"


def sh(*cmd: str, check: bool = True, quiet: bool = False) -> subprocess.CompletedProcess:
    if not quiet:
        console.cmd(" ".join(cmd))
    try:
        return subprocess.run(cmd, check=check, capture_output=quiet, text=True)
    except FileNotFoundError:
        hint = {
            "containerlab": 'curl -sL https://containerlab.dev/setup | sudo -E bash -s "install-containerlab"',
            "docker": "https://docs.docker.com/engine/install/",
        }.get(cmd[0], "install it and retry")
        console.fail(f"{cmd[0]} not found", hint)
        raise SystemExit(1) from None


def dexec(node: str, *cmd: str, quiet: bool = True) -> str:
    r = sh("docker", "exec", f"clab-{LAB}-{node}", *cmd, check=False, quiet=quiet)
    return r.stdout if quiet else ""


def vtysh(node: str, *cmds: str) -> str:
    args = [x for c in cmds for x in ("-c", c)]
    return dexec(node, "vtysh", *args)


# --------------------------------------------------------------------------- lifecycle


def render(scenario: Path, build: Path) -> dict:
    sc = load_scenario(scenario)
    render_all(sc, build)
    log.info(f"rendered scenario {sc['name']} -> {build}")
    return sc


def deploy(build: Path) -> None:
    if sh("docker", "image", "inspect", LAB_IMAGE, check=False, quiet=True).returncode != 0:
        console.stage(f"build image {LAB_IMAGE}")
        sh("docker", "build", "-t", LAB_IMAGE, str(LAB_DIR / "image"))
    console.stage("deploy: containerlab up")
    sh("containerlab", "deploy", "-t", str(build / "lab.clab.yml"), "--reconfigure")
    console.stage("deploy: waiting for BGP sessions and RTR caches")
    sc = current_scenario(build)
    wait_bgp(rov_routers(sc), sc["victim"]["prefix"])


def destroy(build: Path) -> None:
    sh("containerlab", "destroy", "-t", str(build / "lab.clab.yml"), "--cleanup", check=False)


def wait_for(what: str, pred: Callable[[], bool], timeout: float, interval: float) -> float | None:
    """Poll `pred` every `interval` s until it holds; the seconds it took, or None after `timeout` (logged, so a
    wait that ran out is visible in the transcript rather than hidden in a sleep)."""
    t0 = time.time()
    while True:
        if pred():
            return time.time() - t0
        if time.time() - t0 >= timeout:
            console.note(f"timeout: {what} not seen within {timeout:.0f}s")
            return None
        time.sleep(interval)


def collector_paths(prefix: str) -> list[dict]:
    """The paths the collector holds for `prefix` (empty when withdrawn or not yet learnt)."""
    return json.loads(vtysh("collector", f"show bgp ipv4 unicast {prefix} json") or "{}").get("paths", [])


RTR_RESET_AFTER = 15  # seconds a ROV transit may stay unsynced before wait_bgp issues `rpki reset`


def wait_bgp(rov_routers: list[str] = (), prefix: str | None = None, timeout: float = 90) -> None:
    """Every BGP session Established and, on the ROV transits, the RTR cache connected (ROV without a cache lets
    every route through as `notfound`, which would pass the forged more-specific unchecked). Then, with `prefix`,
    until the collector holds it from every one of its peers: the last UPDATEs have propagated."""
    routers = [n for n, v in NODES.items() if v.role == "router"]
    t0 = last = time.time()
    n_collector_peers = 0
    reset_done: set[str] = set()
    while time.time() - t0 < timeout:
        pending = []
        for r in rov_routers:
            if "connected" not in vtysh(r, "show rpki cache-connection").lower():
                pending.append(f"{r}: RTR cache not connected")
                if time.time() - t0 >= RTR_RESET_AFTER and r not in reset_done:
                    # Safety net: a fresh rtrlib session (`rpki reset`) reconnects within retry_interval, whatever
                    # kept the first one from syncing (render/frr.py has the known cause: timer order).
                    reset_done.add(r)
                    vtysh(r, "rpki reset")
                    console.note(f"{r}: RTR cache not connected after {time.time() - t0:.0f}s: issued `rpki reset`")
        for r in routers:
            raw = vtysh(r, "show bgp summary json")
            if not raw:
                pending.append(f"{r}: vtysh gave no output (is FRR running? docker logs clab-{LAB}-{r})")
                continue
            peers = json.loads(raw).get("ipv4Unicast", {}).get("peers", {})
            if r == "collector":
                n_collector_peers = len(peers)
            pending += [f"{r}->{p}" for p, i in peers.items() if i.get("state") != "Established"]
            if not peers:
                pending.append(f"{r}: no peers yet")
        if pending and time.time() - last >= 10:
            last = time.time()
            console.note(
                f"waiting ({time.time() - t0:.0f}s): " + ", ".join(pending[:4]) + (" …" if len(pending) > 4 else "")
            )
        if not pending:
            console.ok(f"all BGP sessions established and RTR caches connected after {time.time() - t0:.0f}s")
            if prefix:
                wait_collector(prefix, n_collector_peers)
            return
        time.sleep(2)
    console.fail(f"BGP sessions not established within {timeout}s", ", ".join(pending))
    raise SystemExit(1)


def wait_collector(prefix: str, n_peers: int) -> None:
    took = wait_for(
        f"{prefix} at the collector from all {n_peers} peers",
        lambda: len(collector_paths(prefix)) >= n_peers,
        timeout=30,
        interval=1,
    )
    if took is not None:
        log.info(f"collector holds {prefix} from all {n_peers} peers after {took:.1f}s")


def rov_routers(sc: dict) -> list[str]:
    return [n for n, v in NODES.items() if v.role == "router" and sc["rov"] and v.asn in sc["transits"]]


def attack(mode: str, sc: dict) -> dict:
    """origin2 announces (or withdraws) the forged more-specifics; then show control plane and data plane.

    Returns what was observed: {"want": {web, ns}, "got": {web, ns}, "paths": {web: [...], ns: [...]}, "text"}
    where want/got name the host ('victim'|'attacker'|'?') answering at the victim's web and nameserver addresses.
    """
    lines: list[str] = []

    def say(msg: str) -> None:
        console.transcript(msg, indent="")  # host 'attacker' red, 'victim' green, UNEXPECTED yellow
        lines.append(msg)

    ms = sc["attacker"]["more_specifics"]
    on = {"off": [], "web": ["web"], "web+ns": ["web", "ns"]}[mode]
    cmds = ["conf t", f"router bgp {sc['attacker']['asn']}", "address-family ipv4 unicast"]
    cmds += [f"{'' if k in on else 'no '}network {ms[k]}" for k in ("web", "ns")]
    console.stage(
        f"attack {mode}: origin2 (AS{sc['attacker']['asn']}) "
        + ("withdraws" if not on else "announces")
        + " the forged more-specific(s)"
    )
    vtysh("origin2", *cmds)
    # control plane: the collector peers with origin2 and with both transits, so a forged route that passes ROV
    # reaches it three times (65010, 65003 65010, 65002 65003 65010) and one the transits drop once; withdrawn: none.
    passes = {k: not sc["rov"] or rpki_valid(sc, ms[k]) for k in ("web", "ns")}
    want_paths = {k: (3 if passes[k] else 1) if k in on else 0 for k in ("web", "ns")}
    took = wait_for(
        f"collector paths web={want_paths['web']} ns={want_paths['ns']}",
        lambda: all(len(collector_paths(ms[k])) == want_paths[k] for k in ("web", "ns")),
        timeout=10,
        interval=0.2,
    )
    paths: dict[str, list[str]] = {}
    for k in ("web", "ns"):
        found = collector_paths(ms[k])
        via = [f"{p.get('aspath', {}).get('string', '?')} via {p.get('peer', {}).get('peerId', '?')}" for p in found]
        paths[k] = via
        state = f"{len(found)} path(s) at the collector: " + "; ".join(via) if found else "withdrawn"
        flag = "" if len(found) == want_paths[k] else f" (UNEXPECTED: {want_paths[k]} expected within 10s)"
        say(f"attack {mode}: {ms[k]} ({k}) {state}{flag}")
    if took is not None:
        say(f"attack {mode}: collector table converged after {took:.1f}s")
    # data plane, seen from the resolver's position: who answers at the web and nameserver addresses now?
    # The resolver sits behind a validating transit: the attacker wins only where its route is RPKI-valid.
    wins = {k: k in on and passes[k] for k in ("web", "ns")}
    want = {k: ("attacker" if wins[k] else "victim") for k in ("web", "ns")}
    got: dict[str, str] = {}

    def plane_settled() -> bool:
        nonlocal got
        got = {"web": who_serves_web(sc["victim"]["web"]), "ns": who_serves_ns(sc["victim"]["ns"])}
        return got == want

    wait_for(f"data plane {want}", plane_settled, timeout=15, interval=0.5)
    for k in ("web", "ns"):
        flag = "" if got[k] == want[k] else " (UNEXPECTED)"
        say(f"attack {mode}: {sc['victim'][k]} ({k}) is answered by host '{got[k]}'{flag}")
    domain = sc["domain"]
    if mode == "off" and MEASURE_LOCKOUT:
        # For the narrative only: after a hijack of a signed zone's nameserver, Unbound holds the key it could not
        # fetch for BOGUS_KEY_TTL (60 s, hard-coded in validator.h; val-bogus-ttl does not shorten it), so the
        # legitimate owner stays locked out through that resolver for that long after the hijack ends.
        if resolver_state(domain) == "SERVFAIL":
            t = wait_for(f"resolver validating {domain} again", lambda: resolver_state(domain) != "SERVFAIL", 90, 1)
            secs = f"{t:.0f}s" if t is not None else ">90s"
            say(f"attack off: lockout measured: resolver validates {domain} again after {secs} (BOGUS_KEY_TTL)")
        else:
            say(f"attack off: lockout measured: resolver was not bogus for {domain}, nothing to wait out")
    # The resolver's cache must not carry the previous state (zone data within TTL, a bogus key for 60 s) into the
    # next check: flush it, then wait until its answer agrees with the data plane just observed.
    say(f"attack {mode}: resolver cache flushed: {flush_resolver(domain)}")
    expect = expected_resolver_state(sc, got)
    t = wait_for(f"resolver {expect} for {domain}", lambda: resolver_state(domain) == expect, timeout=15, interval=0.2)
    seen = resolver_state(domain)
    flag = "" if seen == expect else f" (UNEXPECTED: {expect} expected)"
    say(f"attack {mode}: resolver answers {domain} A with {seen}{flag}" + (f" after {t:.1f}s" if t is not None else ""))
    return {"want": want, "got": got, "paths": paths, "text": "".join(f"{ln}\n" for ln in lines)}


def run_dir(kind: str, logs: Path = LAB_DIR / "logs") -> Path:
    """A fresh lab/logs/<UTC timestamp>-<kind>/ for this run and the lab/logs/latest-<kind> link onto it, so an
    older run is never overwritten."""
    d = logs / f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{kind}"
    d.mkdir(parents=True)
    latest = logs / f"latest-{kind}"
    if latest.is_symlink() or latest.exists():
        latest.unlink()
    latest.symlink_to(d.name)
    log.info(f"logs: {d} ({latest.name} -> {d.name})")
    return d


def rpki_valid(sc: dict, prefix: str) -> bool:
    net = ipaddress.ip_network(prefix)
    for r in sc["roas"]:
        covers = net.subnet_of(ipaddress.ip_network(r["prefix"]))
        if covers and r["asn"] == sc["victim"]["asn"] and net.prefixlen <= r["max_length"]:
            return True
    return False


def resolver_state(name: str) -> str:
    """What the lab resolver answers for `name` A: 'NOERROR ad' (validated), 'NOERROR', 'SERVFAIL' (bogus or
    unreachable), another rcode, or '?' when it does not answer."""
    out = dexec("resolver", "dig", "@127.0.0.1", name, "A", "+noall", "+comments", "+adflag", "+time=2", "+tries=1")
    status = re.search(r"status: (\w+)", out)
    flags = re.search(r"flags: ([^;]*);", out)
    if not status:
        return "?"
    ad = flags and "ad" in flags.group(1).split()
    return status.group(1) + (" ad" if ad else "")


def expected_resolver_state(sc: dict, plane: dict[str, str]) -> str:
    """The answer a validating resolver must give for the victim's A given who serves its nameserver address:
    bogus (SERVFAIL) when the zone is signed and the attacker's unsigned copy answers, validated when signed and
    the victim answers, plain NOERROR when the zone is unsigned."""
    if not sc["dns"]["signed"]:
        return "NOERROR"
    return "SERVFAIL" if plane.get("ns") == "attacker" else "NOERROR ad"


def flush_resolver(domain: str) -> str:
    """Empty the resolver's cache of the victim's names and of every bogus entry (rrsets, messages and the key
    cache, where Unbound keeps a missing DNSKEY for BOGUS_KEY_TTL = 60 s) over unbound-control on the unix socket
    rendered into unbound.conf. Falls back to SIGHUP (a full reload, which drops the cache) when the control
    channel fails, and waits until the resolver answers again. Returns one line saying what was done."""
    done = []
    for cmd in (("flush_zone", domain), ("flush_bogus",)):
        r = sh(
            "docker", "exec", f"clab-{LAB}-resolver", "unbound-control", "-c", "/lab/unbound.conf", *cmd,
            check=False, quiet=True,
        )  # fmt: skip
        if r.returncode != 0:
            why = (r.stderr or r.stdout).strip().splitlines()
            console.note(
                f"unbound-control {' '.join(cmd)} failed ({why[-1] if why else f'exit {r.returncode}'}): "
                "falling back to kill -HUP 1 (reload drops the cache)"
            )
            dexec("resolver", "kill", "-HUP", "1")
            t = wait_for("resolver answering after HUP", lambda: resolver_state(SIGNED_ZONE) != "?", 15, 0.2)
            after = "timeout" if t is None else f"{t:.1f}s"
            return f"unbound-control failed, kill -HUP 1 instead; answering again after {after}"
        done.append(f"{' '.join(cmd)} -> {' '.join(r.stdout.split()) or 'ok'}")
    return "unbound-control " + "; ".join(done)


def deployed(build: Path) -> str | None:
    """The scenario name the running lab was rendered from, or None when the build or any container is missing."""
    f = build / "scenario.json"
    if not f.exists():
        return None
    for name in NODES:
        r = sh("docker", "inspect", "-f", "{{.State.Status}}", f"clab-{LAB}-{name}", check=False, quiet=True)
        if r.stdout.strip() != "running":
            return None
    return json.loads(f.read_text())["name"]


def who_serves_web(ip: str) -> str:
    out = dexec("resolver", "curl", "-s", "-m", "2", "-D", "-", "-o", "/dev/null", f"http://{ip}/")
    return next((ln.split(":", 1)[1].strip() for ln in out.splitlines() if ln.lower().startswith("x-lab-host:")), "?")


def who_serves_ns(ip: str) -> str:
    out = dexec("resolver", "dig", f"@{ip}", "hostname.bind", "CH", "TXT", "+short", "+time=1", "+tries=1")
    return out.strip().strip('"') or "?"


def scan_cmd(build: Path, sc: dict, details: bool = False) -> list[str]:
    """The real scanner, pointed at the lab: its resolver, its feed, its ROA day, and a routable cap that admits
    the lab's more-specifics (RFC 5737 blocks are /24s, so the forged routes are /28s)."""
    cap = max(ipaddress.ip_network(p).prefixlen for p in sc["attacker"]["more_specifics"].values())
    feed = f"http://{NODES['collector'].mgmt}:{FEED_PORT}/data/{{call}}/data.json"
    cmd = ["uv", "run", "hijackscan"]  # global options first, then the `domain` subcommand
    cmd += ["--data-dir", str(build / "data"), "--resolver", f"{NODES['resolver'].mgmt}:53"]
    cmd += ["--rpki-date", "lab", "--ripestat-url", feed, "--routable-cap-v4", str(cap)]
    return cmd + ["domain", sc["domain"], "--force"] + (["--details"] if details else [])


def scan(build: Path, sc: dict, details: bool, capture: bool = False) -> subprocess.CompletedProcess:
    for d in ("cache", "collected"):
        shutil.rmtree(build / "data" / d, ignore_errors=True)
    cmd = scan_cmd(build, sc, details)
    console.stage(f"scan: the real scanner against the lab ({sc['domain']})")
    console.cmd(" ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT, check=False, capture_output=capture, text=True)


def ca(account: str) -> int:
    return sh(
        "docker",
        "exec",
        f"clab-{LAB}-ca",
        "python3",
        "/lab/ca.py",
        "--config",
        "/lab/ca.json",
        "--account",
        account,
        check=False,
    ).returncode


def check() -> int:
    from check import main as check_main

    return check_main()


# --------------------------------------------------------------------------- CLI


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="labctl", description=__doc__.splitlines()[0])
    p.add_argument("--build", type=Path, default=BUILD)
    p.add_argument(
        "--measure-lockout",
        action="store_true",
        default=MEASURE_LOCKOUT,
        help="before flushing the resolver in `attack off`, time how long it keeps the bogus verdict (up to 90 s)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("render", "apply"):
        s = sub.add_parser(name)
        s.add_argument("scenario", nargs="?", type=Path, default=SCENARIOS / "baseline.yml")
    sub.add_parser("deploy")
    sub.add_parser("destroy")
    sub.add_parser("check")
    sub.add_parser("attack").add_argument("mode", choices=("off", "web", "web+ns"))
    s = sub.add_parser("scan")
    s.add_argument("--details", action="store_true")
    sub.add_parser("ca").add_argument("account", choices=("legit", "attacker"))
    m = sub.add_parser("matrix")
    m.add_argument("--rows", nargs="+", metavar="ROW", help="only these rows: scenario, scenario/mode or scenario-mode")
    sub.add_parser("controls")
    return p


def current_scenario(build: Path) -> dict:
    return json.loads((build / "scenario.json").read_text())


def lock(path: Path = LAB_DIR / ".labctl.lock"):
    """One labctl run at a time: every command shares the same containers and build directory, so two runs
    (say a matrix and a controls) silently corrupt each other's results. Fails fast naming the holder."""
    f = path.open("a+")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        f.seek(0)
        console.fail("another labctl run is active", f"{f.read().strip() or '?'}; wait for it or stop it first")
        raise SystemExit(1) from None
    f.seek(0)
    f.truncate()
    f.write(f"pid {os.getpid()}: {' '.join(sys.argv[1:])}\n")
    f.flush()
    return f  # held until the process exits


def main() -> int:
    global MEASURE_LOCKOUT
    a = parser().parse_args()
    console.setup()
    _lock = lock()  # noqa: F841
    MEASURE_LOCKOUT = a.measure_lockout
    if a.cmd == "render":
        render(a.scenario, a.build)
    elif a.cmd == "apply":
        sc = render(a.scenario, a.build)
        deploy(a.build)
        attack("off", sc)
    elif a.cmd == "deploy":
        deploy(a.build)
    elif a.cmd == "destroy":
        destroy(a.build)
    elif a.cmd == "check":
        return check()
    elif a.cmd == "attack":
        attack(a.mode, current_scenario(a.build))
    elif a.cmd == "scan":
        return scan(a.build, current_scenario(a.build), a.details).returncode
    elif a.cmd == "ca":
        return ca(a.account)
    elif a.cmd == "matrix":
        from matrix import run_matrix

        return run_matrix(a.build, a.rows)
    elif a.cmd == "controls":
        from controls import run_controls

        return run_controls(a.build)
    return 0


if __name__ == "__main__":
    sys.exit(main())
