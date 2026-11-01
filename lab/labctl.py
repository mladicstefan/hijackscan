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
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import console  # noqa: E402
from console import log  # noqa: E402
from render import SCENARIOS, load_scenario, render_all  # noqa: E402
from render.dns import TTL  # noqa: E402
from render.topology import FEED_PORT, LAB, NODES  # noqa: E402

LAB_DIR = Path(__file__).resolve().parent
ROOT = LAB_DIR.parent
BUILD = LAB_DIR / "build"


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
    console.stage("deploy: containerlab up")
    sh("containerlab", "deploy", "-t", str(build / "lab.clab.yml"), "--reconfigure")
    console.stage("deploy: waiting for BGP sessions and RTR caches")
    wait_bgp(rov_routers(current_scenario(build)))


def destroy(build: Path) -> None:
    sh("containerlab", "destroy", "-t", str(build / "lab.clab.yml"), "--cleanup", check=False)


def wait_bgp(rov_routers: list[str] = (), timeout: float = 90) -> None:
    """Every BGP session Established and, on the ROV transits, the RTR cache connected (ROV without a cache lets
    every route through as `notfound`, which would pass the forged more-specific unchecked)."""
    routers = [n for n, v in NODES.items() if v.role == "router"]
    t0 = time.time()
    while time.time() - t0 < timeout:
        pending = []
        for r in rov_routers:
            if "connected" not in vtysh(r, "show rpki cache-connection").lower():
                pending.append(f"{r}: RTR cache not connected")
        for r in routers:
            peers = json.loads(vtysh(r, "show bgp summary json") or "{}").get("ipv4Unicast", {}).get("peers", {})
            pending += [f"{r}->{p}" for p, i in peers.items() if i.get("state") != "Established"]
            if not peers:
                pending.append(f"{r}: no peers yet")
        if not pending:
            console.ok(f"all BGP sessions established and RTR caches connected after {time.time() - t0:.0f}s")
            time.sleep(3)  # let the last UPDATEs propagate
            return
        time.sleep(2)
    console.fail(f"BGP sessions not established within {timeout}s", ", ".join(pending))
    raise SystemExit(1)


def rov_routers(sc: dict) -> list[str]:
    return [n for n, v in NODES.items() if v.role == "router" and sc["rov"] and v.asn in sc["transits"]]


def attack(mode: str, sc: dict) -> dict:
    """origin2 announces (or withdraws) the forged more-specifics; then show control plane and data plane.

    Returns what was observed: {"want": {web, ns}, "got": {web, ns}, "paths": {web: [...], ns: [...]}, "text"}
    where want/got name the host ('victim'|'attacker'|'?') answering at the victim's web and nameserver addresses.
    """
    lines: list[str] = []

    def say(msg: str) -> None:
        (console.note if "UNEXPECTED" in msg else log.info)(msg)
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
    time.sleep(2)
    paths: dict[str, list[str]] = {}
    for k in ("web", "ns"):
        seen = json.loads(vtysh("collector", f"show bgp ipv4 unicast {ms[k]} json") or "{}")
        found = seen.get("paths", [])
        via = [f"{p.get('aspath', {}).get('string', '?')} via {p.get('peer', {}).get('peerId', '?')}" for p in found]
        paths[k] = via
        state = f"{len(found)} path(s) at the collector: " + "; ".join(via) if found else "withdrawn"
        say(f"attack {mode}: {ms[k]} ({k}) {state}")
    # data plane, seen from the resolver's position: who answers at the web and nameserver addresses now?
    # The resolver sits behind a validating transit: the attacker wins only where its route is RPKI-valid.
    wins = {k: k in on and (not sc["rov"] or rpki_valid(sc, ms[k])) for k in ("web", "ns")}
    want = {k: ("attacker" if wins[k] else "victim") for k in ("web", "ns")}
    got = {}
    for _ in range(15):
        got = {"web": who_serves_web(sc["victim"]["web"]), "ns": who_serves_ns(sc["victim"]["ns"])}
        if got == want:
            break
        time.sleep(1)
    for k in ("web", "ns"):
        flag = "" if got[k] == want[k] else " (UNEXPECTED)"
        say(f"attack {mode}: {sc['victim'][k]} ({k}) is answered by host '{got[k]}'{flag}")
    if mode == "off":
        # A validating resolver keeps a bogus verdict for a while after the hijack ends (val-bogus-ttl, 60 s by
        # default; 5 s here, but Unbound's key cache held the bogus key up to 60 s): the legitimate owner stays
        # unreachable through that resolver for that long. Wait it out before the control run.
        t0 = time.time()
        while time.time() - t0 < 90 and not resolver_ok(sc["domain"]):
            time.sleep(1)
        say(f"attack off: resolver validates {sc['domain']} again after {time.time() - t0:.0f}s")
    time.sleep(TTL + 1)  # the resolver's cache (zone TTL) must not carry the previous state into the next check
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


def resolver_ok(domain: str) -> bool:
    out = dexec("resolver", "dig", "@127.0.0.1", domain, "CAA", "+noall", "+comments", "+time=2", "+tries=1")
    return "status: NOERROR" in out


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


def main() -> int:
    a = parser().parse_args()
    console.setup()
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
