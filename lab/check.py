"""Containment check for the running lab (design/lab.md §2.9). Exit 1 with one line per violation."""

from __future__ import annotations

import ipaddress
import json
import subprocess

import console
from console import log
from render.topology import LAB, NODES

PRIVATE_ASN = range(64512, 65535)
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
WGET_NETWORK_FAILURE = {1, 4}  # BusyBox wget: 1 for any failure; GNU wget: 4 = network failure. Only these = blocked.


def _exec(node: str, *cmd: str) -> str:
    r = subprocess.run(["docker", "exec", f"clab-{LAB}-{node}", *cmd], capture_output=True, text=True)
    return r.stdout


def _documentation(ip: str) -> bool:
    return any(ipaddress.ip_address(ip) in n for n in DOC_NETS)


def run() -> list[str]:
    bad: list[str] = []
    for name in NODES:
        state = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Status}}", f"clab-{LAB}-{name}"], capture_output=True, text=True
        ).stdout.strip()
        if state != "running":
            bad.append(f"{name}: container is {state or 'missing'}, nothing to check")
    for name, n in NODES.items():
        for route in json.loads(_exec(name, "ip", "-j", "route") or "[]"):
            if route.get("dst") == "default" and not _documentation(route.get("gateway", "0.0.0.0")):
                bad.append(f"{name}: default route via {route.get('gateway')} ({route.get('dev')}) leaves the fabric")
        if n.role != "router":
            continue
        summary = json.loads(_exec(name, "vtysh", "-c", "show bgp summary json") or "{}").get("ipv4Unicast", {})
        if int(summary.get("as", 0)) not in PRIVATE_ASN:
            bad.append(f"{name}: local AS {summary.get('as')} is not private")
        for peer, info in summary.get("peers", {}).items():
            if not _documentation(peer):
                bad.append(f"{name}: BGP neighbour {peer} is outside RFC 5737 space")
            if int(info.get("remoteAs", 0)) not in PRIVATE_ASN:
                bad.append(f"{name}: neighbour {peer} AS {info.get('remoteAs')} is not private")
    net = subprocess.run(["docker", "network", "inspect", f"{LAB}-mgmt"], capture_output=True, text=True).stdout
    found = json.loads(net or "[]")  # `[]` when the network does not exist
    if not found:
        bad.append(f"management network {LAB}-mgmt not found, masquerade not checked")
    else:
        masq = (found[0].get("Options") or {}).get("com.docker.network.bridge.enable_ip_masquerade")
        if masq != "false":
            bad.append(f"management network: enable_ip_masquerade is {masq!r}, not 'false'")
    for node in ("transit1", "victim"):
        r = subprocess.run(
            ["docker", "exec", f"clab-{LAB}-{node}", "sh", "-c", "wget -q -T 3 -O /dev/null http://1.1.1.1/ 2>&1"],
            capture_output=True,
            text=True,
        )
        if r.returncode == 0:
            bad.append(f"{node}: egress probe to 1.1.1.1 SUCCEEDED")
        elif r.returncode == 127:
            bad.append(f"{node}: probe binary missing (wget exit 127), egress not checked")
        elif r.returncode not in WGET_NETWORK_FAILURE:
            bad.append(f"{node}: egress probe exited {r.returncode}, not a network failure: {r.stdout.strip()}")
    return bad


def main() -> int:
    bad = run()
    checks = (
        "no default route off the fabric",
        "all ASNs private",
        "all BGP neighbours in RFC 5737 space",
        "management network without masquerade",
        "egress probes fail",
    )
    console.stage("containment check")
    for c in checks:
        log.info(f"  check: {c}")
    for b in bad:
        console.fail("VIOLATION", b)
    if bad:
        console.fail(f"containment FAILED ({len(bad)} violations)")
    else:
        console.ok("containment OK")
    return 1 if bad else 0
