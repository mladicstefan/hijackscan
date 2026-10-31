"""Render every node's configuration from one scenario file into lab/build/."""

from __future__ import annotations

import ipaddress
import json
import shutil
from pathlib import Path

import yaml

from .clab import render_clab
from .dns import render_dns
from .frr import render_frr
from .hosts import render_hosts
from .rpki import render_rpki
from .topology import EXTRA_ADDRESSES, LINKS, NODES

SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        out[k] = _merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def load_scenario(path: Path) -> dict:
    """A scenario file, with `extends: <file>` (relative to it) deep-merged underneath."""
    sc = yaml.safe_load(path.read_text())
    if "extends" in sc:
        base = load_scenario(path.parent / sc.pop("extends"))
        sc = _merge(base, sc)
    return sc


def check_topology(sc: dict) -> None:
    """The scenario must agree with the fixed fabric in topology.py; exits listing every mismatch."""
    bad: list[str] = []

    def expect(key: str, got: object, want: object, what: str) -> None:
        if got != want:
            bad.append(f"{key}: scenario has {got}, topology.py has {want} ({what})")

    expect("victim.asn", sc["victim"]["asn"], NODES["origin"].asn, "origin's AS")
    expect("attacker.asn", sc["attacker"]["asn"], NODES["origin2"].asn, "origin2's AS")
    transits = {NODES["transit1"].asn, NODES["transit2"].asn}
    expect("transits", set(sc["transits"]), transits, "transit1 and transit2")
    expect("collector", sc["collector"], NODES["collector"].asn, "collector's AS")

    lan = next(link for link in LINKS if (link.a, link.b) == ("origin", "victim"))
    lan_net = ipaddress.ip_interface(lan.b_ip).network
    victim_ips = {"web": lan.b_ip.split("/")[0], "ns": EXTRA_ADDRESSES["victim"][0][0].split("/")[0]}
    expect("victim.prefix", sc["victim"]["prefix"], str(lan_net), "origin-victim link")
    for k, want in victim_ips.items():
        ip = sc["victim"][k]
        if ipaddress.ip_address(ip) not in lan_net:
            bad.append(f"victim.{k}: {ip} is outside the origin-victim link {lan_net}")
        expect(f"victim.{k}", ip, want, "the victim host's address on that link")

    atk = next(link for link in LINKS if (link.a, link.b) == ("origin2", "attacker"))
    forged = {"web": atk.a_ip, "ns": EXTRA_ADDRESSES["origin2"][0][0]}
    for k, cidr in forged.items():
        net = str(ipaddress.ip_interface(cidr).network)
        expect(f"attacker.more_specifics.{k}", sc["attacker"]["more_specifics"][k], net, "origin2-attacker subnet")
    if bad:
        raise SystemExit("scenario does not match lab/render/topology.py:\n  " + "\n  ".join(bad))


def render_all(sc: dict, build: Path) -> None:
    check_topology(sc)
    if build.exists():
        shutil.rmtree(build)
    build.mkdir(parents=True)
    (build / "scenario.json").write_text(json.dumps(sc, indent=1) + "\n")
    render_frr(sc, build)
    render_rpki(sc, build)
    render_dns(sc, build)
    render_hosts(sc, build)
    render_clab(build)
