"""Fixed lab fabric: nodes, links, addresses, perspectives (design/lab.md §2.5-2.7).

Everything here is constant; the scenario file only changes what is announced, validated, signed or pinned.
"""

from __future__ import annotations

from dataclasses import dataclass

LAB = "hijackscan"  # containerlab name → containers are clab-hijackscan-<node>
MGMT_NET = "172.31.40.0/24"
# Pinned by digest (docker image inspect, 2026-10-31) so a rebuilt lab runs the same FRR; the tag is for humans.
FRR_IMAGE = "quay.io/frrouting/frr:10.7.1@sha256:e995beaa50fdc9edb35eadcfefa29b7f062cc06f2b812613789b68fa541554d2"
LAB_IMAGE = "hijackscan-lab:latest"
RTR_PORT = 8282
FEED_PORT = 8080


@dataclass(frozen=True)
class Node:
    name: str
    role: str  # router | rpki | resolver | ca | victim | attacker
    mgmt: str
    asn: int | None = None


@dataclass(frozen=True)
class Link:
    a: str
    a_ip: str  # with prefix length
    b: str
    b_ip: str


NODES: dict[str, Node] = {
    n.name: n
    for n in (
        Node("origin", "router", "172.31.40.10", 65000),
        Node("transit1", "router", "172.31.40.11", 65002),
        Node("transit2", "router", "172.31.40.12", 65003),
        Node("origin2", "router", "172.31.40.13", 65010),
        Node("collector", "router", "172.31.40.15", 65100),
        Node("rpki", "rpki", "172.31.40.16"),
        Node("resolver", "resolver", "172.31.40.20"),
        Node("ca", "ca", "172.31.40.21"),
        Node("victim", "victim", "172.31.40.22"),
        Node("attacker", "attacker", "172.31.40.23"),
    )
}

LINKS: list[Link] = [
    # inter-AS (198.51.100.0/24)
    Link("origin", "198.51.100.1/30", "transit1", "198.51.100.2/30"),
    Link("transit1", "198.51.100.5/30", "transit2", "198.51.100.6/30"),
    Link("transit2", "198.51.100.9/30", "origin2", "198.51.100.10/30"),
    Link("origin", "198.51.100.13/30", "collector", "198.51.100.14/30"),
    Link("transit1", "198.51.100.17/30", "collector", "198.51.100.18/30"),
    Link("transit2", "198.51.100.21/30", "collector", "198.51.100.22/30"),
    Link("origin2", "198.51.100.25/30", "collector", "198.51.100.26/30"),
    # services (192.0.2.0/24)
    Link("transit1", "192.0.2.1/30", "resolver", "192.0.2.2/30"),
    Link("transit1", "192.0.2.9/29", "ca", "192.0.2.10/29"),
    Link("transit2", "192.0.2.17/30", "ca", "192.0.2.18/30"),
    Link("collector", "192.0.2.21/30", "ca", "192.0.2.22/30"),
    Link("origin", "192.0.2.25/30", "ca", "192.0.2.26/30"),
    # hosts (203.0.113.0/24)
    Link("origin", "203.0.113.1/24", "victim", "203.0.113.10/24"),
    Link("origin2", "203.0.113.1/28", "attacker", "203.0.113.10/28"),
]

# Secondary addresses: the CA's fourth remote shares the primary's link; the nameserver address on both hosts.
EXTRA_ADDRESSES: dict[str, list[tuple[str, str]]] = {  # node -> [(ip/len, dev)]
    "ca": [("192.0.2.11/29", "eth1")],
    "victim": [("203.0.113.100/24", "eth1")],
    "origin2": [("203.0.113.97/28", "eth3")],
    "attacker": [("203.0.113.100/28", "eth1")],
}

# Host default routes point at in-fabric routers (RFC 5737), never at the management gateway.
DEFAULT_VIA: dict[str, str] = {
    "resolver": "192.0.2.1",
    "ca": "192.0.2.9",
    "victim": "203.0.113.1",
    "attacker": "203.0.113.1",
}

# Prefixes each router originates itself (its service links); the victim /24 and the attack /28s come from the scenario.
OWN_PREFIXES: dict[str, list[str]] = {
    "origin": ["192.0.2.24/30"],
    "transit1": ["192.0.2.0/30", "192.0.2.8/29"],
    "transit2": ["192.0.2.16/30"],
    "collector": ["192.0.2.20/30"],
    "origin2": [],
}


@dataclass(frozen=True)
class Perspective:
    name: str
    asn: int  # the AS it sits behind
    ip: str
    dev: str
    gateway: str
    table: str  # "main" for the primary, a number for the policy-routed remotes


PERSPECTIVES: list[Perspective] = [
    Perspective("primary", 65002, "192.0.2.10", "eth1", "192.0.2.9", "main"),
    Perspective("r1", 65003, "192.0.2.18", "eth2", "192.0.2.17", "101"),
    Perspective("r2", 65100, "192.0.2.22", "eth3", "192.0.2.21", "102"),
    Perspective("r3", 65000, "192.0.2.26", "eth4", "192.0.2.25", "103"),
    Perspective("r4", 65002, "192.0.2.11", "eth1", "192.0.2.9", "104"),
]

RESOLVER_IP = "192.0.2.2"


def interfaces() -> dict[str, list[tuple[str, str, str]]]:
    """node -> [(dev, ip/len, peer node)] in link order; dev names are eth1, eth2, ... per node."""
    out: dict[str, list[tuple[str, str, str]]] = {n: [] for n in NODES}
    for link in LINKS:
        out[link.a].append((f"eth{len(out[link.a]) + 1}", link.a_ip, link.b))
        out[link.b].append((f"eth{len(out[link.b]) + 1}", link.b_ip, link.a))
    return out


def neighbours(node: str) -> list[tuple[str, int, str]]:
    """(peer ip, peer asn, peer name) for every link between two routers, from `node`'s side."""
    out = []
    for link in LINKS:
        for me, peer, peer_ip in ((link.a, link.b, link.b_ip), (link.b, link.a, link.a_ip)):
            if me == node and NODES[peer].role == "router":
                out.append((peer_ip.split("/")[0], NODES[peer].asn, peer))  # type: ignore[arg-type]
    return out


def router_id(node: str) -> str:
    return interfaces()[node][0][1].split("/")[0]
