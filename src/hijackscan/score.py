"""Derivation: pure functions over one raw collected record. No network, no I/O.

Every fact the risk model (risk.py) needs is derived here from data/collected/<domain>.json, so a
score can always be traced back to observed answers. `score(record, overrides)` overrides
`signed`, `has_caa`, `pinned`, `web_forgeable` or `ns_forgeable` for quick experiments.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field

from publicsuffix2 import get_sld

# --------------------------------------------------------------------------- per address


@dataclass
class AddressDerived:
    ip: str
    prefix: str | None
    origin_asns: list[int]
    rpki_state: str | None  # RIPEstat's verdict, as reported
    rpki_derived: str  # found | not-found | no-prefix (from the local ROA set)
    forgeable_more_specific: bool  # an RPKI-valid, routable, more-specific forged announcement exists
    roa_too_permissive: bool  # some ROA maxLength exceeds the announced length (RFC 9319 hygiene)
    exact_prefix_contestable: bool = True  # same-prefix forged origin always competes, absent ASPA
    roas: list[dict] = field(default_factory=list)  # covering ROAs: prefix, origin_asn, max_length, ta
    announced_more_specifics: list[str] = field(default_factory=list)  # "prefix ASn" announced inside this prefix
    ris_visibility: str | None = None  # "323/323" RIS peers seeing the announced prefix

    @property
    def roa_summary(self) -> str:
        """'18.172.0.0/16→24 AS16509, 18.172.0.0/15→15 AS16509' — one entry per covering ROA."""
        return ", ".join(f"{r['prefix']}→{r['max_length']} AS{r['origin_asn']}" for r in self.roas) or "-"


def derive_address(ip: str, raw: dict) -> AddressDerived:
    prefix = raw.get("prefix")
    roas = raw.get("roas") or []
    if not prefix:
        return AddressDerived(ip, None, [], raw.get("rpki_state"), "no-prefix", True, False)
    net = ipaddress.ip_network(prefix, strict=False)
    limit = 24 if net.version == 4 else 48
    announced_len = net.prefixlen
    routing = raw.get("routing") or {}
    extra = {
        "announced_more_specifics": routing.get("more_specifics", []),
        "ris_visibility": (
            f"{routing['ris_peers_seeing']}/{routing['ris_peers_total']}" if routing.get("ris_peers_total") else None
        ),
    }
    if not roas:
        return AddressDerived(
            ip, prefix, raw.get("origin_asns", []), raw.get("rpki_state"), "not-found", True, False, roas=[], **extra
        )
    longest_allowed = max(r["max_length"] for r in roas)
    return AddressDerived(
        ip=ip,
        prefix=prefix,
        origin_asns=raw.get("origin_asns", []),
        rpki_state=raw.get("rpki_state"),
        rpki_derived="found",
        forgeable_more_specific=announced_len < min(longest_allowed, limit),
        roa_too_permissive=any(r["max_length"] > announced_len for r in roas),
        roas=roas,
        **extra,
    )


# --------------------------------------------------------------------------- per domain


@dataclass
class Caa:
    issue: list[str] = field(default_factory=list)
    issuewild: list[str] = field(default_factory=list)
    accounturi: list[str] = field(default_factory=list)  # from issue/issuewild parameters
    validationmethods: list[str] = field(default_factory=list)


def parse_caa(records: list[str]) -> Caa:
    """'0 issue "letsencrypt.org; accounturi=https://...; validationmethods=dns-01"' → fields."""
    caa = Caa()
    for rec in records:
        parts = rec.split(" ", 2)
        if len(parts) < 3:
            continue
        tag, value = parts[1].lower(), parts[2].strip().strip('"')
        if tag not in ("issue", "issuewild"):
            continue
        ca, _, params = value.partition(";")
        getattr(caa, tag).append(ca.strip())
        for p in params.split(";"):
            k, _, v = p.strip().partition("=")
            if k.lower() == "accounturi" and v:
                caa.accounturi.append(v.strip())
            elif k.lower() == "validationmethods" and v:
                caa.validationmethods.extend(m.strip() for m in v.split(",") if m.strip())
    return caa


@dataclass
class Scored:
    domain: str
    dnssec: str  # unsigned | secure | bogus
    signed: bool
    has_caa: bool
    pinned: bool
    caa_from: str | None
    caa: Caa
    web_forgeable: bool
    ns_forgeable: bool  # every nameserver can be captured (all addresses of all NS hosts forgeable)
    ns_forgeable_hosts: int  # nameserver hosts with at least one forgeable address
    ns_hosts: int
    web_addresses: list[AddressDerived]
    ns_addresses: dict[str, list[AddressDerived]]
    ns_operators: list[str]
    hosting_asns: dict[str, str | None]  # asn -> name
    overrides: dict
    errors: list[str]

    def to_json(self) -> dict:
        return asdict(self)


def _dnssec(rec: dict) -> str:
    ds = rec.get("ds") or {}
    if not ds.get("records"):
        return "unsigned"
    answers = [n for n in rec.get("names", {}).values()]
    ok = any(n["rcode"].get(t) == "NOERROR" and n["ad"].get(t) and n.get(t) for n in answers for t in ("A", "AAAA"))
    return "secure" if ok else "bogus"


def _ns_operators(rec: dict) -> list[str]:
    ops = {get_sld(ns, strict=False) or ns for ns in rec.get("nameservers", {})}
    return sorted(ops)


def score(rec: dict, overrides: dict | None = None) -> Scored:
    ov = overrides or {}
    addr = {ip: derive_address(ip, a) for ip, a in rec.get("addresses", {}).items()}

    def addrs_of(entry: dict) -> list[AddressDerived]:
        return [addr[ip] for ip in entry.get("A", []) + entry.get("AAAA", []) if ip in addr]

    web = list({a.ip: a for n in rec.get("names", {}).values() for a in addrs_of(n)}.values())  # apex+www dedup
    ns = {host: addrs_of(e) for host, e in rec.get("nameservers", {}).items()}

    caa_from, caa = None, Caa()
    for hop in rec.get("caa_chain", []):
        if hop.get("records"):
            caa_from, caa = hop["name"], parse_caa(hop["records"])
            break

    dnssec = _dnssec(rec)
    signed = ov.get("signed", dnssec == "secure")
    has_caa = ov.get("has_caa", caa_from is not None)
    pinned = ov.get("pinned", has_caa and bool(caa.accounturi))
    web_forgeable = ov.get("web_forgeable", any(a.forgeable_more_specific for a in web))
    # A CA's resolver (and each MPIC perspective) may ask any nameserver over v4 or v6, so the
    # "forge no CAA / DNS-01" path needs every nameserver address captured, not just one.
    ns_with_addr = {h: v for h, v in ns.items() if v}
    ns_hosts = len(ns_with_addr)
    ns_forgeable_hosts = sum(any(a.forgeable_more_specific for a in v) for v in ns_with_addr.values())
    ns_forgeable = ov.get(
        "ns_forgeable",
        bool(ns_with_addr) and all(a.forgeable_more_specific for v in ns_with_addr.values() for a in v),
    )

    hosting = {str(asn): (rec.get("asns", {}).get(str(asn)) or {}).get("name") for a in web for asn in a.origin_asns}

    return Scored(
        domain=rec["domain"],
        dnssec=dnssec,
        signed=signed,
        has_caa=has_caa,
        pinned=pinned,
        caa_from=caa_from,
        caa=caa,
        web_forgeable=web_forgeable,
        ns_forgeable=ns_forgeable,
        ns_forgeable_hosts=ns_forgeable_hosts,
        ns_hosts=ns_hosts,
        web_addresses=web,
        ns_addresses=ns,
        ns_operators=_ns_operators(rec),
        hosting_asns=hosting,
        overrides=ov,
        errors=rec.get("errors", []),
    )
