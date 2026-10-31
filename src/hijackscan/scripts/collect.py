"""Collect the DNS and routing facts behind one question per domain:

    can a BGP hijack below DNS make a CA's domain validation succeed, and does the zone's
    CAA + DNSSEC setup close that path?

For every domain in data/domains.txt:
  DNS   (dnspython, through one resolver)   A/AAAA of apex and www, NS and their addresses,
                                            CAA (climbing to the parent), DS, DNSKEY, AD bit
  routing (RIPEstat, cached on disk)        covering prefix + origin AS per address,
                                            RPKI validity and the matching ROAs with maxLength

Output: data/facts.jsonl, one JSON object per domain. Every record carries fetched_at and the
resolver / RIPEstat source so the report can cite them. Re-runs reuse the RIPEstat cache.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import dns.flags
import dns.nameserver
import dns.rdatatype
import dns.resolver
import httpx

log = logging.getLogger("hijackscan.collect")

USER_AGENT = "hijackscan/0.1 (DNS SEC Hackathon 2026)"
RIPESTAT = "https://stat.ripe.net/data/{call}/data.json"
SOURCEAPP = "hijackscan"


# --------------------------------------------------------------------------- records


@dataclass
class Caa:
    flags: int
    tag: str
    value: str


@dataclass
class Roa:
    prefix: str
    origin_asn: int
    max_length: int


@dataclass
class AddressFacts:
    ip: str
    prefix: str | None = None
    origin_asns: list[int] = field(default_factory=list)
    rpki: str | None = None  # valid | invalid | unknown (RIPEstat wording)
    roas: list[Roa] = field(default_factory=list)
    forgeable_more_specific: bool | None = None  # some ROA allows a longer prefix than announced


@dataclass
class DomainFacts:
    domain: str
    fetched_at: str
    resolver: str
    web: list[AddressFacts] = field(default_factory=list)
    nameservers: dict[str, list[AddressFacts]] = field(default_factory=dict)
    caa: list[Caa] = field(default_factory=list)
    caa_from: str | None = None  # name where the CAA RRset was found (apex or an ancestor)
    ds: bool = False
    dnskey: bool = False
    dnssec: str | None = None  # secure | insecure | bogus, from the validating resolver's AD bit / SERVFAIL
    errors: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- DNS


class Dns:
    """Queries through one validating resolver. Default: Quad9 over DNS-over-TLS, because plain
    port-53 to public resolvers is often blocked and the local stub (systemd-resolved) does not
    validate, which would make the AD bit meaningless."""

    def __init__(self, resolver: str, qps: float) -> None:
        host, _, port = resolver.partition(":")
        self.r = dns.resolver.Resolver(configure=False)
        if port == "53":
            self.r.nameservers = [host]
        else:
            self.r.nameservers = [dns.nameserver.DoTNameserver(host, int(port or 853))]
        self.address = f"{host}:{port or 853}{'' if port == '53' else ' (DoT)'}"
        self.r.lifetime = 10
        self.r.use_edns(0, dns.flags.DO, 1232)
        self.r.flags = dns.flags.RD | dns.flags.AD  # ask the resolver to tell us if it validated
        self._gap = 1 / qps
        self._last = 0.0
        self.last_servfail = False

    def query(self, name: str, rtype: str) -> dns.resolver.Answer | None:
        wait = self._last + self._gap - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        self.last_servfail = False
        try:
            return self.r.resolve(name, rtype, raise_on_no_answer=False)
        except dns.resolver.NoNameservers as e:
            self.last_servfail = "SERVFAIL" in str(e)
            log.debug("%s %s: %s", name, rtype, e)
            return None
        except (dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout) as e:
            log.debug("%s %s: %s", name, rtype, e)
            return None

    def addresses(self, name: str) -> list[str]:
        out: list[str] = []
        for rtype in ("A", "AAAA"):
            ans = self.query(name, rtype)
            if ans and ans.rrset:
                out.extend(r.address for r in ans.rrset)
        return out

    def names(self, name: str, rtype: str) -> list[str]:
        ans = self.query(name, rtype)
        return [str(r.target).rstrip(".").lower() for r in ans.rrset] if ans and ans.rrset else []

    def caa(self, name: str) -> tuple[list[Caa], str | None]:
        """RFC 8659 tree climb: the first ancestor with a CAA RRset decides."""
        labels = name.split(".")
        while len(labels) > 1:  # stop before the TLD
            cand = ".".join(labels)
            ans = self.query(cand, "CAA")
            if ans and ans.rrset:
                return [Caa(r.flags, r.tag.decode(), r.value.decode()) for r in ans.rrset], cand
            labels = labels[1:]
        return [], None

    def exists(self, name: str, rtype: str) -> bool:
        ans = self.query(name, rtype)
        return bool(ans and ans.rrset)

    def dnssec_status(self, name: str) -> str | None:
        """secure (AD set) | insecure (answer without AD) | bogus (validator returned SERVFAIL)."""
        ans = self.query(name, "A")
        if ans is None:
            return "bogus" if self.last_servfail else None
        return "secure" if ans.response.flags & dns.flags.AD else "insecure"


# --------------------------------------------------------------------------- RIPEstat


class RipeStat:
    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.http = httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=30)

    def call(self, call: str, **params: str) -> dict:
        key = call + "_" + "_".join(f"{k}={v}" for k, v in sorted(params.items()))
        path = self.cache_dir / (key.replace("/", "_") + ".json")
        if path.exists():
            return json.loads(path.read_text())
        for attempt in range(4):
            try:
                r = self.http.get(RIPESTAT.format(call=call), params={**params, "sourceapp": SOURCEAPP})
                r.raise_for_status()
                data = r.json()
                path.write_text(json.dumps(data))
                return data
            except httpx.HTTPError as e:
                log.warning("ripestat %s %s: %s (attempt %d)", call, params, e, attempt + 1)
                time.sleep(2**attempt)
        raise RuntimeError(f"ripestat {call} {params} failed")

    def address(self, ip: str) -> AddressFacts:
        f = AddressFacts(ip=ip)
        info = self.call("network-info", resource=ip)["data"]
        f.prefix = info.get("prefix") or None
        f.origin_asns = [int(a) for a in info.get("asns", [])]
        if not f.prefix or not f.origin_asns:
            return f
        announced_len = int(f.prefix.split("/")[1])
        v = self.call("rpki-validation", resource=str(f.origin_asns[0]), prefix=f.prefix)["data"]
        f.rpki = v.get("status")
        for roa in v.get("validating_roas", []):
            f.roas.append(Roa(roa["prefix"], int(roa["origin"]), int(roa["max_length"])))
        f.forgeable_more_specific = any(r.max_length > announced_len for r in f.roas) if f.roas else None
        return f


# --------------------------------------------------------------------------- per domain


def collect(domain: str, dns_: Dns, ripe: RipeStat) -> DomainFacts:
    facts = DomainFacts(
        domain=domain, fetched_at=datetime.now(UTC).isoformat(timespec="seconds"), resolver=dns_.address
    )
    try:
        web_ips = sorted(set(dns_.addresses(domain)) | set(dns_.addresses("www." + domain)))
        facts.web = [ripe.address(ip) for ip in web_ips]
        for ns in dns_.names(domain, "NS"):
            facts.nameservers[ns] = [ripe.address(ip) for ip in dns_.addresses(ns)]
        facts.caa, facts.caa_from = dns_.caa(domain)
        facts.ds = dns_.exists(domain, "DS")
        facts.dnskey = dns_.exists(domain, "DNSKEY")
        facts.dnssec = dns_.dnssec_status(domain)
    except Exception as e:  # keep going; the record says what failed
        log.error("%s: %s", domain, e)
        facts.errors.append(f"{type(e).__name__}: {e}")
    return facts


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--domains", type=Path, default=Path("data/domains.txt"))
    p.add_argument("--out", type=Path, default=Path("data/facts.jsonl"))
    p.add_argument("--cache", type=Path, default=Path("data/ripestat"))
    p.add_argument(
        "--resolver", default="9.9.9.9", help="validating resolver, host[:port]; port 853 = DoT (default), 53 = plain"
    )
    p.add_argument("--qps", type=float, default=10.0, help="max DNS queries per second")
    p.add_argument("--limit", type=int, help="only the first N domains")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if a.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)

    domains = [d.strip().lower() for d in a.domains.read_text().splitlines() if d.strip() and not d.startswith("#")]
    if a.limit:
        domains = domains[: a.limit]
    dns_, ripe = Dns(a.resolver, a.qps), RipeStat(a.cache)
    log.info("%d domains, resolver %s", len(domains), dns_.address)

    tmp = a.out.with_suffix(".jsonl.part")
    with tmp.open("w") as f:
        for i, d in enumerate(domains, 1):
            facts = collect(d, dns_, ripe)
            f.write(json.dumps(asdict(facts), ensure_ascii=False) + "\n")
            f.flush()
            log.info(
                "[%d/%d] %s web=%d ns=%d caa=%d ds=%s dnssec=%s",
                i,
                len(domains),
                d,
                len(facts.web),
                len(facts.nameservers),
                len(facts.caa),
                facts.ds,
                facts.dnssec,
            )
    tmp.replace(a.out)
    log.info("wrote %s", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
