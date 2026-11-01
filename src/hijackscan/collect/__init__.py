"""Raw facts per domain → data/collected/<domain>.json. Observes, never judges.

For each domain: A/AAAA (with AD flag and rcode) of the name, www and every NS host; the zones the
name and its CNAME targets live in (found by their SOA), with NS and DS at each zone apex; DNSKEY
at the first; the CAA RRset at every label up to the TLD; per distinct address the announced prefix,
origin ASNs and RIPEstat's RPKI verdict, plus every covering ROA from the local RPKI archive; AS names.
"""

from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

from publicsuffix2 import get_sld

from .. import console
from ..config import Config
from .dns import Dns
from .resolver_check import check_resolver, passes
from .ripestat import RipeStat
from .rpki import RoaIndex, ensure_archive, latest_archive_day

MAX_CNAME_HOPS = 8  # CNAME targets followed per name (resolvers stop around there too)


class Collector:
    """Collects what is stale. The resolver check, the ROA day and index and the RIPEstat client are prepared
    only when at least one domain is actually collected: a run served from data/collected/ touches no network."""

    def __init__(
        self,
        cfg: Config,
        *,
        dns: Dns | None = None,
        ripe: RipeStat | None = None,
        resolver_check: dict | None = None,
    ) -> None:
        """`dns`, `ripe` and `resolver_check` let several Collectors (one per ROA day, as in `hijackscan replay`)
        share one resolver cache, one RIPEstat client (so its concurrency limit holds across all of them) and one
        proof that the resolver validates."""
        self.cfg = cfg
        self.dns = dns or Dns(cfg.resolver, cfg.dns_qps)
        self._shared_ripe = ripe
        self._shared_check = resolver_check
        self._ready = False
        self._lock = threading.Lock()

    def prepare(self) -> None:
        """Once per Collector: prove the resolver validates, pick and load the ROA day, open RIPEstat."""
        with self._lock:
            if self._ready:
                return
            cfg = self.cfg
            self.resolver_check = self._shared_check or check_resolver(self.dns)
            if not passes(self.resolver_check):
                console.fail("resolver does not validate DNSSEC", f"{self.dns.address}: {self.resolver_check}")
                raise SystemExit(1)
            if not self._shared_check:
                console.ok(
                    "resolver validates DNSSEC",
                    f"{self.dns.address}: AD on {self.resolver_check['signed_zone']}, "
                    f"SERVFAIL on {self.resolver_check['bogus_zone']}",
                )
            if cfg.rpki_date == "latest":
                day, why = latest_archive_day(cfg.data_dir / "rpki", cfg.rpki_max_age_days)
                cfg = replace(cfg, rpki_date=day)
                self.cfg = cfg
            else:
                why = "given"
            console.info("rpki day", f"{cfg.rpki_date}  ({why})")
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", cfg.rpki_date):
                ensure_archive(cfg.rpki_dir, cfg.rpki_date)
            elif not any(cfg.rpki_dir.glob("*/roas.csv.xz")):  # a synthetic day (the lab's "lab") must be on disk
                raise SystemExit(f"no ROA archive under {cfg.rpki_dir}: use a YYYY-MM-DD day or write one there")
            self.roas = RoaIndex(cfg.rpki_dir)
            self.ripe = self._shared_ripe or RipeStat(cfg.cache_dir, cfg.ripestat_concurrency, cfg.ripestat_url)
            cfg.collected_dir.mkdir(parents=True, exist_ok=True)
            self._ready = True

    # -- one domain --------------------------------------------------------

    def collect(self, domain: str) -> dict:
        self.prepare()
        rec: dict = {
            "domain": domain,
            "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "resolver": self.dns.address,
            "resolver_check": self.resolver_check,
            "routing_source": self.cfg.ripestat_url,
            "rpki_source": str(self.cfg.rpki_dir),
            "routable_caps": list(self.cfg.routable_caps),
            "rpki_date": self.cfg.rpki_date,
            "names": {},
            "zones": [],  # ordered: the zone of the name first, then the zone of each CNAME target
            "ds": None,  # the first zone's DS (every zone's is in zones[])
            "dnskey": None,
            "caa_chain": [],
            "nameservers": {},  # merged over every zone: any of them can answer a CA's resolver
            "addresses": {},
            "asns": {},
            "errors": [],
        }
        try:
            for name in (domain, f"www.{domain}"):
                rec["names"][name] = self._addresses(name)
            for apex in self._zones(domain, rec["names"]):
                hosts = [ns.rstrip(".").lower() for ns in self.dns.query(apex, "NS").records]
                rec["zones"].append({"name": apex, "ds": self.dns.query(apex, "DS").to_json(), "nameservers": hosts})
                for ns in hosts:
                    if ns not in rec["nameservers"]:
                        rec["nameservers"][ns] = self._addresses(ns)
            rec["ds"] = rec["zones"][0]["ds"]
            rec["dnskey"] = self.dns.query(rec["zones"][0]["name"], "DNSKEY").to_json()
            labels = domain.split(".")
            for i in range(len(labels)):
                name = ".".join(labels[i:])
                rec["caa_chain"].append({"name": name, **self.dns.query(name, "CAA").to_json()})
            ips = {
                ip for n in list(rec["names"].values()) + list(rec["nameservers"].values()) for ip in n["A"] + n["AAAA"]
            }
            for ip in sorted(ips):
                rec["addresses"][ip] = self._address(ip)
            for asn in sorted({a for v in rec["addresses"].values() for a in v["origin_asns"]}):
                rec["asns"][str(asn)] = self.ripe.as_overview(asn)
        except Exception as e:  # noqa: BLE001 - the batch must never abort
            console.fail(domain, str(e))
            rec["errors"].append(f"{type(e).__name__}: {e}")
        return rec

    def _addresses(self, name: str) -> dict:
        a, aaaa = self.dns.query(name, "A"), self.dns.query(name, "AAAA")
        return {
            "A": a.records,
            "AAAA": aaaa.records,
            "ad": {"A": a.ad, "AAAA": aaaa.ad},
            "rcode": {"A": a.rcode, "AAAA": aaaa.rcode},
            "cname": (a.cnames or aaaa.cnames)[:MAX_CNAME_HOPS],
        }

    def _zones(self, domain: str, names: dict) -> list[str]:
        """The zone apexes a CA's resolver depends on for `domain`: the zone of the name itself, then the zone
        of every CNAME target of the name and of www, in chain order, each once."""
        zones = [self._zone_apex(domain)]
        for entry in names.values():
            for target in entry["cname"]:
                apex = self._zone_apex(target)
                if apex not in zones:
                    zones.append(apex)
        return zones

    def _zone_apex(self, name: str) -> str:
        """The apex of the zone holding `name`: the owner of the SOA the resolver returns for it, in the answer
        section when the name is the apex, in the authority section when it is below one (NODATA or NXDOMAIN).
        A CNAME owner is chased to its target, so the SOA seen is the target's: its own zone is the one holding
        its parent name. The registrable domain is a floor in two cases: an NXDOMAIN whose SOA comes from above
        it (the registry does not delegate the name) and a CNAME at a delegated apex both leave the name itself.
        A NODATA SOA from above the floor is trusted (foo.github.io lives in github.io)."""
        floor = get_sld(name, strict=False) or name
        soa = self.dns.query(name, "SOA")
        if soa.cnames:
            parent = name.partition(".")[2]
            return self._zone_apex(parent) if _within(parent, floor) else name
        if soa.soa and _within(name, soa.soa) and (_within(soa.soa, floor) or soa.rcode != "NXDOMAIN"):
            return soa.soa
        return floor

    def _address(self, ip: str) -> dict:
        prefix, asns = self.ripe.network_info(ip)
        return {
            "prefix": prefix,
            "origin_asns": asns,
            "routing": self.ripe.routing_status(prefix) if prefix else None,
            "rpki_state": self.ripe.rpki_state(asns[0], prefix) if prefix and asns else None,
            "roas": self.roas.covering(prefix) if prefix else [],
            "roas_within": self.roas.contained(prefix) if prefix else [],
        }

    # -- a batch -----------------------------------------------------------

    def path(self, domain: str) -> Path:
        return self.cfg.collected_dir / f"{domain}.json"

    def collect_one(self, domain: str, label: str = "") -> dict:
        """Collect one domain, store it under data/collected/ and log one line; `label` prefixes the log line."""
        rec = self.collect(domain)
        tmp = self.path(domain).with_suffix(".json.part")
        tmp.write_text(json.dumps(rec, indent=1, ensure_ascii=False) + "\n")
        tmp.replace(self.path(domain))
        detail = (
            f"{len(rec['names'])} names, {len(rec['zones'])} zones, {len(rec['nameservers'])} ns, "
            f"{len(rec['addresses'])} addrs, caa on {sum(bool(c['records']) for c in rec['caa_chain'])} labels"
        )
        what = f"{label} {domain}".strip()
        if rec["errors"]:
            console.fail(what, f"{detail}, {len(rec['errors'])} errors: {rec['errors'][0]}")
        else:
            console.ok(what, detail)
        return rec

    def fresh(self, domain: str) -> bool:
        p = self.path(domain)
        return p.exists() and (time.time() - p.stat().st_mtime) < self.cfg.max_age_hours * 3600

    def run(self, domains: list[str], *, force: bool = False) -> list[dict]:
        todo = [d for d in domains if force or not self.fresh(d)]
        console.stage(f"collect  {len(todo)} of {len(domains)} domains")
        if todo:
            self.prepare()  # before the pool: the one place the index is built
        cached = len(domains) - len(todo)
        console.info("resolver", self.dns.address)
        console.info("workers", f"{self.cfg.workers}   ({cached} cached, younger than {self.cfg.max_age_hours:g} h)")
        t0 = time.monotonic()
        done = count(1)
        failed: list[str] = []

        def one(domain: str) -> dict:
            rec = self.collect_one(domain, label=f"[{next(done)}/{len(todo)}]")
            if rec["errors"]:
                failed.append(domain)
            return rec

        with ThreadPoolExecutor(max_workers=self.cfg.workers) as pool:
            list(pool.map(one, todo))
        took = f"{len(todo)} collected in {time.monotonic() - t0:.0f}s"
        if failed:
            console.note(
                f"{took}, {len(failed)} with errors (rerun with --force to retry): {', '.join(failed[:5])}"
                + (" …" if len(failed) > 5 else "")
            )
        else:
            console.ok(took)
        records = [json.loads(self.path(d).read_text()) for d in domains if self.path(d).exists()]
        if not todo:  # nothing resolved a day: the records carry the one they were collected against
            days = sorted({r.get("rpki_date", "?") for r in records})
            console.info("rpki day", f"{', '.join(days)}  (from the cached records)")
        return records


def _within(name: str, zone: str) -> bool:
    """`name` is `zone` or below it."""
    return name == zone or name.endswith("." + zone)


def read_domains(arg: str) -> list[str]:
    """A file of domains (one per line, # comments) or a single domain name."""
    return read_list(arg)[0]


def read_list(arg: str) -> tuple[list[str], dict | None]:
    """Domains plus the population facts if the file is a `hijackscan sample` output (None for a plain list)."""
    p = Path(arg)
    if p.is_file():
        from .zonefile import read_meta

        names = [d.strip().lower() for d in p.read_text().splitlines() if d.strip() and not d.startswith("#")]
        return names, read_meta(p)
    if "/" in arg or arg.endswith(".txt"):
        raise SystemExit(f"no such file: {arg} (cwd {Path.cwd()})")
    return [arg.strip().lower().rstrip(".")], None
