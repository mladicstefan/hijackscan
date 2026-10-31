"""Raw facts per domain → data/collected/<domain>.json. Observes, never judges.

For each domain: A/AAAA (with AD flag and rcode) of apex, www and every NS host; DS and DNSKEY;
the CAA RRset at every label up to the TLD; per distinct address the announced prefix, origin
ASNs and RIPEstat's RPKI verdict, plus every covering ROA from the local RPKI archive; AS names.
"""

from __future__ import annotations

import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from ..config import Config
from .dns import Dns
from .resolver_check import check_resolver, passes
from .ripestat import RipeStat
from .rpki import RoaIndex, ensure_archive, latest_archive_day

log = logging.getLogger(__name__)


class Collector:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.dns = Dns(cfg.resolver, cfg.dns_qps)
        self.resolver_check = check_resolver(self.dns)
        if not passes(self.resolver_check):
            raise SystemExit(f"resolver {self.dns.address} does not validate DNSSEC: {self.resolver_check}")
        if cfg.rpki_date == "latest":
            cfg = replace(cfg, rpki_date=latest_archive_day())
            self.cfg = cfg
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", cfg.rpki_date):
            ensure_archive(cfg.rpki_dir, cfg.rpki_date)
        elif not any(cfg.rpki_dir.glob("*/roas.csv.xz")):  # a synthetic day (the lab's "lab") must be on disk
            raise SystemExit(f"no ROA archive under {cfg.rpki_dir}: use a YYYY-MM-DD day or write one there")
        self.roas = RoaIndex(cfg.rpki_dir)
        self.ripe = RipeStat(cfg.cache_dir, cfg.ripestat_concurrency, cfg.ripestat_url)
        cfg.collected_dir.mkdir(parents=True, exist_ok=True)

    # -- one domain --------------------------------------------------------

    def collect(self, domain: str) -> dict:
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
            "ds": None,
            "dnskey": None,
            "caa_chain": [],
            "nameservers": {},
            "addresses": {},
            "asns": {},
            "errors": [],
        }
        try:
            for name in (domain, f"www.{domain}"):
                rec["names"][name] = self._addresses(name)
            rec["ds"] = self.dns.query(domain, "DS").to_json()
            rec["dnskey"] = self.dns.query(domain, "DNSKEY").to_json()
            labels = domain.split(".")
            for i in range(len(labels)):
                name = ".".join(labels[i:])
                rec["caa_chain"].append({"name": name, **self.dns.query(name, "CAA").to_json()})
            for ns in self.dns.query(domain, "NS").records:
                ns = ns.rstrip(".").lower()
                rec["nameservers"][ns] = self._addresses(ns)
            ips = {
                ip for n in list(rec["names"].values()) + list(rec["nameservers"].values()) for ip in n["A"] + n["AAAA"]
            }
            for ip in sorted(ips):
                rec["addresses"][ip] = self._address(ip)
            for asn in sorted({a for v in rec["addresses"].values() for a in v["origin_asns"]}):
                rec["asns"][str(asn)] = self.ripe.as_overview(asn)
        except Exception as e:  # noqa: BLE001 - the batch must never abort
            log.error("%s: %s", domain, e)
            rec["errors"].append(f"{type(e).__name__}: {e}")
        return rec

    def _addresses(self, name: str) -> dict:
        a, aaaa = self.dns.query(name, "A"), self.dns.query(name, "AAAA")
        return {
            "A": a.records,
            "AAAA": aaaa.records,
            "ad": {"A": a.ad, "AAAA": aaaa.ad},
            "rcode": {"A": a.rcode, "AAAA": aaaa.rcode},
        }

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

    def fresh(self, domain: str) -> bool:
        """Young enough to reuse, and complete: a record with errors is always collected again."""
        p = self.path(domain)
        if not p.exists() or (time.time() - p.stat().st_mtime) >= self.cfg.max_age_hours * 3600:
            return False
        try:
            return not json.loads(p.read_text(encoding="utf-8")).get("errors")
        except (OSError, ValueError):
            return False  # unreadable or half-written: collect again

    def run(self, domains: list[str], *, force: bool = False) -> list[dict]:
        todo = [d for d in domains if force or not self.fresh(d)]
        log.info(
            "%d domains, %d to collect (resolver %s, rpki %s, %d workers)",
            len(domains),
            len(todo),
            self.dns.address,
            self.cfg.rpki_date,
            self.cfg.workers,
        )
        t0 = time.monotonic()

        def one(domain: str) -> dict:
            rec = self.collect(domain)
            tmp = self.path(domain).with_suffix(".json.part")
            tmp.write_text(json.dumps(rec, indent=1, ensure_ascii=False) + "\n")
            tmp.replace(self.path(domain))
            log.info(
                "%s: %d names, %d ns, %d addrs, caa labels with records=%d, errors=%d",
                domain,
                len(rec["names"]),
                len(rec["nameservers"]),
                len(rec["addresses"]),
                sum(bool(c["records"]) for c in rec["caa_chain"]),
                len(rec["errors"]),
            )
            return rec

        with ThreadPoolExecutor(max_workers=self.cfg.workers) as pool:
            list(pool.map(one, todo))
        log.info("collected %d in %.0fs", len(todo), time.monotonic() - t0)
        return [json.loads(self.path(d).read_text()) for d in domains if self.path(d).exists()]


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
