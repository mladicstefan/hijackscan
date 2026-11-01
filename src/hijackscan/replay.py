"""`hijackscan replay [incident ...]`: four BGP hijacks against the ROAs of their day, every scan in parallel.

Only the ROA set is historical (one archive day per incident). DNS answers and the routing table are today's,
so each incident also scans a domain that still sits in the infrastructure that was hijacked; the original
victims have all moved since (Softaculous/Virtualizor and MyEtherWallet are behind Cloudflare, the Celer host
is gone). Every scan is forced: the collected cache is keyed by domain, not by ROA day.

Three of the four are certificate thefts (a CA validated the attacker over the hijacked route). MyEtherWallet
is not: the attackers presented a self-signed certificate and relied on users clicking through the warning.
It stays in the set because it is the canonical nameserver-path hijack of space with no ROA.

Sources: APNIC blog 2026-09-22 and ipregistry (Hetzner/Virtualizor); Cloudflare and Internet Society blogs,
2018-04 (Route 53 / MyEtherWallet); MANRS and S2W, 2022-02 (KLAYswap); Coinbase, Kentik on APNIC blog
2022-11-07, and crt.sh id 7356184952 (Celer Bridge).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path

from . import console
from .collect import Collector
from .collect.dns import Dns
from .collect.ripestat import RipeStat
from .config import Config
from .report import risk_view
from .report.domain import render_html, render_text
from .risk import assess
from .score import score


@dataclass(frozen=True)
class Scan:
    domain: str
    note: str  # what today's verdict for this domain says about the incident


@dataclass(frozen=True)
class Incident:
    key: str
    title: str
    day: str  # the RPKI archive day: the ROAs in force when it happened
    story: tuple[str, ...]  # the verified facts, one line each
    scans: tuple[Scan, ...]


INCIDENTS: tuple[Incident, ...] = (
    Incident(
        "hetzner",
        "1. Virtualizor / Hetzner, 2026-08-28: an RPKI-valid more-specific, a Let's Encrypt certificate, a bad update",
        "2026-08-28",
        (
            "20:57 UTC: AS62390 (NexonHost) announced 162.55.80.0/24 through AS6204 with Hetzner's AS24940 kept as the",
            "origin. The ROA for 162.55.0.0/16 allowed maxLength 24, so the forgery validated everywhere; at its peak",
            "72% of RIS peers preferred it. 33 minutes later (CT 21:30:29 UTC) Let's Encrypt issued one certificate",
            "for 26 Softaculous names (softaculous.com, files.virtualizor.com, api.virtualizor.com, ...) after the",
            "HTTP-01 check reached the impostor at 162.55.80.8; a malicious Virtualizor update followed. Two waves,",
            "33 hours in all, ending 2026-08-30 06:10 UTC. Hetzner set the ROA to maxLength 16 on 2026-09-22.",
        ),
        (
            Scan(
                "softaculous.com", "the victim: behind Cloudflare since the incident, so today's web prefixes are tight"
            ),
            Scan("virtualizor.com", "the update host's domain: behind Cloudflare now as well"),
            Scan(
                "roberiehitus.ee",
                "still at Hetzner: 95.217.0.0/16 announced, ROA maxLength 24, the incident's exact shape",
            ),
        ),
    ),
    Incident(
        "mew",
        "2. MyEtherWallet / Route 53, 2018-04-24: nameserver space with no ROA, a self-signed certificate",
        "2018-04-24",
        (
            "11:05 to 12:55 UTC: eNet AS10297 announced 205.251.192.0/24, .193, .195, .197 and .199, more-specifics of",
            "Route 53's four /23s (205.251.192.0/23 to 205.251.198.0/23). Amazon had no ROA, so nothing was invalid.",
            "The rogue resolvers answered myetherwallet.com with a server in AS48693/AS41995 (Russia), which",
            "presented a SELF-SIGNED certificate: no CA was involved; users who clicked through the warning lost",
            "about 150 000 USD in ETH. Today Amazon announces the Route 53 ranges as /24s, so no more-specific fits.",
        ),
        (
            Scan(
                "myetherwallet.com",
                "the victim: behind Cloudflare now; with 2018's ROA set none of its space was covered",
            ),
            Scan("amazon.com", "still on Route 53 nameservers: 205.251.19x.0/24 with no ROA that day, but already /24"),
        ),
    ),
    Incident(
        "klayswap",
        "3. KLAYswap / Kakao SDK, 2022-02-03: more-specifics of unsigned space, a ZeroSSL certificate",
        "2022-02-03",
        (
            "01:04 UTC (10:04 KST): 211.249.221.0/24, then 02:09 UTC 121.53.104.0/24, more-specifics of Kakao's",
            "211.249.216.0/21 (AS7625) and 121.53.104.0/23 (AS38099), appeared with AS9457 (Dreamline) as origin",
            "behind a forged AS6461 adjacency. No ROA covered either prefix. developers.kakao.com, which served the",
            "Kakao JavaScript SDK, resolved into both; ZeroSSL issued a certificate for it at 11:27:57 KST, and a",
            "tampered kakao.min.js redirected KLAYswap transactions until 13:04 KST: about 1.9 M USD moved.",
        ),
        (
            Scan("developers.kakao.com", "the hijacked host: an alias into kgns5.com, its addresses have moved since"),
            Scan(
                "klayswap.com",
                "never hijacked itself: the theft came through the third-party script, outside this model",
            ),
        ),
    ),
    Incident(
        "celer",
        "4. Celer Bridge, 2022-08-17: a forged Amazon origin inside a maxLength-24 ROA, a GoGetSSL certificate",
        "2022-08-17",
        (
            "19:39 UTC: AS209243 (QuickHostUK) announced 44.235.216.0/24 inside Amazon's 44.224.0.0/11 with the",
            "origin forged to Amazon's AS14618, after planting route objects for it in AltDB on 16 August. Amazon's",
            "ROAs for 44.192.0.0/10 (AS8987, AS14618, AS16509, maxLength 24) made the forgery RPKI-valid. GoGetSSL",
            "issued a DV certificate for cbridge-prod2.celer.network at 19:42:25 UTC, three minutes in; 32 users lost",
            "about 235 000 USD before the route was withdrawn for good at 22:07 UTC.",
        ),
        (
            Scan(
                "celer.network",
                "the hijacked hostname is gone; www still sits in AWS space under the same maxLength-24 ROAs",
            ),
        ),
    ),
)

KEYS = tuple(i.key for i in INCIDENTS)


def run_replay(cfg: Config, keys: list[str] | None, out: Path, *, details: bool = False) -> int:
    """Collect every scan of the chosen incidents in one thread pool (one Collector per ROA day, one shared
    resolver cache and RIPEstat client), then print incident by incident. Exit 1 when any record has errors."""
    incidents = [i for i in INCIDENTS if not keys or i.key in keys]
    days = sorted({i.day for i in incidents})
    jobs = [(inc, sc) for inc in incidents for sc in inc.scans]
    out.mkdir(parents=True, exist_ok=True)
    console.stage(f"replay  {len(incidents)} incidents, {len(jobs)} scans, ROA days {', '.join(days)}")
    dns = Dns(cfg.resolver, cfg.dns_qps)
    ripe = RipeStat(cfg.cache_dir, cfg.ripestat_concurrency, cfg.ripestat_url)
    first = Collector(replace(cfg, rpki_date=days[0]), dns=dns, ripe=ripe)
    first.prepare()  # proves the resolver validates once; the other days reuse that proof
    collectors = {days[0]: first} | {
        day: Collector(replace(cfg, rpki_date=day), dns=dns, ripe=ripe, resolver_check=first.resolver_check)
        for day in days[1:]
    }
    with ThreadPoolExecutor(max_workers=max(1, len(days) - 1)) as pool:  # archive + index per day, side by side
        list(pool.map(Collector.prepare, collectors.values()))

    def one(job: tuple[Incident, Scan]) -> tuple[list[str], bool]:
        inc, sc = job
        c = collectors[inc.day]
        rec = c.collect_one(sc.domain, label=f"[{inc.key} {inc.day}]")
        s = score(rec, caps=c.cfg.routable_caps)
        r = assess(rec, s)
        path = out / f"{sc.domain}-{inc.day}.html"
        path.write_text(render_html(s, rec, r), encoding="utf-8")
        lines = risk_view.summary_text(r) + [f"  replay      {sc.note}"]
        if details:
            lines += risk_view.details_text(r) + ["", "RAW FACTS", "", render_text(s, rec)]
        return lines, bool(rec["errors"])

    with ThreadPoolExecutor(max_workers=cfg.workers) as pool:
        results = dict(zip(jobs, pool.map(one, jobs), strict=True))

    failed = 0
    for inc in incidents:
        console.stage(inc.title)
        console.show([f"  {line}" for line in inc.story] + [""])
        for sc in inc.scans:
            lines, bad = results[(inc, sc)]
            failed += bad
            console.show(lines + [""])
    console.ok("HTML drill-downs", str(out))
    if failed:
        console.fail(f"{failed} scans with collection errors")
    return 1 if failed else 0
