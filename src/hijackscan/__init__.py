"""hijackscan: configuration exposure of .rs domains to certificate theft through BGP hijacks below DNS.

hijackscan sample <zone parts...> --out domains.txt    seeded sample of a TLD zone (dig axfr text)
hijackscan collect <domain|domains.txt> [--force]       raw facts -> data/collected/<domain>.json
hijackscan zone <domains.txt> --out dir/                 zone report (report.json + report.html)
hijackscan <domain> [--details] [--html file]            one domain: risk summary; --details for everything
hijackscan list [domains.txt|domain] [filters]           filter and sort collected domains by risk (no network)
hijackscan browse <domains.jsonl> [--out file]           one HTML page of every domain, details on click
hijackscan replay [incident ...] [--details]              four historical hijacks against the ROAs of their day
hijackscan load <domains.txt> [--name NAME]              score collected records, save them to MongoDB as a run
hijackscan serve [--port 8000] [--reload]                read-only API over MongoDB, docs at /docs
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

from . import console
from .config import Config


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hijackscan", description=__doc__.splitlines()[0])
    p.add_argument("--resolver", help=f"validating resolver host[:port] (default {Config.resolver})")
    p.add_argument("--rpki-date", help=f"RPKI archive day for ROAs (default {Config.rpki_date})")
    p.add_argument(
        "--rpki-max-age",
        type=int,
        help=f"days a local archive day still counts as latest (default {Config.rpki_max_age_days})",
    )
    p.add_argument(
        "--max-age", type=float, help=f"hours a collected record stays fresh (default {Config.max_age_hours})"
    )
    p.add_argument("--workers", type=int)
    p.add_argument("--data-dir", type=Path, help=f"default {Config.data_dir}")
    p.add_argument("--ripestat-url", help=f"RIPEstat Data API template (default {Config.ripestat_url})")
    p.add_argument(
        "--routable-cap-v4", type=int, help=f"longest routable IPv4 prefix (default {Config.routable_cap_v4})"
    )
    p.add_argument(
        "--routable-cap-v6", type=int, help=f"longest routable IPv6 prefix (default {Config.routable_cap_v6})"
    )
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("sample", help="draw a reproducible sample of delegations from a zone file")
    s.add_argument("zone", nargs="+", type=Path, help="dig axfr output, one or more parts in order")
    s.add_argument("--n", type=int, default=100)
    s.add_argument("--seed", type=int, default=1)
    s.add_argument("--out", type=Path, required=True)
    c = sub.add_parser("collect", help="collect raw facts")
    c.add_argument("target", help="a domain or a file with one domain per line")
    c.add_argument("--force", action="store_true", help="ignore fresh cached records")
    z = sub.add_parser("zone", help="aggregate report for a list of domains")
    z.add_argument("domains", help="file with one domain per line")
    z.add_argument("--out", type=Path, required=True)
    z.add_argument("--force", action="store_true")
    d = sub.add_parser("domain", help="drill-down for one domain")
    d.add_argument("name")
    d.add_argument("--html", type=Path)
    d.add_argument("--force", action="store_true")
    d.add_argument("--details", action="store_true", help="calculation, findings, vectors, references, raw facts")
    b = sub.add_parser("browse", help="HTML page of every domain in a domains.jsonl, worst first, details on click")
    b.add_argument("jsonl", type=Path, help="a domains.jsonl written by `hijackscan zone`")
    b.add_argument("--out", type=Path, help="default: domains.html next to the jsonl")
    li = sub.add_parser("list", help="filter and sort collected domains by risk (reads data/collected, no network)")
    li.add_argument("target", nargs="?", help="a domain or a file of domains (default: every collected record)")
    li.add_argument(
        "--severity", help="comma list: None,Low,Medium,High,Critical,Unknown (e.g. High,Critical)", default=""
    )
    li.add_argument("--min-score", type=float, help="only domains scoring at least this")
    li.add_argument("--label", default="", help="comma list, e.g. ns-partial,open-dns")
    li.add_argument("--finding", default="", help="comma list of finding ids; a domain must have all of them")
    li.add_argument("--sort", choices=("score", "domain", "label"), default="score")
    li.add_argument("--details", action="store_true", help="print the full details of every match")
    li.add_argument("--json", action="store_true", help="one JSON object per line (summary, or full with --details)")
    from .replay import KEYS

    r = sub.add_parser("replay", help="four BGP-hijack incidents scanned against the ROAs of their day, in parallel")
    r.add_argument("incidents", nargs="*", choices=KEYS, metavar="incident", help=f"any of {', '.join(KEYS)}")
    r.add_argument(
        "--out", type=Path, default=Path("data/out/replay"), help="HTML drill-downs (default data/out/replay)"
    )
    r.add_argument("--details", action="store_true", help="calculation, findings and raw facts for every scan")
    lo = sub.add_parser("load", help="score collected records (no network) and save them to MongoDB as a new run")
    lo.add_argument("domains", help="file with one domain per line (the same list as for `zone`)")
    lo.add_argument("--name", help="a name for the run shown on the web page (default: the file name)")
    lo.add_argument("--skip-existing", action="store_true", help="do nothing if a run with this name is loaded")
    se = sub.add_parser("serve", help="start the read-only API over MongoDB (docs at http://127.0.0.1:8000/docs)")
    se.add_argument("--host", default="127.0.0.1", help="address to listen on (default: this computer only)")
    se.add_argument("--port", type=int, default=8000)
    se.add_argument("--reload", action="store_true", help="restart automatically when the code changes")
    return p


def main() -> None:
    argv = sys.argv[1:]
    if (
        argv
        and not argv[0].startswith("-")
        and argv[0] not in ("sample", "collect", "zone", "domain", "list", "browse", "replay", "load", "serve")
    ):
        argv = ["domain", *argv]  # `hijackscan blic.rs`
    a = parser().parse_args(argv)
    console.setup(a.verbose)
    cfg = Config()
    for field, value in (
        ("resolver", a.resolver),
        ("rpki_date", a.rpki_date),
        ("rpki_max_age_days", a.rpki_max_age),
        ("max_age_hours", a.max_age),
        ("workers", a.workers),
        ("data_dir", a.data_dir),
        ("ripestat_url", a.ripestat_url),
        ("routable_cap_v4", a.routable_cap_v4),
        ("routable_cap_v6", a.routable_cap_v6),
    ):
        if value is not None:
            cfg = replace(cfg, **{field: value})

    if a.cmd == "sample":
        from .collect.zonefile import read_zone, sample, write_sample

        z = read_zone(a.zone)
        write_sample(z, sample(z, a.n, a.seed), a.seed, a.out)
        return

    from .collect import Collector, read_domains, read_list

    if a.cmd == "collect":
        Collector(cfg).run(read_domains(a.target), force=a.force)
        return
    if a.cmd == "zone":
        from .report.zone import zone_report

        domains, meta = read_list(a.domains)
        sys.exit(zone_report(cfg, domains, a.out, meta=meta, force=a.force))
    if a.cmd == "domain":
        from .report.domain import domain_report

        sys.exit(domain_report(cfg, a.name.lower().rstrip("."), html_path=a.html, force=a.force, details=a.details))
    if a.cmd == "browse":
        from .report.browse import browse

        if not a.jsonl.is_file():
            raise SystemExit(f"no such file: {a.jsonl}")
        console.ok("wrote", str(browse(a.jsonl, a.out)))
        return
    if a.cmd == "list":
        from .report.listing import listing

        sys.exit(listing(cfg, a))
    if a.cmd == "replay":
        from .replay import run_replay

        sys.exit(run_replay(cfg, a.incidents, a.out, details=a.details))
    if a.cmd == "load":
        from .store import load

        domains, meta = read_list(a.domains)
        r = load(cfg, domains, meta, source=a.domains, name=a.name, skip_existing=a.skip_existing)
        if r["skipped"]:
            print(f"run '{r['name']}' is already loaded: skipped")
        else:
            print(f"run {r['run_id']} '{r['name']}': {r['domains']} domains saved, {r['missing']} not collected ({r['db']})")
        return
    if a.cmd == "serve":
        import uvicorn

        uvicorn.run("hijackscan.api:app", host=a.host, port=a.port, reload=a.reload)
        return
    parser().print_help()
    sys.exit(2)
