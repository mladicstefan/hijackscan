"""hijackscan: configuration exposure of .rs domains to certificate theft through BGP hijacks below DNS.

hijackscan collect <domain|domains.txt> [--force]       raw facts -> data/collected/<domain>.json
hijackscan zone <domains.txt> --out dir/                 zone report (report.json + report.html)
hijackscan <domain> [--html file]                        one domain: facts, class, attack path, fixes
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import replace
from pathlib import Path

from .config import Config


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hijackscan", description=__doc__.splitlines()[0])
    p.add_argument("--resolver", help=f"validating resolver host[:port] (default {Config.resolver})")
    p.add_argument("--rpki-date", help=f"RPKI archive day for ROAs (default {Config.rpki_date})")
    p.add_argument(
        "--max-age", type=float, help=f"hours a collected record stays fresh (default {Config.max_age_hours})"
    )
    p.add_argument("--workers", type=int)
    p.add_argument("--data-dir", type=Path, help=f"default {Config.data_dir}")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd")
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
    return p


def main() -> None:
    argv = sys.argv[1:]
    if argv and not argv[0].startswith("-") and argv[0] not in ("collect", "zone", "domain"):
        argv = ["domain", *argv]  # `hijackscan blic.rs`
    a = parser().parse_args(argv)
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if a.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    cfg = Config()
    for field, value in (
        ("resolver", a.resolver),
        ("rpki_date", a.rpki_date),
        ("max_age_hours", a.max_age),
        ("workers", a.workers),
        ("data_dir", a.data_dir),
    ):
        if value is not None:
            cfg = replace(cfg, **{field: value})

    from .collect import Collector, read_domains

    if a.cmd == "collect":
        Collector(cfg).run(read_domains(a.target), force=a.force)
        return
    if a.cmd == "zone":
        from .report.zone import zone_report

        sys.exit(zone_report(cfg, read_domains(a.domains), a.out, force=a.force))
    if a.cmd == "domain":
        from .report.domain import domain_report

        sys.exit(domain_report(cfg, a.name.lower().rstrip("."), html_path=a.html, force=a.force))
    parser().print_help()
    sys.exit(2)
