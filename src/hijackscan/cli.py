"""`hijackscan fetch <target>... | all` — get public datasets onto disk, verified, with a manifest."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from .fetch import TARGETS
from .fetch.common import Fetcher, load_config

ORDER = ["caida", "rpki", "ris", "tranco", "bgpy-smoke", "crtsh"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hijackscan")
    p.add_argument("--config", type=Path, default=Path("config/fetch.yaml"))
    p.add_argument("--quiet", "-q", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="download datasets into data/")
    f.add_argument("targets", nargs="+", help=f"one or more of {', '.join(TARGETS)} or 'all'")
    f.add_argument("--force", action="store_true", help="re-download even if present")
    f.add_argument("--yes", action="store_true", help="accept large downloads (ris > 2 GB)")
    f.add_argument("--email", help="contact email for the User-Agent")
    f.add_argument("--data-dir", help="override data_dir")
    f.add_argument("--caida-date", help="caida: YYYY-MM-01")
    f.add_argument("--dates", help="rpki: comma-separated YYYY-MM-DD (or 'today')")
    f.add_argument("--rrcs", help="ris: comma-separated collector numbers, e.g. 00,01")
    f.add_argument("--window", help="ris: START/END, e.g. 2026-08-28T10:00Z/2026-08-28T10:30Z")
    f.add_argument("--crtsh-start", help="crtsh: first month YYYY-MM-DD")
    f.add_argument("--crtsh-end", help="crtsh: end (exclusive) YYYY-MM-DD or 'today'")
    f.add_argument("--months", type=int, help="crtsh: only the last N months of the range (testing)")
    f.add_argument("--finalize", action="store_true", help="crtsh: build names/registered_domains from cache")
    return p


def setup_logging(quiet: bool, verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    logging.basicConfig(stream=sys.stderr, level=level,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
    logging.getLogger("httpx").setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.quiet, args.verbose)
    log = logging.getLogger("hijackscan")

    overrides = {
        "contact_email": args.email,
        "data_dir": args.data_dir,
        "caida.date": args.caida_date,
        "rpki.dates": args.dates.split(",") if args.dates else None,
        "ris.rrcs": [r.strip() for r in args.rrcs.split(",")] if args.rrcs else None,
        "crtsh.start": args.crtsh_start,
        "crtsh.end": args.crtsh_end,
    }
    if args.window:
        start, end = args.window.split("/", 1)
        overrides["ris.window_start"], overrides["ris.window_end"] = start, end
    cfg = load_config(args.config, overrides)

    targets = ORDER if args.targets == ["all"] else args.targets
    unknown = [t for t in targets if t not in TARGETS]
    if unknown:
        log.error("unknown target(s): %s (choose from %s)", ", ".join(unknown), ", ".join(TARGETS))
        return 2

    rc = 0
    fetcher = Fetcher(cfg, force=args.force)
    try:
        for t in targets:
            fn = TARGETS[t]
            if fn is None:
                log.warning("%s: not implemented (stub), see README", t)
                continue
            t0 = time.perf_counter()
            log.info("== %s ==", t)
            try:
                if t == "ris":
                    fn(fetcher, cfg, yes=args.yes)
                elif t == "crtsh":
                    if args.finalize:
                        from .fetch.crtsh import finalize

                        finalize(cfg)
                    else:
                        fn(fetcher, cfg, months_limit=args.months)
                else:
                    fn(fetcher, cfg)
            except SystemExit as e:
                rc = int(e.code or 1)
                break
            except Exception:
                log.exception("%s failed", t)
                rc = 1
            log.info("== %s done in %.1fs ==", t, time.perf_counter() - t0)
    finally:
        fetcher.close()
    return rc
