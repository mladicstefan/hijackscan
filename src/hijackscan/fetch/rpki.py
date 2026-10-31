"""Target `rpki`: RIPE NCC RPKI archive (roas.csv.xz, output.json.xz, routinator.log + .sha256)."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path
from typing import Any

from .common import ClientError, Fetcher, parse_hrefs, resolve_date, sha256_file, write_json_atomic

log = logging.getLogger("hijackscan.fetch.rpki")


def rpki_dir_url(base_url: str, ta: str, day: date) -> str:
    return f"{base_url.rstrip('/')}/{ta}.tal/{day:%Y}/{day:%m}/{day:%d}/"


def rpki_dates(values: list[Any]) -> list[date]:
    seen: list[date] = []
    for v in values:
        d = resolve_date(v)
        if d not in seen:
            seen.append(d)
    return seen


def _listing(fetcher: Fetcher, cfg_rpki: dict[str, Any], ta: str, day: date) -> tuple[str, list[str]] | None:
    """Return (dir_url, filenames) from the primary or fallback tree, None if both 404."""
    for base in (cfg_rpki["base_url"], cfg_rpki.get("fallback_base_url")):
        if not base:
            continue
        url = rpki_dir_url(base, ta, day)
        try:
            return url, parse_hrefs(fetcher.get_text(url))
        except ClientError as e:
            log.warning("%s: %s", url, e)
    return None


def _fetch_one(fetcher: Fetcher, dir_url: str, listed: list[str], ta: str, day: date, fname: str) -> dict[str, Any]:
    out_dir = fetcher.data_dir / "rpki" / day.isoformat() / ta
    params = {"ta": ta, "date": day.isoformat()}
    if fname not in listed:
        return {"status": "missing"}
    fetcher.download("rpki", dir_url + fname, out_dir / fname, params)
    result: dict[str, Any] = {"status": "ok"}
    sums = fname + ".sha256"
    if sums in listed:
        fetcher.download("rpki", dir_url + sums, out_dir / sums, params)
        expected = (out_dir / sums).read_text().split()[0].lower()
        actual = sha256_file(out_dir / fname)
        if expected != actual:
            log.error("sha256 mismatch for %s: expected %s got %s", out_dir / fname, expected, actual)
            (out_dir / fname).rename(out_dir / (fname + ".corrupt"))
            result = {"status": "sha256-mismatch"}
        else:
            result["sha256_verified"] = True
    else:
        result["sha256_verified"] = False
    return result


def run(fetcher: Fetcher, cfg: dict[str, Any]) -> None:
    c = cfg["rpki"]
    days = rpki_dates(c["dates"])
    status_path = fetcher.data_dir / "rpki" / "STATUS.json"
    status: dict[str, Any] = {}
    jobs = []
    with ThreadPoolExecutor(max_workers=int(cfg.get("max_concurrency_per_host", 4))) as pool:
        for day in days:
            for ta in c["tas"]:
                key = f"{day.isoformat()}/{ta}"
                lst = _listing(fetcher, c, ta, day)
                if lst is None:
                    log.warning("no archive directory for %s (both trees); skipped", key)
                    status[key] = {"status": "missing-day"}
                    continue
                dir_url, listed = lst
                status[key] = {"status": "ok", "dir_url": dir_url, "files": {}}
                for fname in c["files"]:
                    jobs.append((key, fname, pool.submit(_fetch_one, fetcher, dir_url, listed, ta, day, fname)))
        for key, fname, fut in jobs:
            try:
                status[key]["files"][fname] = fut.result()
            except Exception as e:  # one bad file must not kill the run
                log.error("%s/%s failed: %s", key, fname, e)
                status[key]["files"][fname] = {"status": "error", "error": str(e)}
    write_json_atomic(status_path, status)
    missing = [k for k, v in status.items() if v["status"] != "ok"]
    log.info("rpki: %d TA/days fetched, %d missing (%s)", len(status) - len(missing), len(missing), status_path)
    for k in missing:
        log.info("  missing: %s", k)


def output_dir(cfg: dict[str, Any]) -> Path:
    return Path(cfg["data_dir"]) / "rpki"
