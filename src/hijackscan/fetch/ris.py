"""Target `ris`: RIPE RIS MRT updates (5-min) and the last bview before the window, per collector."""

from __future__ import annotations

import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .common import ClientError, Fetcher, parse_hrefs, resolve_datetime, write_json_atomic

log = logging.getLogger("hijackscan.fetch.ris")

UPDATE_STEP = timedelta(minutes=5)
BVIEW_HOURS = (0, 8, 16)


@dataclass(frozen=True)
class RisFile:
    rrc: str
    kind: str  # "updates" | "bview"
    ts: datetime

    @property
    def name(self) -> str:
        return f"{self.kind}.{self.ts:%Y%m%d}.{self.ts:%H%M}.gz"

    def url(self, base_url: str) -> str:
        return f"{base_url.rstrip('/')}/rrc{self.rrc}/{self.ts:%Y.%m}/{self.name}"


def month_index_url(base_url: str, rrc: str, ts: datetime) -> str:
    return f"{base_url.rstrip('/')}/rrc{rrc}/{ts:%Y.%m}/"


def parse_window(spec: str) -> tuple[datetime, datetime]:
    """'2026-08-28T10:00Z/2026-08-28T10:30Z' -> (start, end), both UTC-aware."""
    a, b = spec.split("/", 1)
    start, end = resolve_datetime(a), resolve_datetime(b)
    if end <= start:
        raise ValueError(f"window end must be after start: {spec}")
    return start, end


def update_times(start: datetime, end: datetime) -> list[datetime]:
    """5-minute update file timestamps in [start, end), aligned down to the 5-minute grid."""
    t = start.replace(second=0, microsecond=0)
    t -= timedelta(minutes=t.minute % 5)
    out = []
    while t < end:
        out.append(t)
        t += UPDATE_STEP
    return out


def last_bview_before(start: datetime) -> datetime:
    """Most recent 00:00/08:00/16:00 dump at or before `start`."""
    t = start.replace(minute=0, second=0, microsecond=0)
    while t.hour not in BVIEW_HOURS:
        t -= timedelta(hours=1)
    return t


def plan(rrcs: list[str], start: datetime, end: datetime) -> list[RisFile]:
    files: list[RisFile] = []
    bv = last_bview_before(start)
    for rrc in rrcs:
        files.append(RisFile(rrc, "bview", bv))
        files.extend(RisFile(rrc, "updates", t) for t in update_times(start, end))
    return files


def _active(fetcher: Fetcher, base_url: str, rrc: str, months: list[datetime]) -> dict[str, set[str]]:
    """Fetch each month index for a collector; returns {month: set(filenames)}; {} if 404."""
    listing: dict[str, set[str]] = {}
    for m in months:
        url = month_index_url(base_url, rrc, m)
        try:
            listing[f"{m:%Y.%m}"] = set(parse_hrefs(fetcher.get_text(url)))
        except ClientError as e:
            log.warning("rrc%s: %s", rrc, e)
    return listing


def run(fetcher: Fetcher, cfg: dict[str, Any], *, yes: bool = False) -> None:
    c = cfg["ris"]
    base = c["base_url"]
    start, end = resolve_datetime(c["window_start"]), resolve_datetime(c["window_end"])
    rrcs = [str(r).zfill(2) for r in c["rrcs"]]
    bv = last_bview_before(start)
    months = sorted({bv.replace(day=1), start.replace(day=1), end.replace(day=1)})

    status: dict[str, Any] = {"window": [start.isoformat(), end.isoformat()], "rrcs": {}}
    wanted: list[RisFile] = []
    for rrc in rrcs:
        listing = _active(fetcher, base, rrc, months)
        if not listing:
            status["rrcs"][rrc] = {"status": "inactive"}
            continue
        files = plan([rrc], start, end)
        present = [f for f in files if f.name in listing.get(f"{f.ts:%Y.%m}", set())]
        missing = [f.name for f in files if f not in present]
        status["rrcs"][rrc] = {"status": "ok", "planned": len(files), "missing": missing}
        wanted.extend(present)

    # Size estimate: one HEAD per collector for a sample updates file + the bview.
    est = 0
    for rrc in rrcs:
        if status["rrcs"][rrc]["status"] != "ok":
            continue
        ups = [f for f in wanted if f.rrc == rrc and f.kind == "updates"]
        bvs = [f for f in wanted if f.rrc == rrc and f.kind == "bview"]
        if ups:
            est += (fetcher.content_length(ups[len(ups) // 2].url(base)) or 0) * len(ups)
        for f in bvs:
            est += fetcher.content_length(f.url(base)) or 0
    log.info("ris: %d files planned across %d collectors, estimated %.2f GB", len(wanted),
             sum(1 for v in status["rrcs"].values() if v["status"] == "ok"), est / 1e9)
    status["planned_files"] = len(wanted)
    status["estimated_bytes"] = est
    write_json_atomic(fetcher.data_dir / "ris" / "STATUS.json", status)
    if est > int(c.get("confirm_above_bytes", 2_000_000_000)) and not yes:
        log.error("estimated %.2f GB exceeds the confirmation threshold; re-run with --yes", est / 1e9)
        sys.exit(3)

    def dl(f: RisFile) -> None:
        fetcher.download("ris", f.url(base), fetcher.data_dir / "ris" / f"rrc{f.rrc}" / f.name,
                         {"rrc": f.rrc, "kind": f.kind, "timestamp": f.ts.astimezone(UTC).isoformat()})

    errors = 0
    with ThreadPoolExecutor(max_workers=int(cfg.get("max_concurrency_per_host", 4))) as pool:
        for f, fut in [(f, pool.submit(dl, f)) for f in wanted]:
            try:
                fut.result()
            except Exception as e:
                errors += 1
                log.error("%s: %s", f.name, e)
    log.info("ris: done, %d errors", errors)
