"""Target `tranco`: latest Tranco top list, via the official package with a direct-download fallback."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from .common import Fetcher, ManifestEntry, now_iso, sha256_file

log = logging.getLogger("hijackscan.fetch.tranco")


def list_page_url(list_id: str) -> str:
    return f"https://tranco-list.eu/list/{list_id}/"


def _symlink_latest(out_dir: Path, target_name: str) -> None:
    link = out_dir / "latest"
    if link.is_symlink() or link.exists():
        link.unlink()
    os.symlink(target_name, link)


def run(fetcher: Fetcher, cfg: dict[str, Any]) -> None:
    c = cfg["tranco"]
    out_dir = fetcher.data_dir / "tranco"
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        from tranco import Tranco

        t = Tranco(cache=True, cache_dir=str(out_dir))
        lst = t.list()
        path = out_dir / f"{lst.list_id}.csv"
        if fetcher.force or fetcher.manifest.get(path) is None:
            fetcher.manifest.record(ManifestEntry(
                target="tranco", url=f"https://tranco-list.eu/download_daily/{lst.list_id}",
                path=str(path), bytes=path.stat().st_size, sha256=sha256_file(path),
                fetched_at=now_iso(),
                params={"list_id": lst.list_id, "list_page": list_page_url(lst.list_id), "date": lst.date},
            ))
        _symlink_latest(out_dir, path.name)
        log.info("tranco list %s (%s), %d domains -> %s", lst.list_id, lst.date, len(lst.top()), path)
        return
    except Exception as e:  # package or API hiccup: fall back to the plain daily zip
        log.warning("tranco package failed (%s); falling back to %s", e, c["fallback_url"])

    list_id = fetcher.get_text(c["id_url"]).strip()
    path = out_dir / f"{list_id}.csv.zip"
    fetcher.download("tranco", c["fallback_url"], path,
                     {"list_id": list_id, "list_page": list_page_url(list_id)})
    _symlink_latest(out_dir, path.name)
    log.info("tranco list %s -> %s", list_id, path)
