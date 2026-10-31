"""Target `caida`: CAIDA AS relationships, serial-2, one monthly file."""

from __future__ import annotations

import logging
from datetime import date
from pathlib import Path
from typing import Any

from .common import Fetcher, resolve_date

log = logging.getLogger("hijackscan.fetch.caida")


def caida_filename(day: date) -> str:
    return f"{day:%Y%m}01.as-rel2.txt.bz2"


def caida_url(base_url: str, day: date) -> str:
    return base_url.rstrip("/") + "/" + caida_filename(day)


def run(fetcher: Fetcher, cfg: dict[str, Any]) -> None:
    c = cfg["caida"]
    day = resolve_date(c["date"])
    out = fetcher.data_dir / "caida"
    url = caida_url(c["base_url"], day)
    fetcher.download("caida", url, out / caida_filename(day), {"date": f"{day:%Y-%m-01}"})
    fetcher.download("caida", c["base_url"].rstrip("/") + "/README.txt", out / "README.txt")


def cached_file(cfg: dict[str, Any]) -> Path:
    return Path(cfg["data_dir"]) / "caida" / caida_filename(resolve_date(cfg["caida"]["date"]))
