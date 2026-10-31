"""Run-time defaults. Every value can be overridden by the matching CLI flag."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path("data")


@dataclass(frozen=True)
class Config:
    # Validating resolver as host[:port]; port 853 means DNS-over-TLS, 53 plain DNS.
    # Our local Unbound would be "127.0.0.1:53"; Quad9 over DoT is the default because plain
    # port-53 to public resolvers is blocked on the hackathon network and the systemd stub does
    # not validate. scripts/check_resolver.py proves whichever one is configured validates.
    resolver: str = "9.9.9.9:853"
    dns_qps: float = 50.0
    workers: int = 8
    ripestat_concurrency: int = 8  # the proposal's limit
    rpki_date: str = "2026-08-28"  # RIPE NCC RPKI archive day used for ROAs
    max_age_hours: float = 24 * 7  # re-use data/collected/<domain>.json younger than this
    data_dir: Path = DATA_DIR

    @property
    def collected_dir(self) -> Path:
        return self.data_dir / "collected"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def rpki_dir(self) -> Path:
        return self.data_dir / "rpki" / self.rpki_date


USER_AGENT = "hijackscan/0.1 (DNS SEC Hackathon 2026)"
SOURCEAPP = "hijackscan"
