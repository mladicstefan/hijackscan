"""Run-time defaults. Every value can be overridden by the matching CLI flag."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


def project_root() -> Path:
    """The directory holding pyproject.toml, searched upwards from the cwd; else the cwd.
    Lets `hijackscan` run from any subdirectory with the same data/ tree."""
    for d in (Path.cwd(), *Path.cwd().parents):
        if (d / "pyproject.toml").exists():
            return d
    return Path.cwd()


DATA_DIR = project_root() / "data"


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
    rpki_date: str = "latest"  # RIPE NCC RPKI archive day for ROAs: "latest" or YYYY-MM-DD (2026-08-28 = the replay)
    max_age_hours: float = 24 * 7  # re-use data/collected/<domain>.json younger than this
    data_dir: Path = DATA_DIR
    # Longest prefix the Internet routes (RFC 7454 filtering): a forged more-specific longer than this does not
    # propagate, so it is not counted as forgeable. The sealed lab raises v4 to 28 (RFC 5737 only has /24 blocks).
    routable_cap_v4: int = 24
    routable_cap_v6: int = 48
    # RIPEstat Data API template; the lab points it at its own RIS-shaped feed.
    ripestat_url: str = "https://stat.ripe.net/data/{call}/data.json"

    @property
    def collected_dir(self) -> Path:
        return self.data_dir / "collected"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def rpki_dir(self) -> Path:
        return self.data_dir / "rpki" / self.rpki_date

    @property
    def routable_caps(self) -> tuple[int, int]:
        return (self.routable_cap_v4, self.routable_cap_v6)


USER_AGENT = "hijackscan/0.1 (DNS SEC Hackathon 2026)"
SOURCEAPP = "hijackscan"
