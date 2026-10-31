"""ROAs for one archive day from the RIPE NCC RPKI archive, loaded into a prefix index.

Files: https://ftp.ripe.net/rpki/<ta>.tal/YYYY/MM/DD/roas.csv.xz (one per trust anchor), columns
URI, ASN, IP Prefix, Max Length, Not Before, Not After. Downloaded once into
data/rpki/<date>/<ta>/roas.csv.xz (sha256 checked against the sibling .sha256 file).
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import logging
import lzma
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

import httpx

from ..config import USER_AGENT

log = logging.getLogger(__name__)

TAS = ("afrinic", "apnic", "arin", "lacnic", "ripencc")
ARCHIVE = "https://ftp.ripe.net/rpki/{ta}.tal/{y}/{m}/{d}/roas.csv.xz"


@dataclass(frozen=True)
class Roa:
    prefix: str
    origin_asn: int
    max_length: int
    ta: str


def latest_archive_day(http: httpx.Client | None = None) -> str:
    """Newest day (today, yesterday, ...) for which the archive has a ripencc roas.csv.xz."""
    from datetime import UTC, datetime, timedelta

    own = http is None
    http = http or httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=30)
    try:
        for back in range(0, 7):
            d = datetime.now(UTC).date() - timedelta(days=back)
            url = ARCHIVE.format(ta="ripencc", y=d.year, m=f"{d.month:02d}", d=f"{d.day:02d}") + ".sha256"
            if http.head(url).status_code == 200:
                return d.isoformat()
    finally:
        if own:
            http.close()
    raise RuntimeError("no RPKI archive day found in the last week")


def ensure_archive(rpki_dir: Path, date: str) -> None:
    """Download the five roas.csv.xz files for `date` (YYYY-MM-DD) if missing; verify sha256."""
    y, m, d = date.split("-")
    with httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=120, follow_redirects=True) as http:
        for ta in TAS:
            dest = rpki_dir / ta / "roas.csv.xz"
            if dest.exists():
                continue
            url = ARCHIVE.format(ta=ta, y=y, m=m, d=d)
            log.info("rpki: fetching %s", url)
            r = http.get(url)
            r.raise_for_status()
            want = http.get(url + ".sha256").text.split()[0].lower()
            got = hashlib.sha256(r.content).hexdigest()
            if want != got:
                raise RuntimeError(f"sha256 mismatch for {url}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_suffix(".xz.part")
            tmp.write_bytes(r.content)
            tmp.replace(dest)


class RoaIndex:
    """All ROAs keyed by prefix; covering(prefix) walks the supernets (≤ 33 / 129 lookups)."""

    def __init__(self, rpki_dir: Path) -> None:
        self._by_prefix: dict[ipaddress.IPv4Network | ipaddress.IPv6Network, list[Roa]] = defaultdict(list)
        self.count = 0
        for ta_dir in sorted(rpki_dir.iterdir()):
            f = ta_dir / "roas.csv.xz"
            if not f.exists():
                continue
            with lzma.open(f, "rb") as xz:
                for row in csv.DictReader(io.TextIOWrapper(xz, encoding="utf-8")):
                    try:
                        net = ipaddress.ip_network(row["IP Prefix"].strip(), strict=False)
                        asn = int(row["ASN"].strip().upper().removeprefix("AS"))
                        ml = row["Max Length"].strip()
                        roa = Roa(str(net), asn, int(ml) if ml else net.prefixlen, ta_dir.name)
                    except (KeyError, ValueError):
                        continue
                    self._by_prefix[net].append(roa)
                    self.count += 1
        log.info("rpki: %d ROAs from %s", self.count, rpki_dir)

    def covering(self, prefix: str) -> list[dict]:
        net = ipaddress.ip_network(prefix, strict=False)
        out: list[Roa] = []
        for length in range(net.prefixlen, -1, -1):
            out.extend(self._by_prefix.get(net.supernet(new_prefix=length), ()))
        return [asdict(r) for r in sorted(set(out), key=lambda r: (r.prefix, r.origin_asn, r.ta))]
