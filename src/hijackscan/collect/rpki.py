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
import lzma
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

import httpx

from .. import console
from ..config import USER_AGENT

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
            console.info("rpki fetch", url)
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


Net = ipaddress.IPv4Network | ipaddress.IPv6Network
BUCKET_SHIFT = {4: 24, 6: 112}  # one bucket per /8 (v4) or /16 (v6)


def _bucket(net: Net) -> tuple[int, int]:
    return (net.version, int(net.network_address) >> BUCKET_SHIFT[net.version])


class RoaIndex:
    """All ROAs keyed by prefix; covering(prefix) walks the supernets (≤ 33 / 129 lookups),
    contained(prefix) scans the /8 or /16 bucket(s) the prefix lies in for strict subnets."""

    def __init__(self, rpki_dir: Path) -> None:
        self._by_prefix: dict[Net, list[Roa]] = defaultdict(list)
        self._by_bucket: dict[tuple[int, int], list[Net]] = defaultdict(list)  # distinct ROA prefixes per bucket
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
                    if net not in self._by_prefix:
                        self._by_bucket[_bucket(net)].append(net)
                    self._by_prefix[net].append(roa)
                    self.count += 1
        console.info("rpki", f"{self.count:,} ROAs from {rpki_dir}")

    @staticmethod
    def _rows(roas: list[Roa]) -> list[dict]:
        return [asdict(r) for r in sorted(set(roas), key=lambda r: (r.prefix, r.origin_asn, r.ta))]

    def covering(self, prefix: str) -> list[dict]:
        """ROAs whose prefix is `prefix` or a supernet of it."""
        net = ipaddress.ip_network(prefix, strict=False)
        out: list[Roa] = []
        for length in range(net.prefixlen, -1, -1):
            out.extend(self._by_prefix.get(net.supernet(new_prefix=length), ()))
        return self._rows(out)

    def contained(self, prefix: str) -> list[dict]:
        """ROAs whose prefix is a strict subnet of `prefix` (a child ROA makes that more-specific RPKI-valid)."""
        net = ipaddress.ip_network(prefix, strict=False)
        shift = BUCKET_SHIFT[net.version]
        first, last = int(net.network_address) >> shift, int(net.broadcast_address) >> shift
        out: list[Roa] = []
        for key in range(first, last + 1):  # one key unless the prefix is shorter than the bucket
            for child in self._by_bucket.get((net.version, key), ()):
                if child.prefixlen > net.prefixlen and child.subnet_of(net):
                    out.extend(self._by_prefix[child])
        return self._rows(out)
