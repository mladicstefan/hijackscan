"""ROAs for one archive day from the RIPE NCC RPKI archive, loaded into a prefix index.

Files: https://ftp.ripe.net/rpki/<ta>.tal/YYYY/MM/DD/roas.csv.xz (one per trust anchor), columns
URI, ASN, IP Prefix, Max Length, Not Before, Not After. Downloaded once into
data/rpki/<date>/<ta>/roas.csv.xz (sha256 checked against the sibling .sha256 file). The parsed index is
kept next to them in data/rpki/<date>/index.marshal, keyed by the sha256 of the CSVs, so a day is parsed once.
"""

from __future__ import annotations

import hashlib
import ipaddress
import lzma
import marshal
import re
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx

from .. import console
from ..config import USER_AGENT

TAS = ("afrinic", "apnic", "arin", "lacnic", "ripencc")
ARCHIVE = "https://ftp.ripe.net/rpki/{ta}.tal/{y}/{m}/{d}/roas.csv.xz"
DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
INDEX_FILE = "index.marshal"
INDEX_FORMAT = 1  # bump when the sidecar layout changes


def local_days(rpki_root: Path) -> list[str]:
    """Complete archive days under data/rpki/ (all five roas.csv.xz on disk), newest first."""
    if not rpki_root.is_dir():
        return []
    days = [d.name for d in rpki_root.iterdir() if DAY.fullmatch(d.name)]
    return sorted((d for d in days if all((rpki_root / d / ta / "roas.csv.xz").exists() for ta in TAS)), reverse=True)


def latest_archive_day(rpki_root: Path, max_age_days: int, http: httpx.Client | None = None) -> tuple[str, str]:
    """The day `--rpki-date latest` means, with the reason: the newest complete local day at most `max_age_days`
    old (no network); else the newest day the archive has, probed from yesterday (a day is published after it
    closes); else, when the archive is unreachable, the newest local day of any age."""
    today = datetime.now(UTC).date()
    local = local_days(rpki_root)
    days = (today - date.fromisoformat(local[0])).days if local else None
    age = f"{days} d old"
    if local and days <= max_age_days:
        return local[0], f"local archive, {age}, limit {max_age_days} d"
    own = http is None
    http = http or httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=5)
    try:
        for back in range(1, 8):
            d = today - timedelta(days=back)
            url = ARCHIVE.format(ta="ripencc", y=d.year, m=f"{d.month:02d}", d=f"{d.day:02d}") + ".sha256"
            if http.head(url).status_code == 200:
                return d.isoformat(), "RIPE archive, newest published day"
    except httpx.HTTPError as e:
        if local:
            console.note(f"RPKI archive unreachable ({type(e).__name__}): using local day {local[0]}, {age}")
            return local[0], f"local archive, {age}, RIPE archive unreachable"
        raise RuntimeError(f"RPKI archive unreachable and no local day under {rpki_root}") from e
    finally:
        if own:
            http.close()
    if local:
        console.note(f"no RPKI archive day published in the last week: using local day {local[0]}, {age}")
        return local[0], f"local archive, {age}, none published in the last week"
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


BUCKET_SHIFT = {4: 24, 6: 112}  # one bucket per /8 (v4) or /16 (v6)
FIELDS = ("prefix", "origin_asn", "max_length", "ta")
Roa = tuple[int, int, str]  # origin_asn, max_length, ta
Child = tuple[int, int, str]  # network address as int, prefix length, canonical prefix
Net = tuple[str, int, int, int]  # canonical prefix, version, network address as int, prefix length


def _net(raw: str) -> Net | None:
    """Parse one prefix. Canonical IPv4 text (what the archive writes) is decoded by hand, which is 4x faster
    than ipaddress; anything else, IPv6 included, goes through ipaddress and comes back in its canonical form."""
    addr, _, plen = raw.partition("/")
    if addr.count(".") == 3 and plen.isdecimal():
        try:
            a, b, c, d = (int(o) for o in addr.split("."))
            length = int(plen)
        except ValueError:
            pass
        else:
            n = (a << 24) | (b << 16) | (c << 8) | d
            canonical = f"{a}.{b}.{c}.{d}/{length}" == raw and n >> 32 == 0 and length <= 32
            if canonical and n & ((1 << (32 - length)) - 1) == 0:  # host bits clear, else ipaddress masks them
                return raw, 4, n, length
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None
    return str(net), net.version, int(net.network_address), net.prefixlen


def _digest(files: list[Path]) -> str:
    h = hashlib.sha256()
    for f in files:
        h.update(f.parent.name.encode())
        h.update(f.read_bytes())
    return h.hexdigest()


def _parse(files: list[Path]) -> tuple[dict[str, list[Roa]], dict[tuple[int, int], list[Child]], int]:
    by_prefix: dict[str, list[Roa]] = {}
    by_bucket: dict[tuple[int, int], list[Child]] = {}
    nets: dict[str, Net | None] = {}  # raw prefix text -> parsed once (903k distinct of 1M rows)
    count = 0
    for f in files:
        ta = f.parent.name
        with lzma.open(f, "rt", encoding="utf-8") as fh:
            cols = [c.strip() for c in next(fh, "").rstrip("\r\n").split(",")]
            try:
                i_asn, i_pfx, i_ml = cols.index("ASN"), cols.index("IP Prefix"), cols.index("Max Length")
            except ValueError:
                continue
            for line in fh:
                parts = line.rstrip("\r\n").split(",")
                try:
                    raw = parts[i_pfx].strip()
                    net = nets[raw] if raw in nets else nets.setdefault(raw, _net(raw))
                    if net is None:
                        continue
                    asn = int(parts[i_asn].strip().upper().removeprefix("AS"))
                    ml = parts[i_ml].strip()
                    maxlen = int(ml) if ml else net[3]
                except (IndexError, ValueError):
                    continue
                prefix = net[0]
                roas = by_prefix.get(prefix)
                if roas is None:
                    roas = by_prefix[prefix] = []
                    by_bucket.setdefault((net[1], net[2] >> BUCKET_SHIFT[net[1]]), []).append((net[2], net[3], prefix))
                roas.append((asn, maxlen, ta))
                count += 1
    return by_prefix, by_bucket, count


class RoaIndex:
    """All ROAs keyed by canonical prefix text; covering(prefix) walks the supernets (≤ 33 / 129 lookups),
    contained(prefix) scans the /8 or /16 bucket(s) the prefix lies in for strict subnets. ipaddress objects are
    built only for queried prefixes; the archive rows stay plain ints and strings so the index marshals."""

    def __init__(self, rpki_dir: Path) -> None:
        files = sorted(rpki_dir.glob("*/roas.csv.xz"))
        key = _digest(files)
        sidecar = rpki_dir / INDEX_FILE
        loaded = self._load(sidecar, key)
        if loaded is None:
            self._by_prefix, self._by_bucket, self.count = _parse(files)
            self._save(sidecar, key)
            how = f"parsed, index written to {INDEX_FILE}"
        else:
            self._by_prefix, self._by_bucket, self.count = loaded
            how = f"from {INDEX_FILE}"
        console.info("rpki", f"{self.count:,} ROAs from {rpki_dir} ({how})")

    @staticmethod
    def _load(sidecar: Path, key: str) -> tuple[dict, dict, int] | None:
        """The sidecar's index when it was built from exactly these CSVs; None when missing, stale or unreadable."""
        try:
            fmt, built_from, count, by_prefix, by_bucket = marshal.loads(sidecar.read_bytes())
        except (OSError, ValueError, EOFError, TypeError):
            return None
        if fmt != INDEX_FORMAT or built_from != key:
            return None
        return by_prefix, by_bucket, count

    def _save(self, sidecar: Path, key: str) -> None:
        tmp = sidecar.with_suffix(".marshal.part")
        try:
            tmp.write_bytes(marshal.dumps((INDEX_FORMAT, key, self.count, self._by_prefix, self._by_bucket)))
            tmp.replace(sidecar)
        except OSError as e:
            console.note(f"could not write {sidecar}: {e} (the archive will be parsed again next run)")

    @staticmethod
    def _rows(roas: list[tuple[str, int, int, str]]) -> list[dict]:
        """Distinct rows as dicts, ordered by prefix, origin ASN, trust anchor, max length."""
        return [dict(zip(FIELDS, r, strict=True)) for r in sorted(set(roas), key=lambda r: (r[0], r[1], r[3], r[2]))]

    def covering(self, prefix: str) -> list[dict]:
        """ROAs whose prefix is `prefix` or a supernet of it."""
        net = ipaddress.ip_network(prefix, strict=False)
        out: list[tuple[str, int, int, str]] = []
        for length in range(net.prefixlen, -1, -1):
            sup = str(net.supernet(new_prefix=length))
            out.extend((sup, *roa) for roa in self._by_prefix.get(sup, ()))
        return self._rows(out)

    def contained(self, prefix: str) -> list[dict]:
        """ROAs whose prefix is a strict subnet of `prefix` (a child ROA makes that more-specific RPKI-valid)."""
        net = ipaddress.ip_network(prefix, strict=False)
        shift = BUCKET_SHIFT[net.version]
        addr, plen = int(net.network_address), net.prefixlen
        first, last = addr >> shift, int(net.broadcast_address) >> shift
        host = net.max_prefixlen - plen
        out: list[tuple[str, int, int, str]] = []
        for key in range(first, last + 1):  # one key unless the prefix is shorter than the bucket
            for caddr, cplen, child in self._by_bucket.get((net.version, key), ()):
                if cplen > plen and (caddr >> host) == (addr >> host):
                    out.extend((child, *roa) for roa in self._by_prefix[child])
        return self._rows(out)
