"""Target `crtsh`: Certificate Transparency names under .rs / .срб from crt.sh's PostgreSQL mirror.

crt.sh is a shared courtesy service: exactly one connection at a time, one calendar month per
query, every result cached on disk, never parallel. The server sits behind pgbouncer in statement
pooling mode: no transactions, no `options=` startup parameter, and a `SET` only lives for the
statement it is sent with — so the timeout is prepended to the query itself via the simple-query
protocol (psycopg ClientCursor). Measured 2026-10-31: even so, `guest` statements are killed at
~60 s and the FTS plan scans every notAfter partition, so a month of .rs did not finish. DEFERRED:
re-run off-peak with shorter chunks, or replace with an openly published zone file (.se-style).
"""

from __future__ import annotations

import csv
import logging
import socket
import threading
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from .common import now_iso, resolve_date, write_json_atomic

log = logging.getLogger("hijackscan.fetch.crtsh")

# Guarantees "exactly one connection to crt.sh, ever" inside this process.
_CONN_LOCK = threading.Lock()

QUERY = """
SELECT cai.NAME_VALUE, x509_notBefore(cai.CERTIFICATE) AS not_before,
       cai.ISSUER_CA_ID, cai.CERTIFICATE_ID
FROM certificate_and_identities cai
WHERE plainto_tsquery('certwatch', %(term)s) @@ identities(cai.CERTIFICATE)
  AND cai.NAME_VALUE ILIKE %(suffix)s
  AND cai.NAME_TYPE IN ('san:dNSName', 'commonName')
  AND x509_notBefore(cai.CERTIFICATE) >= %(start)s
  AND x509_notBefore(cai.CERTIFICATE) <  %(end)s
"""

COLUMNS = ["name_value", "not_before", "issuer_ca_id", "cert_id"]


@dataclass(frozen=True)
class Chunk:
    start: date
    end: date  # exclusive

    def halves(self) -> tuple[Chunk, Chunk]:
        mid = self.start + (self.end - self.start) / 2
        mid = date(mid.year, mid.month, mid.day)
        return Chunk(self.start, mid), Chunk(mid, self.end)

    @property
    def days(self) -> int:
        return (self.end - self.start).days


def months(start: date, end: date) -> list[Chunk]:
    """Calendar months covering [start, end); the first/last are clipped to the range."""
    out: list[Chunk] = []
    cur = start
    while cur < end:
        nxt = date(cur.year + (cur.month == 12), cur.month % 12 + 1, 1)
        out.append(Chunk(cur, min(nxt, end)))
        cur = nxt
    return out


def month_key(chunk: Chunk) -> str:
    return f"{chunk.start:%Y-%m}"


def csv_path(data_dir: Path, tld: str, chunk: Chunk) -> Path:
    return data_dir / "crtsh" / "raw" / tld / f"{month_key(chunk)}.csv"


def _ipv4(host: str) -> str | None:
    """crt.sh's AAAA record times out from some networks; pin the A record when we can."""
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except OSError:
        return None


def _connect(c: dict[str, Any]) -> Any:
    import psycopg

    kw: dict[str, Any] = dict(host=c["host"], port=int(c["port"]), user=c["user"], dbname=c["dbname"],
                              sslmode="disable", connect_timeout=30, autocommit=True,
                              cursor_factory=psycopg.ClientCursor)
    ip = _ipv4(c["host"])
    if ip:
        kw["hostaddr"] = ip
    return psycopg.connect(**kw)


def _query(c: dict[str, Any], tld: str, chunk: Chunk) -> list[tuple[Any, ...]]:
    """One query on a fresh connection. ClientCursor sends a simple-query message, which lets the
    SET and the SELECT travel together (the only way a SET survives statement pooling)."""
    with _CONN_LOCK, _connect(c) as conn, conn.cursor() as cur:
        sql = f"SET statement_timeout = '{c['statement_timeout']}'; " + QUERY
        cur.execute(sql, {"term": tld, "suffix": f"%.{tld}",
                          "start": chunk.start.isoformat(), "end": chunk.end.isoformat()})
        cur.nextset()
        return cur.fetchall()


def _is_timeout(e: Exception) -> bool:
    return "canceling statement" in str(e) or "statement timeout" in str(e)


def fetch_month(
    c: dict[str, Any], tld: str, month: Chunk, *, chunk_days: int
) -> tuple[list[tuple[Any, ...]], dict[str, Any]]:
    """Fetch a month, splitting into shorter chunks on timeout (down to min_chunk_days)."""
    rows: list[tuple[Any, ...]] = []
    info: dict[str, Any] = {"chunks": [], "retries": 0}
    todo = [month] if chunk_days >= month.days else _split_to(month, chunk_days)
    slowest = 0.0
    while todo:
        chunk = todo.pop(0)
        for attempt in range(1, int(c["retries"]) + 1):
            t0 = time.perf_counter()
            try:
                got = _query(c, tld, chunk)
                secs = time.perf_counter() - t0
                rows.extend(got)
                info["chunks"].append({"start": chunk.start.isoformat(), "end": chunk.end.isoformat(),
                                       "rows": len(got), "seconds": round(secs, 1)})
                slowest = max(slowest, secs)
                log.info("crt.sh %s %s..%s: %d rows in %.1fs", tld, chunk.start, chunk.end, len(got), secs)
                break
            except Exception as e:
                secs = time.perf_counter() - t0
                if _is_timeout(e) and chunk.days > int(c["min_chunk_days"]):
                    log.warning("crt.sh %s %s..%s timed out after %.0fs; splitting", tld, chunk.start, chunk.end, secs)
                    todo[0:0] = list(chunk.halves())
                    break
                info["retries"] += 1
                wait = min(60, 5 * 2 ** (attempt - 1))
                log.warning("crt.sh %s %s..%s attempt %d failed (%s); sleeping %ds", tld, chunk.start, chunk.end,
                            attempt, str(e).strip().splitlines()[0], wait)
                if attempt == int(c["retries"]):
                    raise
                time.sleep(wait)
    info["slowest_chunk_seconds"] = round(slowest, 1)
    return rows, info


def _split_to(chunk: Chunk, days: int) -> list[Chunk]:
    parts = [chunk]
    while max(p.days for p in parts) > days:
        parts = [h for p in parts for h in (p.halves() if p.days > days else (p,))]
    return parts


def run(fetcher: Any, cfg: dict[str, Any], *, months_limit: int | None = None) -> None:
    c = cfg["crtsh"]
    data_dir = Path(cfg["data_dir"])
    start, end = resolve_date(c["start"]), resolve_date(c["end"])
    status_path = data_dir / "crtsh" / "STATUS.json"
    status: dict[str, Any] = {}
    if status_path.exists():
        import json

        status = json.loads(status_path.read_text())
    plan = months(start, end)
    if months_limit:
        plan = plan[-months_limit:]
    chunk_days = 10**6  # whole months until something is slow
    for tld in c["tlds"]:
        for month in plan:
            key = f"{tld}/{month_key(month)}"
            out = csv_path(data_dir, tld, month)
            if out.exists() and not fetcher.force and status.get(key, {}).get("status") == "ok":
                log.debug("skip %s", out)
                continue
            try:
                rows, info = fetch_month(c, tld, month, chunk_days=chunk_days)
            except Exception as e:
                status[key] = {"status": "failed", "error": str(e).strip().splitlines()[0], "at": now_iso()}
                write_json_atomic(status_path, status)
                log.error("crt.sh %s failed after retries; continuing", key)
                continue
            if info["slowest_chunk_seconds"] > float(c["split_threshold_seconds"]):
                chunk_days = max(int(c["min_chunk_days"]), min(chunk_days, month.days) // 2)
                log.warning("slow chunk (%.0fs > %ss): later months use %d-day chunks",
                            info["slowest_chunk_seconds"], c["split_threshold_seconds"], chunk_days)
            out.parent.mkdir(parents=True, exist_ok=True)
            tmp = out.with_name(out.name + ".part")
            with tmp.open("w", newline="") as f:
                w = csv.writer(f)
                w.writerow(COLUMNS)
                for r in rows:
                    w.writerow([r[0], r[1].isoformat() if hasattr(r[1], "isoformat") else r[1], r[2], r[3]])
            tmp.replace(out)
            status[key] = {"status": "ok", "rows": len(rows), "at": now_iso(), **info}
            write_json_atomic(status_path, status)
    failed = [k for k, v in status.items() if v["status"] != "ok"]
    log.info("crt.sh: %d months ok, %d failed (%s)", len(status) - len(failed), len(failed), status_path)


def finalize(cfg: dict[str, Any]) -> None:
    """names.txt, registered_domains.txt and registered_domains.counts.csv from the raw CSVs. No network."""
    from publicsuffix2 import get_sld

    data_dir = Path(cfg["data_dir"]) / "crtsh"
    names: dict[str, set[int]] = {}
    for p in sorted((data_dir / "raw").glob("*/*.csv")):
        with p.open(newline="") as f:
            for row in csv.DictReader(f):
                n = row["name_value"].strip().lower()
                if n.startswith("*."):
                    n = n[2:]
                if not n or " " in n:
                    continue
                names.setdefault(n, set()).add(int(row["cert_id"]))
    registered: dict[str, dict[str, Any]] = {}
    for n, certs in names.items():
        sld = get_sld(n, strict=True)
        if not sld:
            continue
        r = registered.setdefault(sld, {"names": 0, "certs": set()})
        r["names"] += 1
        r["certs"] |= certs
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "names.txt").write_text("".join(f"{n}\n" for n in sorted(names)))
    (data_dir / "registered_domains.txt").write_text("".join(f"{d}\n" for d in sorted(registered)))
    with (data_dir / "registered_domains.counts.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["registered_domain", "names", "certs"])
        for d in sorted(registered):
            w.writerow([d, registered[d]["names"], len(registered[d]["certs"])])
    log.info("crt.sh finalize: %d names, %d registered domains", len(names), len(registered))
