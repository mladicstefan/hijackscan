"""RIPEstat Data API, read-only, ≤ N concurrent, every response cached as a file under data/cache/."""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path

import httpx

from ..config import SOURCEAPP, USER_AGENT

log = logging.getLogger(__name__)
URL = "https://stat.ripe.net/data/{call}/data.json"


class RipeStat:
    def __init__(self, cache_dir: Path, concurrency: int) -> None:
        self.cache_dir = cache_dir / "ripestat"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.http = httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=30)
        self._sem = threading.Semaphore(concurrency)

    def call(self, call: str, **params: str) -> dict:
        key = call + "_" + "_".join(f"{k}={v}" for k, v in sorted(params.items()))
        path = self.cache_dir / (key.replace("/", "_") + ".json")
        if path.exists():
            return json.loads(path.read_text())["data"]
        last: Exception | None = None
        for attempt in range(4):
            try:
                with self._sem:
                    r = self.http.get(URL.format(call=call), params={**params, "sourceapp": SOURCEAPP})
                r.raise_for_status()
                data = r.json()
                tmp = path.with_name(f"{path.name}.{threading.get_ident()}.part")
                tmp.write_text(json.dumps(data))
                tmp.replace(path)
                return data["data"]
            except (httpx.HTTPError, KeyError, ValueError) as e:
                last = e
                log.warning("ripestat %s %s: %s (attempt %d)", call, params, e, attempt + 1)
                time.sleep(2**attempt)
        raise RuntimeError(f"ripestat {call} {params}: {last}")

    def network_info(self, ip: str) -> tuple[str | None, list[int]]:
        """Most specific announced prefix covering ip, and its origin ASNs."""
        d = self.call("network-info", resource=ip)
        return d.get("prefix") or None, [int(a) for a in d.get("asns", [])]

    def rpki_state(self, asn: int, prefix: str) -> str | None:
        """RIPEstat's own verdict for (origin, prefix): valid | invalid | unknown (as reported)."""
        return self.call("rpki-validation", resource=str(asn), prefix=prefix).get("status")

    def routing_status(self, prefix: str) -> dict:
        """Announced more-specifics of a prefix and how many RIS peers see it."""
        d = self.call("routing-status", resource=prefix)
        vis = d.get("visibility", {}).get("v6" if ":" in prefix else "v4", {})
        return {
            "more_specifics": [f"{m['prefix']} AS{m['origin']}" for m in d.get("more_specifics", [])],
            "ris_peers_seeing": vis.get("ris_peers_seeing"),
            "ris_peers_total": vis.get("total_ris_peers"),
        }

    def as_overview(self, asn: int) -> dict:
        d = self.call("as-overview", resource=f"AS{asn}")
        return {"name": d.get("holder"), "announced": d.get("announced")}
