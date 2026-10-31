"""Raw DNS answers through one resolver: records as rdata strings, the AD flag and the rcode.

Nothing here decides what an answer means. Every query sets the DO bit so a validating
resolver reports AD; the collector stores the flag, score.py interprets it.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

import dns.flags
import dns.message
import dns.nameserver
import dns.rcode
import dns.resolver

log = logging.getLogger(__name__)


@dataclass
class Answer:
    records: list[str] = field(default_factory=list)  # rdata as text, in answer order
    ad: bool = False
    rcode: str = "NOERROR"  # NOERROR | NXDOMAIN | SERVFAIL | TIMEOUT | ...

    def to_json(self) -> dict:
        return {"records": self.records, "ad": self.ad, "rcode": self.rcode}


class Dns:
    """One shared resolver with a global rate cap and an answer cache (thread-safe)."""

    def __init__(self, resolver: str, qps: float) -> None:
        host, _, port = resolver.partition(":")
        port = int(port or 853)
        self.r = dns.resolver.Resolver(configure=False)
        self.r.nameservers = [host] if port == 53 else [dns.nameserver.DoTNameserver(host, port)]
        self.r.lifetime = 10
        self.r.use_edns(0, dns.flags.DO, 1232)
        self.r.flags = dns.flags.RD | dns.flags.AD
        self.address = f"{host}:{port}" + ("" if port == 53 else " (DoT)")
        self._gap = 1 / qps
        self._next = 0.0
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, str], Answer] = {}

    def _throttle(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._next - now
            self._next = max(now, self._next) + self._gap
        if wait > 0:
            time.sleep(wait)

    def query(self, name: str, rtype: str) -> Answer:
        key = (name.lower().rstrip("."), rtype)
        if key in self._cache:
            return self._cache[key]
        self._throttle()
        try:
            ans = self.r.resolve(key[0], rtype, raise_on_no_answer=False)
            out = Answer(
                records=[r.to_text() for r in ans.rrset] if ans.rrset else [],
                ad=bool(ans.response.flags & dns.flags.AD),
                rcode=dns.rcode.to_text(ans.response.rcode()),
            )
        except dns.resolver.NXDOMAIN as e:
            out = Answer(rcode="NXDOMAIN", ad=_ad_from(e))
        except dns.resolver.NoNameservers as e:
            out = Answer(rcode="SERVFAIL" if "SERVFAIL" in str(e) else "REFUSED")
        except dns.resolver.LifetimeTimeout:
            out = Answer(rcode="TIMEOUT")
        except Exception as e:  # malformed answer etc.: keep the rcode-ish label, never raise
            log.debug("%s %s: %s", name, rtype, e)
            out = Answer(rcode=type(e).__name__.upper())
        self._cache[key] = out
        return out


def _ad_from(e: dns.resolver.NXDOMAIN) -> bool:
    try:
        resp = next(iter(e.kwargs["responses"].values()))
        return bool(resp.flags & dns.flags.AD)
    except Exception:
        return False
