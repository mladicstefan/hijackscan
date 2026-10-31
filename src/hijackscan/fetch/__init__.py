"""Dataset fetchers. Each target module exposes run(fetcher, cfg, **opts)."""

from __future__ import annotations

from . import bgpy_smoke, caida, crtsh, ris, rpki, tranco

TARGETS = {
    "caida": caida.run,
    "rpki": rpki.run,
    "ris": ris.run,
    "ris-parquet": None,  # TODO: RIS as Parquet, see README
    "tranco": tranco.run,
    "bgpy-smoke": bgpy_smoke.run,
    "crtsh": crtsh.run,
}

__all__ = ["TARGETS"]
