"""Target `bgpy-smoke`: build the CAIDA graph in BGPy 13.0.13 and time a tiny simulation."""

from __future__ import annotations

import bz2
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .common import ManifestEntry, now_iso, resolve_date, sha256_file, write_json_atomic

log = logging.getLogger("hijackscan.fetch.bgpy_smoke")


def bgpy_cache_name(day: datetime) -> str:
    """BGPy's own cache file name for a CAIDA serial-2 month (CAIDAASGraphCollector.cache_path)."""
    return f"CAIDAASGraphCollector_{day:%Y.%m.%d}.txt"


def seed_cache_from_caida(bz2_path: Path, cache_dir: Path, day: datetime) -> Path | None:
    """Unpack the serial-2 file we already fetched into BGPy's cache so it does not download again."""
    cache = cache_dir / bgpy_cache_name(day)
    if cache.exists() or not bz2_path.exists():
        return cache if cache.exists() else None
    cache_dir.mkdir(parents=True, exist_ok=True)
    tmp = cache.with_name(cache.name + ".part")
    with bz2.open(bz2_path, "rb") as src, tmp.open("w") as dst:
        for line in src:
            dst.write(line.decode().strip() + "\n")
    os.replace(tmp, cache)
    log.info("seeded BGPy cache %s from %s", cache, bz2_path)
    return cache


def smoke(cfg: dict[str, Any]) -> dict[str, Any]:
    """Run the smoke simulation; returns {wall_seconds, trials, cores, ...}."""
    from frozendict import frozendict

    c = cfg["bgpy_smoke"]
    data_dir = Path(cfg["data_dir"])
    day = datetime.combine(resolve_date(c["dl_time"]).replace(day=1), datetime.min.time())
    cache_dir = data_dir / "bgpy_cache"
    cores = int(c.get("parse_cpus") or os.cpu_count() or 1)
    trials = int(c["num_trials"])

    from .caida import cached_file

    seed_cache_from_caida(cached_file(cfg), cache_dir, day)

    # Lazy: importing bgpy.simulation_framework parses sys.argv (--trials etc.).
    from bgpy.as_graphs import CAIDAASGraphCollector, CAIDAASGraphConstructor
    from bgpy.simulation_engine import ROV
    from bgpy.simulation_framework import ScenarioConfig, Simulation, SubprefixHijack

    t0 = time.perf_counter()
    collector = CAIDAASGraphCollector(dl_time=day, cache_dir=cache_dir)
    tsv = collector.run()
    t_graph = time.perf_counter() - t0

    sim = Simulation(
        percent_adoptions=tuple(float(p) for p in c["percent_adoptions"]),
        scenario_configs=(ScenarioConfig(ScenarioCls=SubprefixHijack, AdoptPolicyCls=ROV),),
        num_trials=trials,
        parse_cpus=cores,
        output_dir=data_dir / "bgpy_smoke",
        ASGraphConstructorCls=CAIDAASGraphConstructor,
        as_graph_constructor_kwargs=frozendict(
            as_graph_collector_kwargs=frozendict(dl_time=day, cache_dir=cache_dir),
            as_graph_kwargs=frozendict(store_customer_cone_size=True, store_customer_cone_asns=False,
                                       store_provider_cone_size=False, store_provider_cone_asns=False),
            tsv_path=None,
        ),
    )
    t1 = time.perf_counter()
    sim.run()
    wall = time.perf_counter() - t1
    return {
        "wall_seconds": round(wall, 2),
        "graph_seconds": round(t_graph, 2),
        "trials": trials,
        "cores": cores,
        "caida_file": str(tsv),
        "caida_month": f"{day:%Y-%m}",
        "bgpy_version": "13.0.13",
        "output_dir": str(data_dir / "bgpy_smoke"),
        "ran_at": now_iso(),
    }


def run(fetcher: Any, cfg: dict[str, Any]) -> None:
    res = smoke(cfg)
    out = Path(cfg["data_dir"]) / "bgpy_smoke" / "smoke.json"
    write_json_atomic(out, res)
    tsv = Path(res["caida_file"])
    fetcher.manifest.record(ManifestEntry(
        target="bgpy-smoke", url="(unpacked from caida target)", path=str(tsv),
        bytes=tsv.stat().st_size, sha256=sha256_file(tsv), fetched_at=now_iso(),
        params={"caida_month": res["caida_month"], "bgpy_version": res["bgpy_version"]},
    ))
    log.info("bgpy smoke: %.1fs wall, %d trials, %d cores (graph build %.1fs)",
             res["wall_seconds"], res["trials"], res["cores"], res["graph_seconds"])
