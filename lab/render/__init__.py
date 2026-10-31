"""Render every node's configuration from one scenario file into lab/build/."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import yaml

from .clab import render_clab
from .dns import render_dns
from .frr import render_frr
from .hosts import render_hosts
from .rpki import render_rpki

SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        out[k] = _merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def load_scenario(path: Path) -> dict:
    """A scenario file, with `extends: <file>` (relative to it) deep-merged underneath."""
    sc = yaml.safe_load(path.read_text())
    if "extends" in sc:
        base = load_scenario(path.parent / sc.pop("extends"))
        sc = _merge(base, sc)
    return sc


def render_all(sc: dict, build: Path) -> None:
    if build.exists():
        shutil.rmtree(build)
    build.mkdir(parents=True)
    (build / "scenario.json").write_text(json.dumps(sc, indent=1) + "\n")
    render_frr(sc, build)
    render_rpki(sc, build)
    render_dns(sc, build)
    render_hosts(sc, build)
    render_clab(build)
