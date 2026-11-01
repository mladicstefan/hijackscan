"""`hijackscan list`: filter and sort collected domains by risk. Reads data/collected only, no network.

hijackscan list --severity High,Critical
hijackscan list data/samples/dev100.txt --label ns-partial --details
hijackscan list --finding NO_CAA,UNSIGNED --min-score 4 --json
"""

from __future__ import annotations

import argparse
import json

from rich.markup import escape

from .. import console
from ..collect import read_domains
from ..config import Config
from ..risk import SEVERITIES, Risk, assess
from ..score import score
from . import risk_view


def _csv(x: str) -> set[str]:
    return {v.strip() for v in x.split(",") if v.strip()}


def load(cfg: Config, target: str | None) -> list[Risk]:
    if target:
        paths = [cfg.collected_dir / f"{d}.json" for d in read_domains(target)]
    else:
        paths = sorted(cfg.collected_dir.glob("*.json"))
    out = []
    for p in paths:
        if p.exists():
            rec = json.loads(p.read_text(encoding="utf-8"))
            out.append(assess(rec, score(rec, caps=cfg.routable_caps)))
    return out


def listing(cfg: Config, a: argparse.Namespace) -> int:
    risks = load(cfg, a.target)
    sev = {s.lower() for s in _csv(a.severity)}
    bad = sev - {s.lower() for s in SEVERITIES}
    if bad:
        raise SystemExit(f"unknown severity: {', '.join(sorted(bad))} (use {', '.join(SEVERITIES)})")
    labels, finds = _csv(a.label), _csv(a.finding)
    hits = [
        r
        for r in risks
        if (not sev or r.severity.lower() in sev)
        and (a.min_score is None or (r.score is not None and r.score >= a.min_score))
        and (not labels or r.label in labels)
        and finds <= {f.id for f in r.findings}
    ]
    key = {
        "score": lambda r: (-(r.score if r.score is not None else -1), r.domain),
        "domain": lambda r: r.domain,
        "label": lambda r: (r.label, -(r.score or 0), r.domain),
    }[a.sort]
    hits.sort(key=key)

    if a.json:
        for r in hits:
            print(json.dumps(r.to_json() if a.details else r.summary(), ensure_ascii=False))
        return 0
    if a.details:
        for r in hits:
            console.show(risk_view.summary_text(r) + risk_view.details_text(r))
            console.out.print("\n" + "─" * 100 + "\n", style="dim")
    else:
        console.out.print(f"{'SCORE':>5}  {'SEVERITY':<8}  {'LABEL':<15} {'DOMAIN':<24} FIX FIRST", style="heading")
        for r in hits:
            s = "    -" if r.score is None else f"{r.score:5.1f}"
            fix = f"{r.fix.owner}: {r.fix.action} → {r.fix.score_after:.1f}" if r.fix else "-"
            console.out.print(
                f"{console.sev(r.severity, f'{s}  {r.severity:<8}')}  [class]{escape(f'{r.label:<15}')}[/] "
                f"[name]{escape(f'{r.domain:<24}')}[/] [dim]{escape(fix)}[/]",
                soft_wrap=True,
            )
    hint = "" if a.details else "   (--details for the calculation and evidence, --json for machine output)"
    console.out.print(f"\n{len(hits)} of {len(risks)} collected domains match[dim]{hint}[/]", soft_wrap=True)
    return 0
