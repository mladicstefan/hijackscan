"""Risk rendering shared by `hijackscan <domain>`, `hijackscan list` and the zone report.

Two levels: the summary (score, severity, one sentence, what to fix) is always shown; the details
(calculation, every path, finding, fix, CVSS vector and ATT&CK technique) only on request. The numbered
references stay in the JSON (`Risk.details()`) but are not printed: they read the same for every domain.
"""

from __future__ import annotations

from ..risk import COMPLEXITY_STEP, Fix, Risk
from . import html


def _fix_line(f: Fix) -> str:
    return f"{f.owner}: {f.action} → {f.score_after:.1f} {f.severity_after}"


def summary_text(r: Risk) -> list[str]:
    score = "  -" if r.score is None else f"{r.score:4.1f}"
    out = [f"{r.domain}  {r.severity.upper()} {score}  {r.label}", f"  {r.headline}"]
    if r.fix:
        out.append(f"  fix first   {_fix_line(r.fix)}")
    if r.full_fix:
        out.append(f"  to close    {_fix_line(r.full_fix)}")
    return out


def details_text(r: Risk) -> list[str]:
    prm = r.params
    out = ["", "RISK CALCULATION   (design/formula.md)"]
    b = r.best
    if b:
        out += [
            f"  driving path   {b.path} → {b.target}",
            f"  p              {b.p:.2f}   {b.p_note}",
            f"  P per attempt  {b.p_attempt:.3f}   = p × P(≥ {prm.remote_perspectives - prm.allowed_non_corroborations} "
            f"of {prm.remote_perspectives} remote perspectives fooled)   [BR 3.2.2.9]",
            f"  likelihood L   {b.likelihood:.3f}   = 1 − (1 − P)^{prm.attempts}",
            f"  complexity K   {b.complexity:.3f}   = {COMPLEXITY_STEP:.2f}^{b.h}"
            + (f"   ({'; '.join(b.h_reasons)})" if b.h_reasons else ""),
            f"  score          {r.score:.1f}   = Roundup(10 × {prm.impact:g} × K × L)   → {r.severity} (CVSS scale)",
        ]
    elif r.score == 0:
        out.append("  every path is blocked → 0.0 None")
    else:
        out.append(f"  not scored: {'; '.join(r.errors)}")
    if r.paths:
        out += ["", "ALL PATHS"]
        for p in r.paths:
            state = f"{p.score:4.1f} {p.severity:<8}" if p.open else "blocked       "
            out.append(f"  {p.path:<8} {state} p={p.p:.2f} h={p.h}  {p.target}: {p.p_note}")
            for why in p.blocked_by:
                out.append(f"  {'':<8} blocked by {why}")
    out += ["", "FINDINGS"]
    for f in r.findings:
        sev = f" [{f.severity}]" if f.severity else ""
        out.append(f"  {f.id:<21}{sev} {f.detail}")
        out += [f"  {'':<21} - {e}" for e in f.evidence[:6]]
        if len(f.evidence) > 6:
            out.append(f"  {'':<21} - … {len(f.evidence) - 6} more")
    if r.fixes:
        out += ["", "WHAT EACH FIX DOES (re-scored)"]
        out += [f"  {f.score_after:4.1f} {f.severity_after:<8} {f.owner}: {f.action}" for f in r.fixes]
    if r.cvss31_vector:
        out += [
            "",
            "VECTORS",
            f"  {r.cvss31_vector}   base {r.cvss31_base}  (CVSS alone: same for every domain on this path)",
            f"  {r.cvss40_vector}",
        ]
    if r.attack_techniques:
        out += ["", "MITRE ATT&CK"]
        out += [f"  {t['id']:<10} {t['name']}" for t in r.attack_techniques]
    return out


# --------------------------------------------------------------------------- HTML


def summary_html(r: Risk) -> str:
    e = html.e
    score = "–" if r.score is None else f"{r.score:.1f}"
    out = (
        f'<div class="risk"><span class="badge sev-{r.severity.lower()}">{e(r.severity)} {score}</span> '
        f"<code>{e(r.label)}</code><p>{e(r.headline)}</p>"
    )
    rows = []
    if r.fix:
        rows.append(
            ["fix first", e(r.fix.owner), e(r.fix.action), f"{r.fix.score_after:.1f} {e(r.fix.severity_after)}"]
        )
    if r.full_fix:
        rows.append(
            [
                "to close",
                e(r.full_fix.owner),
                e(r.full_fix.action),
                f"{r.full_fix.score_after:.1f} {e(r.full_fix.severity_after)}",
            ]
        )
    if rows:
        out += html.table(["", "owner", "action", "score after"], rows)
    return out + "</div>"


def details_html(r: Risk) -> str:
    e = html.e
    text = "\n".join(details_text(r)[1:])
    return f"<details><summary>How this score was calculated</summary><pre>{e(text)}</pre></details>"
