"""`hijackscan browse <domains.jsonl>`: one HTML page listing every domain, worst first.

Each domain is one row with the quick, actionable summary (severity, score, label, headline, first fix); clicking it
opens the details (calculation, paths, findings with evidence, re-scored fixes, CVSS vectors, ATT&CK techniques).
Self-contained: inline CSS and a small inline script for filtering. Without the script every row is still shown
and every row still expands. This page names domains, like domains.jsonl, so it never goes next to report.json in
anything shared.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from ..risk import SEVERITIES, SEVERITY_BANDS
from . import html

e = html.e

CSS = """
body{max-width:1200px}
.controls{display:flex;flex-wrap:wrap;gap:.6rem 1.2rem;align-items:center;background:#f7f7f7;padding:.6rem .8rem;
border-radius:6px;margin:1rem 0;position:sticky;top:0;z-index:1}
.controls label{font-size:.9rem} .controls select,.controls input[type=search]{font:inherit;padding:.15rem .3rem}
.sevbox{display:inline-flex;gap:.25rem;align-items:center;margin-right:.4rem}
.dom{border:1px solid #e5e5e5;border-radius:6px;margin:.35rem 0;padding:0}
.dom>summary{display:grid;grid-template-columns:7.2rem 3rem 13rem 11rem 1fr;gap:.6rem;align-items:baseline;
padding:.45rem .7rem;cursor:pointer;list-style:none;font-weight:400}
.dom>summary::-webkit-details-marker{display:none}
.dom[open]>summary{border-bottom:1px solid #e5e5e5;background:#fafafa}
.dom .score{font-variant-numeric:tabular-nums;font-weight:600;text-align:right}
.dom .name{font-weight:600;overflow-wrap:anywhere} .dom .head{color:#333} .dom .fix{color:#555;font-size:.88rem}
.body{padding:.4rem .9rem .8rem} .body h4{margin:.9rem 0 .3rem;font-size:.95rem}
.body ul{margin:.2rem 0 .2rem 1.1rem;padding:0} .body li{margin:.1rem 0}
.formula{font-family:ui-monospace,monospace;font-size:.85rem;background:#f7f7f7;padding:.5rem .7rem;border-radius:4px}
.blocked{color:#666} .count{color:#666;font-size:.9rem}
@media (max-width:800px){.dom>summary{grid-template-columns:6.5rem 2.6rem 1fr}.dom .label,.dom .headcol{grid-column:1/-1}}
"""

SCRIPT = """
(function(){
  var rows=[].slice.call(document.querySelectorAll('.dom'));
  var list=document.getElementById('list');
  var q=document.getElementById('q'),lab=document.getElementById('label'),fin=document.getElementById('finding'),
      srt=document.getElementById('sort'),cnt=document.getElementById('shown');
  var sev=[].slice.call(document.querySelectorAll('.sev'));
  function apply(){
    var on={};sev.forEach(function(c){on[c.value]=c.checked;});
    var text=q.value.trim().toLowerCase(),l=lab.value,f=fin.value,n=0;
    rows.forEach(function(r){
      var ok=on[r.dataset.severity]&&(!l||r.dataset.label===l)&&(!f||(' '+r.dataset.findings+' ').indexOf(' '+f+' ')>=0)
        &&(!text||r.dataset.domain.indexOf(text)>=0);
      r.hidden=!ok;if(ok)n++;
    });
    cnt.textContent=n;
  }
  function order(){
    var k=srt.value,s=rows.slice();
    s.sort(function(a,b){
      if(k==='domain')return a.dataset.domain<b.dataset.domain?-1:1;
      if(k==='label')return a.dataset.label<b.dataset.label?-1:a.dataset.label>b.dataset.label?1:b.dataset.score-a.dataset.score;
      return (b.dataset.score-a.dataset.score)||(a.dataset.domain<b.dataset.domain?-1:1);
    });
    s.forEach(function(r){list.appendChild(r);});
  }
  [q,lab,fin].forEach(function(x){x.addEventListener('input',apply);});
  sev.forEach(function(x){x.addEventListener('change',apply);});
  srt.addEventListener('change',order);
  document.getElementById('expand').addEventListener('click',function(){
    var open=this.dataset.open!=='1';this.dataset.open=open?'1':'0';this.textContent=open?'collapse all':'expand all';
    rows.forEach(function(r){if(!r.hidden)r.open=open;});
  });
  apply();
})();
"""


def _fix_text(f: dict | None) -> str:
    if not f:
        return ""
    return f"{e(f['owner'])}: {e(f['action'])} → <b>{f['score_after']:.1f}</b> {e(f['severity_after'])}"


def _badge(severity: str, score: float | None) -> str:
    return f'<span class="badge sev-{severity.lower()}">{e(severity)}</span>'


def _details(r: dict) -> str:
    d = r.get("details") or {}
    prm = d.get("params") or {}
    out = []

    fixes = []
    if r.get("fix"):
        fixes.append(["fix first", _fix_text(r["fix"])])
    if r.get("full_fix"):
        fixes.append(["to close", _fix_text(r["full_fix"])])
    if fixes:
        out.append("<h4>What to do</h4>" + html.table(["", "owner: action → score after"], fixes))

    c = d.get("calculation")
    if c:
        rem = prm.get("remote_perspectives", "r")
        need = rem - prm.get("allowed_non_corroborations", 0) if isinstance(rem, int) else "r-f"
        out.append(
            "<h4>How the score was calculated</h4><div class=formula>"
            f"driving path: <b>{e(c['path'])}</b> → {e(c['target'])}<br>"
            f"p = {c['p']:.2f} &nbsp; ({e(c['p_note'])})<br>"
            f"P per attempt = p × P(≥ {need} of {rem} remote perspectives fooled) = {c['p_attempt']:.3f}"
            " &nbsp; [CA/B BR 3.2.2.9]<br>"
            f"L = 1 − (1 − P)^{prm.get('attempts', 'N')} = {c['likelihood']:.3f}<br>"
            f"K = {prm.get('complexity_step', 0.87):.2f}^{c['h']} = {c['complexity']:.3f}"
            + (f" &nbsp; ({e('; '.join(c['h_reasons']))})" if c.get("h_reasons") else "")
            + f"<br>score = Roundup(10 × {prm.get('impact', 1):g} × K × L) = <b>{r['score']:.1f}</b> → "
            f"{e(r['severity'])} (CVSS scale)</div>"
        )
    elif r.get("score") == 0:
        out.append("<h4>How the score was calculated</h4><p>Every attack path is blocked → 0.0 None.</p>")

    paths = d.get("paths") or []
    if paths:
        rows = []
        for p in paths:
            state = (
                f"{_badge(p['severity'], p['score'])} {p['score']:.1f}"
                if p["open"]
                else "<span class=blocked>blocked by " + e("; ".join(p["blocked_by"])) + "</span>"
            )
            rows.append([e(p["path"]), e(p["target"]), state, f"{p['p']:.2f}", p["h"], e(p["p_note"])])
        out.append(
            "<h4>All attack paths</h4>" + html.table(["path", "target", "result", "p", "h", "why"], rows, {3, 4})
        )

    finds = d.get("findings") or []
    if finds:
        items = []
        for f in finds:
            sev = f" {_badge(f['severity'], None)}" if f.get("severity") else ""
            ev = "".join(f"<li>{e(x)}</li>" for x in f.get("evidence") or [])
            items.append(
                f"<li><code>{e(f['id'])}</code>{sev} <span class=muted>{e(f['kind'])}</span> — {e(f['detail'])}"
                + (f"<ul>{ev}</ul>" if ev else "")
                + "</li>"
            )
        out.append("<h4>Findings</h4><ul>" + "".join(items) + "</ul>")

    allfix = d.get("fixes") or []
    if allfix:
        out.append(
            "<h4>What each fix does (re-scored)</h4>"
            + html.table(
                ["score after", "severity", "owner", "action"],
                [
                    [f"{f['score_after']:.1f}", _badge(f["severity_after"], None), e(f["owner"]), e(f["action"])]
                    for f in allfix
                ],
                {0},
            )
        )

    v = d.get("vectors") or {}
    if v.get("cvss31"):
        out.append(
            "<h4>Vectors</h4><p><code>"
            + e(v["cvss31"])
            + f"</code> base {v['cvss31_base']} <span class=muted>(CVSS alone: same for every domain on this path)"
            "</span><br><code>" + e(v["cvss40"]) + "</code></p>"
        )
    tech = d.get("attack_techniques") or []
    if tech:
        out.append(
            "<h4>MITRE ATT&amp;CK</h4><ul>"
            + "".join(f"<li><code>{e(t['id'])}</code> {e(t['name'])}</li>" for t in tech)
            + "</ul>"
        )
    dq = d.get("data_quality") or {}
    if dq.get("errors"):
        out.append("<h4>Data quality</h4><ul>" + "".join(f"<li>{e(x)}</li>" for x in dq["errors"]) + "</ul>")
    return "".join(out)


def _row(r: dict) -> str:
    score = r.get("score")
    finds = " ".join(sorted({f["id"] for f in (r.get("details") or {}).get("findings") or []}))
    fix = f"<div class=fix>fix first: {_fix_text(r['fix'])}</div>" if r.get("fix") else ""
    return (
        f'<details class=dom data-severity="{e(r["severity"])}" data-label="{e(r["label"])}" '
        f'data-domain="{e(r["domain"].lower())}" data-score="{-1 if score is None else score}" '
        f'data-findings="{e(finds)}">'
        f"<summary>{_badge(r['severity'], score)}"
        f"<span class=score>{'–' if score is None else f'{score:.1f}'}</span>"
        f"<span class=name>{e(r['domain'])}</span><code class=label>{e(r['label'])}</code>"
        f"<span class=headcol><span class=head>{e(r['headline'])}</span>{fix}</span></summary>"
        f"<div class=body>{_details(r)}</div></details>"
    )


def render(rows: list[dict], source: str) -> str:
    sev = Counter(r["severity"] for r in rows)
    labels = Counter(r["label"] for r in rows)
    finds = Counter(
        f["id"] for r in rows for f in {x["id"]: x for x in (r.get("details") or {}).get("findings") or []}.values()
    )
    n = len(rows)
    rows = sorted(rows, key=lambda r: (-(r["score"] if r.get("score") is not None else -1), r["domain"]))

    body = html.explain(
        "How to read this page",
        f"One row per domain, worst first: severity (CVSS scale), score 0–10, label (what drives the score), what an "
        f"attacker can do, and the single fix that lowers the score most. Click a row for the calculation, every "
        f"attack path, the findings with evidence, what each fix does, the CVSS vectors and the ATT&amp;CK techniques. "
        f"Formula: design/formula.md. Source: <code>{e(source)}</code>.",
    )
    body += html.bar(dict(sev), html.SEVERITY_ORDER)
    body += html.table(
        ["severity", "score", "domains"],
        [[_badge(c, None), e(SEVERITY_BANDS[c]), sev.get(c, 0)] for c in SEVERITIES],
        {2},
    )
    sev_boxes = "".join(
        f'<label class=sevbox><input type=checkbox class=sev value="{c}" checked> {c} ({sev.get(c, 0)})</label>'
        for c in SEVERITIES
    )
    label_opts = "".join(f'<option value="{e(k)}">{e(k)} ({v})</option>' for k, v in labels.most_common())
    find_opts = "".join(f'<option value="{e(k)}">{e(k)} ({v})</option>' for k, v in finds.most_common())
    body += (
        "<div class=controls>"
        f"<span>{sev_boxes}</span>"
        f'<label>label <select id=label><option value="">all</option>{label_opts}</select></label>'
        f'<label>finding <select id=finding><option value="">any</option>{find_opts}</select></label>'
        "<label>sort <select id=sort><option value=score>score</option><option value=domain>domain</option>"
        "<option value=label>label</option></select></label>"
        '<input type=search id=q placeholder="search domain" aria-label="search domain">'
        "<button type=button id=expand>expand all</button>"
        f"<span class=count><span id=shown>{n}</span> of {n} shown</span>"
        "</div>"
    )
    body += "<div id=list>" + "".join(_row(r) for r in rows) + "</div>"
    body += f"<p class=muted>Generated {datetime.now(UTC).isoformat(timespec='seconds')} from {e(source)}.</p>"
    page = html.page(
        f"hijackscan: {n} domains by risk", body, "Per-domain risk of certificate theft through BGP hijacks below DNS"
    )
    return page.replace("</style>", CSS + "</style>", 1).replace("</body>", f"<script>{SCRIPT}</script></body>", 1)


def browse(jsonl: Path, out: Path | None = None) -> Path:
    rows = [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
    out = out or jsonl.with_name("domains.html")
    out.write_text(render(rows, str(jsonl)), encoding="utf-8")
    return out
