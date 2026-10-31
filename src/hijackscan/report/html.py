"""Self-contained HTML: inline CSS, no scripts, no CDN."""

from __future__ import annotations

from html import escape

CSS = """
body{font:15px/1.45 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#1c1c1c}
h1{font-size:1.6rem;margin-bottom:.2rem} h2{font-size:1.15rem;margin-top:2rem;border-bottom:1px solid #ddd}
.muted{color:#666;font-size:.9rem} table{border-collapse:collapse;width:100%;margin:.6rem 0}
th,td{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #e5e5e5;vertical-align:top}
th{background:#f4f4f4;font-weight:600} td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.bar{display:flex;height:28px;border-radius:4px;overflow:hidden;margin:.5rem 0}
.bar span{display:block;height:100%} .legend span{display:inline-block;margin-right:1rem}
.sw{display:inline-block;width:.9em;height:.9em;border-radius:2px;vertical-align:-.1em;margin-right:.3em}
.c-closed{background:#2a9d8f} .c-caa-only{background:#8ab17d} .c-contested-only{background:#e9c46a}
.c-caa-erasable{background:#f4a261} .c-open{background:#e76f51}
.badge{display:inline-block;padding:.1rem .5rem;border-radius:3px;color:#fff;font-weight:600}
code{background:#f4f4f4;padding:0 .25rem;border-radius:2px} .ok{color:#2a9d8f} .bad{color:#e76f51}
.explain{background:#f7f7f2;border-left:3px solid #c9c9b8;padding:.4rem .8rem;margin:.6rem 0;font-size:.92rem}
.explain p,.explain ul{margin:.2rem 0} .explain li{margin:.15rem 0}
details{border:1px solid #e5e5e5;border-radius:4px;padding:.3rem .7rem;margin:.5rem 0} summary{cursor:pointer;font-weight:600}
details table{margin:.3rem 0} h3{font-size:1rem;margin:1.2rem 0 .2rem}
"""

CLASS_ORDER = ("closed", "caa-only", "contested-only", "caa-erasable", "open")


def page(title: str, body: str, subtitle: str = "") -> str:
    return (
        "<!DOCTYPE html><html lang=en><head><meta charset=utf-8>"
        f"<title>{escape(title)}</title><style>{CSS}</style></head><body>"
        f"<h1>{escape(title)}</h1><p class=muted>{escape(subtitle)}</p>{body}</body></html>"
    )


def bar(counts: dict[str, int]) -> str:
    total = sum(counts.values()) or 1
    segs = "".join(
        f'<span class="c-{c}" style="width:{100 * counts.get(c, 0) / total:.1f}%" title="{c}"></span>'
        for c in CLASS_ORDER
    )
    legend = "".join(
        f'<span><i class="sw c-{c}"></i>{c} {counts.get(c, 0)} ({100 * counts.get(c, 0) / total:.0f}%)</span>'
        for c in CLASS_ORDER
    )
    return f"<div class=bar>{segs}</div><div class=legend>{legend}</div>"


def table(headers: list[str], rows: list[list], numeric: set[int] = frozenset()) -> str:
    th = "".join(f'<th class="{"num" if i in numeric else ""}">{escape(str(h))}</th>' for i, h in enumerate(headers))
    trs = "".join(
        "<tr>"
        + "".join(f'<td class="{"num" if i in numeric else ""}">{cell}</td>' for i, cell in enumerate(r))
        + "</tr>"
        for r in rows
    )
    return f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>"


def explain(title: str, text: str, *, as_list: bool = False) -> str:
    inner = f"<ul>{text}</ul>" if as_list else f"<p>{text}</p>"
    return f"<div class=explain><b>{escape(title)}.</b> {inner}</div>"


def badge(cls: str) -> str:
    return f'<span class="badge c-{cls}">{escape(cls)}</span>'


def e(x: object) -> str:
    return escape(str(x))
