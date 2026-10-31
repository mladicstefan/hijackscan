"""`hijackscan zone <domains.txt> --out dir/`: collect (cached) → score → report.json + report.html.

Aggregate only: the HTML names operators and ASes, never domains.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from ..collect import Collector
from ..config import Config
from ..score import CLASSES, Scored, score
from . import html

BAD = ("open", "caa-erasable")

WHAT_IFS: dict[str, dict] = {
    "sign all zones": {"signed": True},
    "CAA on all": {"has_caa": True},
    "CAA + accounturi on all": {"has_caa": True, "pinned": True},
    "sign all + CAA + accounturi": {"signed": True, "has_caa": True, "pinned": True},
    "tighten all ROAs (RFC 9319)": {"web_forgeable": False, "ns_forgeable": False},
}


def zone_report(cfg: Config, domains: list[str], out: Path, *, force: bool = False) -> int:
    records = Collector(cfg).run(domains, force=force)
    scored = [score(r) for r in records]
    report = build(scored, records, cfg)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=1) + "\n")
    (out / "report.html").write_text(render_html(report))
    print(f"{len(scored)} domains: " + ", ".join(f"{c} {report['classes'][c]}" for c in CLASSES))
    print(f"wrote {out / 'report.json'} and {out / 'report.html'}")
    return 0


def _share_bad(items: list[Scored]) -> float:
    return sum(s.exposure in BAD for s in items) / len(items) if items else 0.0


def build(scored: list[Scored], records: list[dict], cfg: Config) -> dict:
    n = len(scored)
    classes = Counter(s.exposure for s in scored)

    by_op: dict[str, list[Scored]] = defaultdict(list)
    for s in scored:
        for op in s.ns_operators:
            by_op[op].append(s)
    by_as: dict[str, list[Scored]] = defaultdict(list)
    names: dict[str, str | None] = {}
    for s in scored:
        for asn, name in s.hosting_asns.items():
            by_as[asn].append(s)
            names[asn] = name

    top_ops = [op for op, _ in sorted(by_op.items(), key=lambda kv: -len(kv[1]))[:3]]
    what_if = {}
    for label, ov in WHAT_IFS.items():
        what_if[label] = Counter(score(r, ov).exposure for r in records)
    top_ov = Counter(
        score(r, {"signed": True}).exposure if set(s.ns_operators) & set(top_ops) else s.exposure
        for r, s in zip(records, scored, strict=True)
    )
    what_if[f"top-3 NS operators sign by default ({', '.join(top_ops)})"] = top_ov

    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "domains": n,
        "resolver": records[0]["resolver"] if records else None,
        "rpki_date": records[0]["rpki_date"] if records else cfg.rpki_date,
        "classes": {c: classes.get(c, 0) for c in CLASSES},
        "facts": {
            "dnssec_secure": sum(s.dnssec == "secure" for s in scored),
            "dnssec_bogus": sum(s.dnssec == "bogus" for s in scored),
            "has_caa": sum(s.has_caa for s in scored),
            "pinned": sum(s.pinned for s in scored),
            "web_forgeable": sum(s.web_forgeable for s in scored),
            "ns_forgeable": sum(s.ns_forgeable for s in scored),
            "ns_partial": sum(bool(s.ns_forgeable_hosts) and not s.ns_forgeable for s in scored),
            "errors": sum(bool(s.errors) for s in scored),
        },
        "by_ns_operator": [
            {
                "operator": op,
                "domains": len(v),
                "share_open_or_erasable": round(_share_bad(v), 3),
                "signed": sum(s.signed for s in v),
            }
            for op, v in sorted(by_op.items(), key=lambda kv: -len(kv[1]))
        ],
        "by_hosting_as": [
            {
                "asn": asn,
                "name": names[asn],
                "domains": len(v),
                "share_open_or_erasable": round(_share_bad(v), 3),
                "web_forgeable": sum(s.web_forgeable for s in v),
            }
            for asn, v in sorted(by_as.items(), key=lambda kv: -len(kv[1]))
        ],
        "what_if": {label: {c: cnt.get(c, 0) for c in CLASSES} for label, cnt in what_if.items()},
    }


CLASS_MEANING = {
    "closed": "CAA pins issuance to one ACME account and the zone validates: nothing in routing can steer a CA "
    "that validates DNSSEC.",
    "caa-only": "CAA restricts the CA and the zone validates, but any account at that CA may issue after a web hijack.",
    "caa-erasable": "CAA exists, but the zone is unsigned and every nameserver can be captured: the attacker answers "
    "'no CAA' and validation proceeds. CAA bought nothing.",
    "open": "No CAA, and a more-specific hijack captures the web prefix or every nameserver: the 28 August 2026 "
    "pattern applies as is.",
    "contested-only": "No more-specific hijack is possible (ROAs tight, or nothing longer is routable). Only an "
    "exact-prefix origin contest or a partial nameserver capture remains - and there is still no DNS-side defence.",
}

WHAT_IF_MEANING = {
    "sign all zones": "DNSSEC alone: makes CAA answers unforgeable, but protects nothing where there is no CAA.",
    "CAA on all": "CAA alone: in unsigned zones a nameserver hijack erases it, so 'open' turns into 'caa-erasable'.",
    "CAA + accounturi on all": "Pinning the ACME account: still erasable while the zone is unsigned.",
    "sign all + CAA + accounturi": "Both fixes together. This row is 'closed' by definition - it shows the ceiling, "
    "not a measurement.",
    "tighten all ROAs (RFC 9319)": "Routing-side fix only: removes the win-everywhere more-specific, leaves the "
    "exact-prefix contest and no DNS-side defence.",
}


def render_html(r: dict) -> str:
    e, n = html.e, r["domains"]

    def pct(x: int) -> str:
        return f"{100 * x / n:.0f}%" if n else "-"

    f = r["facts"]
    body = html.explain(
        "How to read this report",
        f"Each of the {n} domains was looked up once (web and nameserver addresses, CAA, DS, DNSKEY with the AD flag) "
        f"and every address was matched against BGP (announced prefix, origin AS) and the RPKI ROAs of {e(r['rpki_date'])}. "
        "A prefix is <i>forgeable</i> when a ROA allows a longer prefix than is announced (and nothing longer is already "
        "announced), or when no ROA covers it at all: an attacker can then announce a more-specific that is RPKI-valid "
        "(or never invalid) and wins route selection everywhere - the 28 August 2026 Hetzner pattern. Each domain is "
        "then put in exactly one exposure class, first match wins. No domain names appear below.",
    )
    body += "<h2>Exposure classes</h2>" + html.bar(r["classes"])
    body += html.table(
        ["class", "domains", "share", "meaning"],
        [[html.badge(c), v, pct(v), e(CLASS_MEANING[c])] for c, v in r["classes"].items()],
        {1, 2},
    )
    body += "<h2>Facts</h2>" + html.explain(
        "Raw counts behind the classes",
        "DNSSEC <i>secure</i> = DS at the registry and the validating resolver set AD; <i>bogus</i> = DS present but "
        "answers do not validate. <i>accounturi</i> is the CAA parameter (RFC 8657) that pins issuance to one ACME "
        "account. <i>forgeable</i> counts domains with at least one such address; the nameserver line counts domains "
        "where <b>every</b> nameserver is forgeable, which is what the attack needs.",
    )
    body += html.table(
        ["fact", "domains", "share"],
        [
            ["DNSSEC secure (DS + validates)", f["dnssec_secure"], pct(f["dnssec_secure"])],
            ["DNSSEC bogus (DS but does not validate)", f["dnssec_bogus"], pct(f["dnssec_bogus"])],
            ["CAA present", f["has_caa"], pct(f["has_caa"])],
            ["CAA with accounturi", f["pinned"], pct(f["pinned"])],
            ["web prefix forgeable", f["web_forgeable"], pct(f["web_forgeable"])],
            ["all nameserver prefixes forgeable", f["ns_forgeable"], pct(f["ns_forgeable"])],
            ["some (not all) nameserver prefixes forgeable", f["ns_partial"], pct(f["ns_partial"])],
        ],
        {1, 2},
    )
    body += "<h2>By nameserver operator</h2>" + html.explain(
        "Who can fix the DNS side",
        "Operator = registered domain of the nameserver hosts; a domain with nameservers at two operators counts for "
        "both. <i>signed</i> = domains that validate. The last column is the share of that operator's domains in "
        "open or caa-erasable. An operator that signs by default and keeps tight ROAs moves all of its rows at once.",
    )
    body += html.table(
        ["operator", "domains", "signed", "% open or caa-erasable"],
        [
            [e(x["operator"]), x["domains"], x["signed"], f"{100 * x['share_open_or_erasable']:.0f}%"]
            for x in r["by_ns_operator"][:25]
        ],
        {1, 2, 3},
    )
    body += "<h2>By hosting AS (web)</h2>" + html.explain(
        "Who can fix the routing side",
        "The AS originating the web addresses. <i>web forgeable</i> = domains whose web prefix at this AS admits an "
        "RPKI-valid (or never-invalid) more-specific; a hosting provider fixes it by setting ROA maxLength equal to "
        "what it announces (RFC 9319).",
    )
    body += html.table(
        ["AS", "name", "domains", "web forgeable", "% open or caa-erasable"],
        [
            [
                e(x["asn"]),
                e(x["name"] or "-"),
                x["domains"],
                x["web_forgeable"],
                f"{100 * x['share_open_or_erasable']:.0f}%",
            ]
            for x in r["by_hosting_as"][:25]
        ],
        {2, 3, 4},
    )
    body += "<h2>What if</h2>" + html.explain(
        "Re-scoring under one fix applied to every domain",
        "The same records, with one property overridden for all domains, re-classified with the same rules. "
        "The informative rows are the partial ones: a single fix that moves nothing is a fix that does not work alone.",
    )
    rows = [
        [
            "<i>as measured</i>",
            *[r["classes"][c] for c in CLASSES],
            pct(r["classes"]["open"] + r["classes"]["caa-erasable"]),
            "",
        ]
    ]
    for label, cnt in r["what_if"].items():
        meaning = WHAT_IF_MEANING.get(label, "The three largest nameserver operators sign every zone they host.")
        rows.append([e(label), *[cnt[c] for c in CLASSES], pct(cnt["open"] + cnt["caa-erasable"]), e(meaning)])
    body += html.table(["scenario", *CLASSES, "open + erasable", "reads as"], rows, set(range(1, 7)))
    body += (
        f"<p class=muted>Resolver {e(r['resolver'])}; ROAs from the RIPE NCC RPKI archive, {e(r['rpki_date'])}; "
        f"generated {e(r['generated_at'])}. No domain names are listed.</p>"
    )
    return html.page(
        f"hijackscan zone report - {n} domains",
        body,
        "Exposure to certificate theft through BGP hijacks below DNS, and what CAA + DNSSEC would close",
    )
