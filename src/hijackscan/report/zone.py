"""`hijackscan zone <domains.txt> --out dir/`: collect (cached) → score → risk → report.json + report.html + domains.jsonl.

report.json and report.html are aggregate only: they name operators and ASes, never domains.
domains.jsonl holds one risk record per domain (summary + details), worst first.
Every number comes from the risk model in design/formula.md (risk.py).
"""

from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from ..collect import Collector
from ..config import Config
from ..risk import COMPLEXITY_STEP, LABELS, SEVERITIES, SEVERITY_BANDS, Risk, assess
from ..score import Scored, score
from . import html
from .domain import routing_source, rpki_source
from .browse import browse

SCHEMA_VERSION = 2
SEVERE = ("High", "Critical")

# Each scenario re-scores every domain with the same formula and one fix applied everywhere.
WHAT_IFS: list[tuple[str, dict, str]] = [
    ("sign all zones", {"signed": True}, "DNSSEC alone closes the nameserver path, not the web path."),
    (
        "CAA on all (no accounturi)",
        {"has_caa": True},
        "CAA without accounturi changes no score: the attacker opens an account at the allowed CA.",
    ),
    (
        "CAA + accounturi on all",
        {"pinned": True},
        "Closes the web path; in unsigned zones a nameserver capture still erases CAA.",
    ),
    (
        "sign all + CAA + accounturi",
        {"signed": True, "pinned": True},
        "Both DNS-side fixes: every path blocked. The ceiling, by definition.",
    ),
    (
        "tighten all ROAs (RFC 9319)",
        {"web_tight": True, "ns_tight": True},
        "Routing-side fix only: removes forged more-specifics, leaves the exact-prefix contest.",
    ),
]


def zone_report(cfg: Config, domains: list[str], out: Path, *, meta: dict | None = None, force: bool = False) -> int:
    """`meta` is the header of a `hijackscan sample` list (population facts); None for a plain domain list."""
    records = Collector(cfg).run(domains, force=force)
    scored = [score(r, caps=cfg.routable_caps) for r in records]
    risks = [assess(r, s) for r, s in zip(records, scored, strict=True)]
    report = build(records, scored, risks, cfg, meta)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "report.html").write_text(render_html(report), encoding="utf-8")
    # Per-domain records name domains, so they live in their own file, never in report.json / report.html.
    with (out / "domains.jsonl").open("w", encoding="utf-8") as f:
        for r in sorted(risks, key=lambda r: (-(r.score if r.score is not None else -1), r.domain)):
            f.write(json.dumps(r.to_json(), ensure_ascii=False) + "\n")
    browse(out / "domains.jsonl")
    sev = report["severity"]
    print(f"{len(risks)} domains: " + ", ".join(f"{c} {sev[c]['domains']}" for c in SEVERITIES))
    print(f"wrote {out / 'report.json'}, {out / 'report.html'}, {out / 'domains.jsonl'} and {out / 'domains.html'}")
    return 0


# --------------------------------------------------------------------------- aggregation


def _counts(risks: list[Risk]) -> dict[str, int]:
    c = Counter(r.severity for r in risks)
    return {s: c.get(s, 0) for s in SEVERITIES}


def _stats(risks: list[Risk]) -> dict:
    """Severity counts, mean / median over scored domains, and how many are High or Critical."""
    scores = [r.score for r in risks if r.score is not None]
    return {
        "severity": _counts(risks),
        "scored": len(scores),
        "mean_score": round(statistics.fmean(scores), 2) if scores else None,
        "median_score": round(statistics.median(scores), 2) if scores else None,
        "high_or_critical": sum(r.severity in SEVERE for r in risks),
    }


def _closing(r: Risk):
    """The fewest actions that bring this domain to 0, or None."""
    return r.full_fix or (r.fix if r.fix and r.fix.score_after == 0 else None)


def _tld(records: list[dict]) -> str | None:
    tlds = {r["domain"].rsplit(".", 1)[-1] for r in records}
    return tlds.pop() if len(tlds) == 1 else None


def _population(meta: dict | None, n: int) -> dict | None:
    """Zone-wide facts from the sample header, joined with the sampled DS ratio as the representativeness check."""
    if not meta:
        return None
    pop, pop_ds = meta["population"], meta["population_ds"]
    return {
        "apex": meta.get("apex"),
        "soa_serial": meta.get("soa_serial"),
        "seed": meta.get("seed"),
        "delegations": pop,
        "ds": pop_ds,
        "ds_share": round(pop_ds / pop, 4) if pop else None,
        "sample_ds": meta.get("sample_ds"),
        "sample_ds_share": round(meta["sample_ds"] / n, 4) if n and "sample_ds" in meta else None,
        "ns_operators": meta.get("ns_operators", []),
    }


def build(records: list[dict], scored: list[Scored], risks: list[Risk], cfg: Config, meta: dict | None = None) -> dict:
    n = len(risks)
    population = _population(meta, n)
    pop_ops = {x["operator"]: x for x in population["ns_operators"]} if population else {}
    prm = risks[0].params if risks else None
    sev = _counts(risks)

    by_op: dict[str, list[tuple[Scored, Risk]]] = defaultdict(list)
    by_as: dict[str, list[tuple[Scored, Risk]]] = defaultdict(list)
    as_names: dict[str, str | None] = {}
    for s, r in zip(scored, risks, strict=True):
        for op in s.ns_operators:
            by_op[op].append((s, r))
        for asn, name in s.hosting_asns.items():
            by_as[asn].append((s, r))
            as_names[asn] = name

    what_if = []
    for label, ov, reads in WHAT_IFS:
        rs = [assess(rec, s, ov=ov, fixes=False) for rec, s in zip(records, scored, strict=True)]
        what_if.append({"scenario": label, "overrides": ov, "reads_as": reads, **_stats(rs)})
    top_ops = [op for op, _ in sorted(by_op.items(), key=lambda kv: -len(kv[1]))[:3]]
    rs = [
        assess(rec, s, ov={"signed": True}, fixes=False) if set(s.ns_operators) & set(top_ops) else r
        for rec, s, r in zip(records, scored, risks, strict=True)
    ]
    what_if.append(
        {
            "scenario": f"top-3 NS operators sign by default ({', '.join(top_ops)})",
            "overrides": {"signed": True, "only_ns_operators": top_ops},
            "reads_as": "The three largest nameserver operators sign every zone they host.",
            **_stats(rs),
        }
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "scope": {
        "domains": n,
        "tld": _tld(records),
        "resolver": records[0]["resolver"] if records else None,
        "routing_source": records[0].get("routing_source") if records else None,
        "rpki_source": records[0].get("rpki_source") if records else None,
        "rpki_date": records[0]["rpki_date"] if records else cfg.rpki_date,
        "population": population,
        },
        "model": {
            "formula": "design/formula.md",
            "score": "10 x I x max over paths (open x K x L); L = 1-(1-P)^N; K = complexity_step^h",
            "scale": SEVERITY_BANDS,
            "params": (asdict(prm) | {"complexity_step": round(COMPLEXITY_STEP, 4)}) if prm else None,
        },
        "severity": {
            c: {"band": SEVERITY_BANDS[c], "domains": sev[c], "share": round(sev[c] / n, 4) if n else None}
            for c in SEVERITIES
        },
        "summary": _stats(risks),
        "labels": {
            k: {"domains": v, "meaning": LABELS.get(k, "")} for k, v in Counter(r.label for r in risks).most_common()
        },
        "findings": dict(Counter(f.id for r in risks for f in {x.id: x for x in r.findings}.values()).most_common()),
        "defences": {
            "dnssec_secure": sum(s.dnssec == "secure" for s in scored),
            "dnssec_bogus": sum(s.dnssec == "bogus" for s in scored),
            "dnssec_unsigned": sum(s.dnssec == "unsigned" for s in scored),
            "caa": sum(s.has_caa for s in scored),
            "caa_accounturi": sum(s.pinned for s in scored),
        },
        "fixes": {
            "first_fix": dict(Counter(r.fix.action for r in risks if r.fix).most_common()),
            "to_close": dict(Counter(f.action for r in risks if (f := _closing(r))).most_common()),
        },
        "by_ns_operator": [
            {
                "operator": op,
                "domains": len(v),
                **_stats([r for _, r in v]),
                "signed": sum(s.signed for s, _ in v),
                "zone_delegations": pop_ops[op]["delegations"] if op in pop_ops else None,
                "zone_ds": pop_ops[op]["ds"] if op in pop_ops else None,
            }
            for op, v in sorted(by_op.items(), key=lambda kv: -len(kv[1]))
        ],
        "by_hosting_as": [
            {
                "asn": asn,
                "name": as_names[asn],
                "domains": len(v),
                **_stats([r for _, r in v]),
                "web_forgeable": sum(s.web_forgeable for s, _ in v),
            }
            for asn, v in sorted(by_as.items(), key=lambda kv: -len(kv[1]))
        ],
        "what_if": what_if,
    }


# --------------------------------------------------------------------------- HTML


def render_html(r: dict) -> str:
    e = html.e
    scope, summ, model = r["scope"], r["summary"], r["model"]
    n = scope["domains"]
    prm = model["params"] or {}
    sev = {c: v["domains"] for c, v in r["severity"].items()}

    def pct(x: int) -> str:
        return f"{100 * x / n:.0f}%" if n else "-"

    def mean(x: float | None) -> str:
        return "-" if x is None else f"{x:.1f}"

    d = r["defences"]
    pop = scope.get("population")
    zone_name = f".{scope['tld']}" if scope.get("tld") else "the zone"
    sampled = (
        f"The {n} domains are a seeded random sample (seed {e(str(pop['seed']))}) of the {pop['delegations']:,} "
        f"delegations in the {e(zone_name)} zone file (SOA serial {e(str(pop['soa_serial']))}). "
        if pop
        else ""
    )
    body = html.explain(
        "How to read this report",
        sampled
        + f"Each of the {n} domains was looked up once (web and nameserver addresses, CAA, DS, DNSKEY with the AD flag) "
        f"and every address was matched against BGP (announced prefix, origin AS) and the RPKI ROAs of "
        f"{e(scope['rpki_date'])}. Each domain then gets a risk score from 0 to 10: the chance that the best attack "
        f"path yields a certificate within {prm.get('attempts', '?')} requests, under the CA/B Forum multi-perspective "
        f"rule ({prm.get('remote_perspectives', '?')} remote perspectives, {prm.get('allowed_non_corroborations', '?')} "
        f"may disagree), discounted by {prm.get('complexity_step', 0):.2f} per high-complexity step (the CVSS 3.1 "
        "AC:H / AC:L ratio). Severity uses the CVSS rating scale. Derivation and references: design/formula.md. "
        "No domain names appear below.",
    )
    if pop:
        body += f"<h2>The whole {e(zone_name)} zone</h2>" + html.explain(
            "What the zone file says for free",
            "The parent zone lists every delegation and which of them have a DS record. That is the population the "
            "sample estimates. <b>DS at parent is an upper bound on DNSSEC that validates</b>: zones signed without a "
            "DS (islands) are not counted, and a DS whose chain is broken makes the zone bogus, not secure. Only the "
            "live sample below splits secure from bogus. The sample's DS share next to the zone's is the "
            "representativeness check.",
        )
        body += html.table(
            ["fact", "whole zone", "share", "this sample", "share"],
            [
                ["delegations", f"{pop['delegations']:,}", "100%", n, "100%"],
                [
                    "DS at parent",
                    f"{pop['ds']:,}",
                    f"{100 * pop['ds_share']:.1f}%",
                    pop["sample_ds"] if pop["sample_ds"] is not None else "-",
                    f"{100 * pop['sample_ds_share']:.0f}%" if pop["sample_ds_share"] is not None else "-",
                ],
                ["DNSSEC secure (live)", "-", "-", d["dnssec_secure"], pct(d["dnssec_secure"])],
                ["DNSSEC bogus (live)", "-", "-", d["dnssec_bogus"], pct(d["dnssec_bogus"])],
            ],
            {1, 2, 3, 4},
        )

    body += "<h2>Risk severity</h2>" + html.bar(sev, html.SEVERITY_ORDER)
    body += html.table(
        ["severity", "score", "domains", "share"],
        [[html.badge(c), e(v["band"]), v["domains"], pct(v["domains"])] for c, v in r["severity"].items()],
        {2, 3},
    )
    body += (
        f"<p>Mean score {mean(summ['mean_score'])}, median {mean(summ['median_score'])} over {summ['scored']} "
        f"scored domains; <b>{summ['high_or_critical']} High or Critical ({pct(summ['high_or_critical'])})</b>.</p>"
    )

    body += "<h2>What drives the score</h2>" + html.explain(
        "Label",
        "The attack path with the highest score, and the defence state around it. The label names the specific "
        "weakness; the severity is the number.",
    )
    body += html.table(
        ["label", "domains", "share", "meaning"],
        [[f"<code>{e(k)}</code>", v["domains"], pct(v["domains"]), e(v["meaning"])] for k, v in r["labels"].items()],
        {1, 2},
    )

    body += "<h2>Defences and findings</h2>" + html.explain(
        "Raw counts",
        "DNSSEC <i>secure</i> = DS at the registry and the validating resolver set AD; <i>bogus</i> = DS present but "
        "answers do not validate. <i>accounturi</i> (RFC 8657) pins issuance to one ACME account. A finding counts "
        "each domain once.",
    )
    body += html.table(
        ["defence", "domains", "share"],
        [
            ["DNSSEC secure", d["dnssec_secure"], pct(d["dnssec_secure"])],
            ["DNSSEC bogus", d["dnssec_bogus"], pct(d["dnssec_bogus"])],
            ["unsigned", d["dnssec_unsigned"], pct(d["dnssec_unsigned"])],
            ["CAA present", d["caa"], pct(d["caa"])],
            ["CAA with accounturi", d["caa_accounturi"], pct(d["caa_accounturi"])],
        ],
        {1, 2},
    )
    body += html.table(
        ["finding", "domains", "share"], [[f"<code>{e(k)}</code>", v, pct(v)] for k, v in r["findings"].items()], {1, 2}
    )

    body += "<h2>Fixes</h2>" + html.explain(
        "Re-scored per domain",
        "<i>First fix</i>: the single action that lowers that domain's score most. <i>To close</i>: the fewest "
        "actions that bring it to 0.0.",
    )
    body += html.table(
        ["first fix", "domains"], [[e(k), v] for k, v in r["fixes"]["first_fix"].items()], {1}
    ) + html.table(["to close", "domains"], [[e(k), v] for k, v in r["fixes"]["to_close"].items()], {1})

    body += "<h2>By nameserver operator</h2>" + html.explain(
        "Who can fix the DNS side",
        "Operator = registered domain of the nameserver hosts; a domain with nameservers at two operators counts for "
        "both. <i>signed</i> = sampled domains that validate. An operator that signs by default moves all of its rows "
        "at once."
        + (
            " <i>share of zone</i> and <i>DS at parent, zone-wide</i> come from the zone file (top operators only): "
            "the gap between DS published and DNSSEC validating is visible per operator."
            if pop
            else ""
        ),
    )
    cols = ["operator", "domains", "signed", "mean score", "High + Critical"]
    rows = []
    for x in r["by_ns_operator"][:25]:
        row = [e(x["operator"]), x["domains"], x["signed"], mean(x["mean_score"]), x["high_or_critical"]]
        if pop:
            z = x["zone_delegations"]
            row += [
                f"{100 * z / pop['delegations']:.1f}%" if z else "-",
                f"{100 * x['zone_ds'] / z:.0f}%" if z else "-",
            ]
        rows.append(row)
    if pop:
        cols += ["share of zone", "DS at parent, zone-wide"]
    body += html.table(cols, rows, set(range(1, len(cols))))

    body += "<h2>By hosting AS (web)</h2>" + html.explain(
        "Who can fix the routing side",
        "The AS originating the web addresses. <i>web forgeable</i> = domains whose web prefix at this AS admits an "
        "RPKI-valid (or never-invalid) more-specific; a hosting provider fixes it by setting ROA maxLength equal to "
        "what it announces (RFC 9319).",
    )
    body += html.table(
        ["AS", "name", "domains", "web forgeable", "mean score", "High + Critical"],
        [
            [
                e(x["asn"]),
                e(x["name"] or "-"),
                x["domains"],
                x["web_forgeable"],
                mean(x["mean_score"]),
                x["high_or_critical"],
            ]
            for x in r["by_hosting_as"][:25]
        ],
        {2, 3, 4, 5},
    )

    body += "<h2>What if</h2>" + html.explain(
        "Re-scoring under one fix applied to every domain",
        "The same records and the same formula, with one fix applied everywhere. The informative rows are the "
        "partial ones: a fix that moves nothing does not work alone.",
    )
    rows = [["<i>as measured</i>", *[sev[c] for c in SEVERITIES], mean(summ["mean_score"]), ""]]
    for w in r["what_if"]:
        rows.append(
            [e(w["scenario"]), *[w["severity"][c] for c in SEVERITIES], mean(w["mean_score"]), e(w["reads_as"])]
        )
    body += html.table(["scenario", *SEVERITIES, "mean score", "reads as"], rows, set(range(1, len(SEVERITIES) + 2)))
    body += (
    f"<p class=muted>Resolver {e(scope['resolver'])}; routing from {e(routing_source(scope))}; "
    f"ROAs from {e(rpki_source(scope))}, {e(scope['rpki_date'])}; "
    f"generated {e(r['generated_at'])}. No domain names are listed.</p>"
    )
    return html.page(
        f"hijackscan zone report - {n} {e(zone_name)} domains"
        if scope.get("tld")
        else f"hijackscan zone report - {n} domains",
        body,
        "Risk of certificate theft through BGP hijacks below DNS (CVSS severity scale), and what each fix closes",
    )
