"""`hijackscan <domain> [--details]`: risk summary first; calculation and raw facts on request.

The terminal and the HTML page say the same things in the same order; the HTML adds a short
explanation under every heading and folds the details away. Exit code (CVSS severity):
0 None, 1 Low / Medium, 2 High / Critical, 3 Unknown.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

from ..collect import Collector
from ..config import Config
from ..risk import Risk, assess
from ..score import AddressDerived, Scored, score
from . import html, risk_view

EXIT = {"None": 0, "Low": 1, "Medium": 1, "High": 2, "Critical": 2, "Unknown": 3}

DNSSEC_MEANING = {
    "unsigned": "no DS at the registry: validators cannot verify anything for this zone",
    "secure": "DS present and the resolver set AD on the answers: a validating CA rejects forged answers",
    "bogus": "DS present but answers do not validate (SERVFAIL or no AD): broken chain, validating CAs fail closed",
}


def domain_report(
    cfg: Config, domain: str, *, html_path: Path | None = None, force: bool = False, details: bool = False
) -> int:
    rec = Collector(cfg).run([domain], force=force)[0]
    s = score(rec)
    r = assess(rec, s)
    lines = risk_view.summary_text(r)
    if details:
        lines += risk_view.details_text(r) + ["", "RAW FACTS", "", render_text(s, rec)]
    else:
        lines.append("  (--details: the calculation, every finding, vectors, references and the raw facts)")
    print("\n".join(lines))
    if html_path:
        html_path.write_text(render_html(s, rec, r), encoding="utf-8")
        print(f"\nwrote {html_path}")
    return EXIT[r.severity]


# --------------------------------------------------------------------------- one address, explained


@dataclass
class AddressStory:
    ip: str
    announced: str
    ripestat: str
    neighbours: str
    roas: list[list[str]]  # rows: prefix, maxLength, origin, TA, allows
    roa_note: str
    verdict: str
    bad: bool
    hygiene: str | None = None


def address_story(a: AddressDerived, asn_names: dict, rpki_date: str) -> AddressStory:
    if not a.prefix:
        return AddressStory(
            a.ip,
            "no announced prefix covers this address (RIPEstat network-info)",
            "-",
            "-",
            [],
            "nothing to assess",
            "not assessable",
            False,
        )
    net = ipaddress.ip_network(a.prefix, strict=False)
    limit = 24 if net.version == 4 else 48
    origin = (
        ", ".join(f"AS{n} ({(asn_names.get(str(n)) or {}).get('name') or 'unknown'})" for n in a.origin_asns) or "-"
    )
    seen = f"seen by {a.ris_visibility} RIS peers" if a.ris_visibility else "RIS visibility unknown"
    neighbours = (
        f"announced more-specifics inside it: {', '.join(a.announced_more_specifics)}  ({seen})"
        if a.announced_more_specifics
        else f"no more-specific of {a.prefix} is announced by anyone  ({seen})"
    )
    rows = []
    for r in a.roas:
        rlen = int(r["prefix"].split("/")[1])
        allows = f"allows /{rlen}–/{r['max_length']}" if r["max_length"] > rlen else "exact length only"
        rows.append([r["prefix"], str(r["max_length"]), f"AS{r['origin_asn']}", r["ta"], allows])
    if not a.roas:
        return AddressStory(
            a.ip,
            f"{a.prefix}  (length /{net.prefixlen})  by {origin}",
            a.rpki_state or "-",
            neighbours,
            [],
            f"none cover this prefix on {rpki_date}",
            f"UNKNOWN ORIGIN, effectively forgeable: with no ROA no announcement of this space is ever RPKI-invalid, "
            f"so a forged more-specific up to /{limit} passes every ROV filter and becomes the longest match",
            True,
        )
    longest = max(r["max_length"] for r in a.roas)
    usable = min(longest, limit)
    if a.forgeable_more_specific:
        verdict = (
            f"FORGEABLE: announced /{net.prefixlen}, a ROA allows up to /{longest}; a forged /{net.prefixlen + 1}–/{usable} "
            f"with the ROA's origin AS is RPKI-valid and, since nothing more specific is announced here, "
            f"becomes the longest match everywhere"
        )
    else:
        why = (
            f"ROA maxLength /{longest} equals the announced length"
            if longest == net.prefixlen
            else f"the ROA allows /{longest} but nothing longer than /{limit} is routable"
        )
        verdict = f"not forgeable: {why}; only an exact-prefix origin contest remains"
    hygiene = (
        "ROA maxLength exceeds the announced length (RFC 9319): tighten it anyway"
        if a.roa_too_permissive and not a.forgeable_more_specific
        else None
    )
    return AddressStory(
        a.ip,
        f"{a.prefix}  (length /{net.prefixlen})  by {origin}",
        a.rpki_state or "-",
        neighbours,
        rows,
        f"{len(a.roas)} covering on {rpki_date}",
        verdict,
        a.forgeable_more_specific,
        hygiene,
    )


# --------------------------------------------------------------------------- terminal


def _story_lines(st: AddressStory) -> list[str]:
    out = [
        st.ip,
        f"    announced as   {st.announced}",
        f"    RIPEstat RPKI  {st.ripestat}  (live verdict for that origin + prefix)",
        f"    {st.neighbours}",
        f"    ROAs           {st.roa_note}",
    ]
    for prefix, ml, origin, ta, allows in st.roas:
        out.append(f"      {prefix:<20} maxLength {ml:<3} origin {origin:<9} TA {ta:<8} {allows}")
    out.append(f"    → {st.verdict}")
    if st.hygiene:
        out.append(f"    ! {st.hygiene}")
    return out


def render_text(s: Scored, rec: dict) -> str:
    n_ds, n_key = len(rec["ds"]["records"]), len(rec["dnskey"]["records"])
    asns, day = rec.get("asns", {}), rec["rpki_date"]
    L = [
        s.domain,
        f"  collected     {rec['fetched_at']}  resolver {rec['resolver']}  ROAs from RPKI archive {day}",
        "",
        "DNS",
        f"  DNSSEC        {s.dnssec}   DS records at parent: {n_ds}   DNSKEY records at apex: {n_key}",
        f"                {DNSSEC_MEANING[s.dnssec]}",
    ]
    if s.caa_from:
        c = s.caa
        L += [
            f"  CAA           found at {s.caa_from}",
            f"                issue={c.issue or '-'}  issuewild={c.issuewild or '-'}",
            f"                accounturi={c.accounturi or '- (any account at the allowed CA may issue)'}",
            f"                validationmethods={c.validationmethods or '- (any method)'}",
        ]
    else:
        L.append("  CAA           none at any label up to the TLD: every CA may issue")
    L += [
        f"  nameservers   {', '.join(rec['nameservers']) or '-'}",
        f"  NS operators  {', '.join(s.ns_operators) or '-'}",
        "",
    ]

    L.append(
        "WEB ADDRESSES   — "
        + ("at least one FORGEABLE: HTTP-01 can be captured" if s.web_forgeable else "none forgeable")
    )
    for a in s.web_addresses:
        L += ["  " + x for x in _story_lines(address_story(a, asns, day))]
    if not s.web_addresses:
        L.append("  (apex and www do not resolve)")
    L.append("")
    ns_head = (
        f"all {s.ns_hosts} nameservers FORGEABLE: DNS-01 and 'no CAA' answers can be forged"
        if s.ns_forgeable
        else f"{s.ns_forgeable_hosts} of {s.ns_hosts} nameservers forgeable: partial capture, "
        "succeeds when enough CA perspectives ask a captured one (see the risk calculation)"
        if s.ns_forgeable_hosts
        else "none forgeable"
    )
    L.append("NAMESERVER ADDRESSES   — " + ns_head)
    for host, addrs in s.ns_addresses.items():
        L.append(f"  {host}")
        for a in addrs:
            L += ["    " + x for x in _story_lines(address_story(a, asns, day))]
        if not addrs:
            L.append("    (no address)")
    if s.errors:
        L.append("ERRORS  " + "; ".join(s.errors))
    return "\n".join(L)


# --------------------------------------------------------------------------- HTML, same story


def _story_html(st: AddressStory) -> str:
    e = html.e
    rows = [
        ["announced as", e(st.announced)],
        ["RIPEstat RPKI", f"{e(st.ripestat)} <span class=muted>(live verdict for that origin + prefix)</span>"],
        ["neighbours", e(st.neighbours)],
        ["ROAs", e(st.roa_note)],
    ]
    body = html.table(["", ""], rows)
    if st.roas:
        body += html.table(
            ["ROA prefix", "maxLength", "origin", "TA", "allows"], [[e(x) for x in r] for r in st.roas], {1}
        )
    cls = "bad" if st.bad else "ok"
    body += f'<p class="{cls}">→ {e(st.verdict)}</p>'
    if st.hygiene:
        body += f"<p class=muted>! {e(st.hygiene)}</p>"
    return f"<details open><summary><code>{e(st.ip)}</code> {'<span class=bad>forgeable</span>' if st.bad else '<span class=ok>not forgeable</span>'}</summary>{body}</details>"


def render_html(s: Scored, rec: dict, r: Risk | None = None) -> str:
    e = html.e
    r = r or assess(rec, s)
    asns, day = rec.get("asns", {}), rec["rpki_date"]
    n_ds, n_key = len(rec["ds"]["records"]), len(rec["dnskey"]["records"])
    head = risk_view.summary_html(r) + risk_view.details_html(r)
    body = "<h2>DNS</h2>" + html.explain(
        "What matters",
        "DNSSEC decides whether a CA validating DNSSEC can be fed forged answers; CAA decides which CA "
        "and which ACME account may issue. Both must hold: CAA in an unsigned zone can be erased by a nameserver hijack.",
    )
    caa_rows = (
        [
            ["CAA found at", e(s.caa_from)],
            ["issue / issuewild", e(f"{s.caa.issue or '-'} / {s.caa.issuewild or '-'}")],
            ["accounturi", e(s.caa.accounturi or "- (any account at the allowed CA may issue)")],
            ["validationmethods", e(s.caa.validationmethods or "- (any method)")],
        ]
        if s.caa_from
        else [["CAA", "none at any label up to the TLD: every CA may issue"]]
    )
    body += html.table(
        ["fact", "value"],
        [
            ["DNSSEC", f"<b>{e(s.dnssec)}</b> — {e(DNSSEC_MEANING[s.dnssec])}"],
            ["DS records at parent / DNSKEY at apex", f"{n_ds} / {n_key}"],
            *caa_rows,
            ["nameservers", e(", ".join(rec["nameservers"]) or "-")],
            ["NS operators", e(", ".join(s.ns_operators) or "-")],
        ],
    )

    body += (
        "<h2>Web addresses"
        + (
            " <span class=bad>— at least one forgeable: HTTP-01 can be captured</span>"
            if s.web_forgeable
            else " <span class=ok>— none forgeable</span>"
        )
        + "</h2>"
    )
    body += html.explain(
        "How to read an address",
        f"<i>announced as</i>: the most specific prefix in BGP covering this address and who originates it. "
        f"<i>neighbours</i>: whether anyone already announces something more specific (if so, a forgery is not the longest match). "
        f"<i>ROAs</i>: every ROA covering the prefix on {e(day)} with its maxLength — a maxLength longer than the announced length is what "
        f"lets a forged more-specific validate. Nothing longer than /24 (IPv4) or /48 (IPv6) is routable, so that is the cap.",
    )
    body += (
        "".join(_story_html(address_story(a, asns, day)) for a in s.web_addresses)
        or "<p>(apex and www do not resolve)</p>"
    )

    ns_note = (
        f"all {s.ns_hosts} nameservers forgeable: DNS-01 and 'no CAA' answers can be forged"
        if s.ns_forgeable
        else f"{s.ns_forgeable_hosts} of {s.ns_hosts} nameservers forgeable: partial capture, succeeds when enough CA perspectives ask a captured one"
        if s.ns_forgeable_hosts
        else "none forgeable"
    )
    body += f"<h2>Nameserver addresses <span class={'bad' if s.ns_forgeable else 'ok'}>— {e(ns_note)}</span></h2>"
    body += html.explain(
        "Why every nameserver counts",
        "A CA's resolver, and each of its remote MPIC perspectives, may ask any of the nameservers over IPv4 or IPv6. "
        "The share of captured nameserver addresses sets the chance that enough perspectives see forged answers; "
        "all captured means near certain, some captured means a partial chance (see the risk calculation above).",
    )
    for host, addrs in s.ns_addresses.items():
        body += f"<h3><code>{e(host)}</code></h3>" + (
            "".join(_story_html(address_story(a, asns, day)) for a in addrs) or "<p>(no address)</p>"
        )

    if s.errors:
        body += "<p class=bad>Errors: " + e("; ".join(s.errors)) + "</p>"
    body = head + "<details><summary>Raw facts: DNS, addresses, ROAs</summary>" + body + "</details>"
    return html.page(
        f"hijackscan: {s.domain}",
        body,
        f"collected {rec['fetched_at']} via {rec['resolver']}; ROAs from the RIPE NCC RPKI archive, {day}",
    )
