"""`hijackscan <domain>`: facts, exposure class, attack path, remediations by owner.

Exit code: 0 closed, 1 caa-only / contested-only, 2 open / caa-erasable.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

from ..collect import Collector
from ..config import Config
from ..score import Scored, score
from . import html

EXIT = {"closed": 0, "caa-only": 1, "contested-only": 1, "caa-erasable": 2, "open": 2}


def domain_report(cfg: Config, domain: str, *, html_path: Path | None = None, force: bool = False) -> int:
    rec = Collector(cfg).run([domain], force=force)[0]
    s = score(rec)
    print(render_text(s, rec))
    if html_path:
        html_path.write_text(render_html(s, rec))
        print(f"\nwrote {html_path}")
    return EXIT[s.exposure]


def _explain_address(a, asn_names: dict, rpki_date: str) -> list[str]:
    """One block per address: what is announced, what the ROAs allow, and what follows from it."""
    out = []
    if not a.prefix:
        return [f"{a.ip}", "    no announced prefix covers this address (RIPEstat network-info); nothing to assess"]
    net = ipaddress.ip_network(a.prefix, strict=False)
    limit = 24 if net.version == 4 else 48
    origin = (
        ", ".join(f"AS{n} ({(asn_names.get(str(n)) or {}).get('name') or 'unknown'})" for n in a.origin_asns) or "-"
    )
    out.append(f"{a.ip}")
    out.append(f"    announced as   {a.prefix}  (length /{net.prefixlen})  by {origin}")
    out.append(f"    RIPEstat RPKI  {a.rpki_state or '-'}  (live verdict for that origin + prefix)")
    seen = f"seen by {a.ris_visibility} RIS peers" if a.ris_visibility else "RIS visibility unknown"
    if a.announced_more_specifics:
        out.append(f"    announced more-specifics inside it: {', '.join(a.announced_more_specifics)}  ({seen})")
    else:
        out.append(f"    no more-specific of {a.prefix} is announced by anyone  ({seen})")
    if not a.roas:
        out.append(f"    ROAs {rpki_date}  none cover this prefix")
        out.append(
            f"    → FORGEABLE: no ROA means any origin is 'unknown', never invalid; "
            f"a forged more-specific up to /{limit} is accepted wherever ROV is not strict"
        )
        return out
    out.append(f"    ROAs {rpki_date}  ({len(a.roas)} covering)")
    for r in a.roas:
        allows = (
            f"allows /{r['prefix'].split('/')[1]}–/{r['max_length']}"
            if r["max_length"] > int(r["prefix"].split("/")[1])
            else "exact length only"
        )
        out.append(
            f"      {r['prefix']:<20} maxLength {r['max_length']:<3} origin AS{r['origin_asn']:<8} "
            f"TA {r['ta']:<8} {allows}"
        )
    longest = max(r["max_length"] for r in a.roas)
    usable = min(longest, limit)
    if a.forgeable_more_specific:
        out.append(
            f"    → FORGEABLE: announced /{net.prefixlen}, a ROA allows up to /{longest}; a forged "
            f"/{net.prefixlen + 1}–/{usable} with the ROA's origin AS is RPKI-valid and, since the holder announces "
            f"nothing more specific here, becomes the longest match everywhere"
        )
    else:
        why = (
            f"ROA maxLength is already /{longest} = announced length"
            if longest == net.prefixlen
            else f"ROA allows /{longest} but nothing longer than /{limit} is routable"
        )
        out.append(f"    → not forgeable: {why}; only an exact-prefix origin contest remains")
    if a.roa_too_permissive and not a.forgeable_more_specific:
        out.append("    ! ROA maxLength exceeds the announced length (RFC 9319): tighten it anyway")
    return out


def render_text(s: Scored, rec: dict) -> str:
    n_ds, n_key = len(rec["ds"]["records"]), len(rec["dnskey"]["records"])
    L = [
        f"{s.domain}",
        f"  exposure      {s.exposure.upper()}",
        f"  why           {s.reason}",
        f"  attack path   {s.attack_path}",
        f"  collected     {rec['fetched_at']}  resolver {rec['resolver']}  ROAs from RPKI archive {rec['rpki_date']}",
        "",
        "DNS",
        f"  DNSSEC        {s.dnssec}   DS records at parent: {n_ds}   DNSKEY records at apex: {n_key}",
    ]
    dnssec_note = {
        "unsigned": "no DS at the registry: validators cannot verify anything for this zone",
        "secure": "DS present and the resolver set AD on the answers: a validating CA rejects forged answers",
        "bogus": "DS present but answers do not validate (SERVFAIL or no AD): broken chain, validating CAs fail closed",
    }[s.dnssec]
    L.append(f"                {dnssec_note}")
    if s.caa_from:
        c = s.caa
        L.append(f"  CAA           found at {s.caa_from}")
        L.append(f"                issue={c.issue or '-'}  issuewild={c.issuewild or '-'}")
        L.append(f"                accounturi={c.accounturi or '- (any account at the allowed CA may issue)'}")
        L.append(f"                validationmethods={c.validationmethods or '- (any method)'}")
    else:
        L.append("  CAA           none at any label up to the TLD: every CA may issue")
    L.append(f"  nameservers   {', '.join(rec['nameservers']) or '-'}")
    L.append(f"  NS operators  {', '.join(s.ns_operators) or '-'}")
    L.append("")
    L.append(
        "WEB ADDRESSES"
        + ("   — at least one FORGEABLE: HTTP-01 can be captured" if s.web_forgeable else "   — none forgeable")
    )
    for a in s.web_addresses:
        L += ["  " + x for x in _explain_address(a, rec.get("asns", {}), rec["rpki_date"])]
    if not s.web_addresses:
        L.append("  (apex and www do not resolve)")
    L.append("")
    L.append(
        "NAMESERVER ADDRESSES"
        + (
            "   — at least one FORGEABLE: DNS-01 and 'no CAA' answers can be forged"
            if s.ns_forgeable
            else "   — none forgeable"
        )
    )
    for host, addrs in s.ns_addresses.items():
        L.append(f"  {host}")
        for a in addrs:
            L += ["    " + x for x in _explain_address(a, rec.get("asns", {}), rec["rpki_date"])]
        if not addrs:
            L.append("    (no address)")
    L.append("")
    L.append("REMEDIATIONS  (DNS-side fixes first: they hold regardless of routing)")
    for r in s.remediations:
        L.append(f"  {r.owner:<17} {r.fix}")
        L.append(f"  {'':<17} closes: {r.closes}")
    if not s.remediations:
        L.append("  none needed")
    if s.errors:
        L.append("ERRORS  " + "; ".join(s.errors))
    return "\n".join(L)


def render_html(s: Scored, rec: dict) -> str:
    e = html.e

    def rows(addrs):
        return [
            [
                e(a.ip),
                e(a.prefix or "-"),
                e(", ".join(map(str, a.origin_asns))),
                e(a.rpki_state or "-"),
                "<span class=bad>yes</span>" if a.forgeable_more_specific else "no",
                "yes" if a.roa_too_permissive else "no",
            ]
            for a in addrs
        ]

    hdr = [
        "address",
        "prefix",
        "origin AS",
        "RPKI (RIPEstat)",
        "ROAs prefix→maxLength",
        "forgeable more-specific",
        "ROA too permissive",
    ]
    body = f"<p>{html.badge(s.exposure)} {e(s.reason)}</p><p><b>Attack path:</b> {e(s.attack_path)}</p>"
    body += "<h2>DNS</h2>" + html.table(
        ["fact", "value"],
        [
            ["DNSSEC", e(s.dnssec)],
            ["DS records", len(rec["ds"]["records"])],
            ["DNSKEY records", len(rec["dnskey"]["records"])],
            ["CAA found at", e(s.caa_from or "none")],
            ["CAA issue", e(s.caa.issue)],
            ["accounturi", e(s.caa.accounturi or "-")],
            ["validationmethods", e(s.caa.validationmethods or "-")],
            ["nameserver operators", e(", ".join(s.ns_operators))],
        ],
    )
    body += "<h2>Web addresses</h2>" + html.table(hdr, rows(s.web_addresses))
    body += "<h2>Nameserver addresses</h2>"
    for host, addrs in s.ns_addresses.items():
        body += f"<p><code>{e(host)}</code></p>" + html.table(hdr, rows(addrs))
    body += "<h2>Remediations</h2>" + html.table(
        ["owner", "fix", "closes"], [[e(r.owner), e(r.fix), e(r.closes)] for r in s.remediations]
    )
    return html.page(
        f"hijackscan: {s.domain}",
        body,
        f"collected {rec['fetched_at']} via {rec['resolver']}; ROAs from RPKI archive {rec['rpki_date']}",
    )
