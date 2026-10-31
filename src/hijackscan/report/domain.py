"""`hijackscan <domain>`: facts, exposure class, attack path, remediations by owner.

Exit code: 0 closed, 1 caa-only / contested-only, 2 open / caa-erasable.
"""

from __future__ import annotations

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


def _addr_line(a) -> str:
    flags = []
    if a.forgeable_more_specific:
        flags.append("FORGEABLE more-specific")
    if a.roa_too_permissive:
        flags.append("ROA maxLength too permissive")
    if a.rpki_derived != "found":
        flags.append(f"ROA {a.rpki_derived}")
    asn = "AS" + ",".join(map(str, a.origin_asns)) if a.origin_asns else "-"
    return f"{a.ip:<40} {a.prefix or '-':<20} {asn:<10} {a.rpki_state or '-':<8} {'; '.join(flags)}"


def render_text(s: Scored, rec: dict) -> str:
    L = [
        f"{s.domain}  —  {s.exposure.upper()}",
        f"  {s.reason}",
        f"  collected {rec['fetched_at']} via {rec['resolver']}, ROAs from RPKI archive {rec['rpki_date']}",
        "",
    ]
    L.append("DNS")
    n_ds, n_key = len(rec["ds"]["records"]), len(rec["dnskey"]["records"])
    L.append(f"  DNSSEC: {s.dnssec}  (DS records: {n_ds}, DNSKEY records: {n_key})")
    if s.caa_from:
        c = s.caa
        L.append(f"  CAA at {s.caa_from}: issue={c.issue} issuewild={c.issuewild}")
        L.append(f"    accounturi={c.accounturi or '-'} validationmethods={c.validationmethods or '-'}")
    else:
        L.append("  CAA: none at any label")
    L.append(f"  nameserver operators: {', '.join(s.ns_operators) or '-'}")
    L.append("")
    L.append("Web addresses" + ("  [FORGEABLE]" if s.web_forgeable else ""))
    L += ["  " + _addr_line(a) for a in s.web_addresses] or ["  (none resolved)"]
    L.append("Nameserver addresses" + ("  [FORGEABLE]" if s.ns_forgeable else ""))
    for host, addrs in s.ns_addresses.items():
        L.append(f"  {host}")
        L += ["    " + _addr_line(a) for a in addrs] or ["    (no address)"]
    L.append("")
    L.append(f"Attack path: {s.attack_path}")
    L.append("Remediations")
    for r in s.remediations:
        L.append(f"  [{r.owner}] {r.fix}  → closes: {r.closes}")
    if not s.remediations:
        L.append("  none needed")
    if s.errors:
        L.append("Errors: " + "; ".join(s.errors))
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

    hdr = ["address", "prefix", "origin AS", "RPKI (RIPEstat)", "forgeable more-specific", "ROA too permissive"]
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
