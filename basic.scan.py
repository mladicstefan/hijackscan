#!/usr/bin/env python3
"""
hijackscan step 1: collect facts for every domain in domeni.txt and print
a readable report (one block per domain, one row per server).

Usage:
    python collect.py                       # reads domeni.txt
    python collect.py other_list.txt
    DNS_SERVER=127.0.0.1 python collect.py  # use your local Unbound lab

Output:
    - the report on screen (red VULNERABLE marker where applicable)
    - targets.csv, a machine-readable copy that the next step (the
      classifier) will read. You can ignore it for now.
"""
import csv
import ipaddress
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import dns.exception
import dns.flags
import dns.rdatatype
import dns.resolver

INPUT = sys.argv[1] if len(sys.argv) > 1 else "domeni.txt"
SOURCEAPP = "hijackscan-dogma"  # RIPEstat asks callers to identify themselves

# ------------------------------------------------------------------ colours
# ANSI escape codes make terminal text red. os.system("") switches ANSI
# support on in the Windows 10/11 console; on Linux/macOS it does nothing.
os.system("")
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ------------------------------------------------------------- DNS helpers


def make_resolver():
    """Build the DNS resolver used for every lookup."""
    r = dns.resolver.Resolver()
    if os.environ.get("DNS_SERVER"):  # optional: point at your own resolver
        r.nameservers = [os.environ["DNS_SERVER"]]
    r.lifetime = 6  # give up on a single lookup after 6 seconds
    # EDNS with the DO bit = "please include DNSSEC data (RRSIG) in answers"
    r.use_edns(0, dns.flags.DO, 1232)
    return r


RES = make_resolver()


def query(name, rtype):
    """Ask DNS for one record type. Return the answer, or None on any failure
    (domain doesn't exist, no such record, timeout, SERVFAIL...)."""
    try:
        return RES.resolve(name, rtype)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout,
        dns.exception.DNSException,
    ):
        return None


def get_ips(name):
    """Return every IPv4 (A) and IPv6 (AAAA) address of a hostname."""
    ips = []
    for rtype in ("A", "AAAA"):
        ans = query(name, rtype)
        if ans:
            ips += [rr.to_text() for rr in ans]
    return ips


def signature_expiry(domain):
    """Return the date on which the DNSSEC signature of this domain expires.

    A signed zone attaches an RRSIG record to its answers; that record
    contains an expiry timestamp. We read the RRSIGs that come with the SOA
    answer (falling back to the A answer) and keep the soonest expiry.
    Returns 'YYYY-MM-DD' or None if the domain is unsigned."""
    soonest = None
    for rtype in ("SOA", "A"):
        ans = query(domain, rtype)
        if not ans:
            continue
        for rrset in ans.response.answer:
            if rrset.rdtype != dns.rdatatype.RRSIG:
                continue
            for rr in rrset:
                exp = rr.expiration
                # dnspython stores it as a unix timestamp; convert to a date
                if isinstance(exp, (int, float)):
                    exp = datetime.fromtimestamp(exp, tz=timezone.utc)
                if soonest is None or exp < soonest:
                    soonest = exp
        if soonest:
            break
    return soonest.strftime("%Y-%m-%d") if soonest else None


# ------------------------------------------- IP -> prefix + origin AS + holder
# Team Cymru publishes BGP data over DNS (no API key needed).
#   IP lookup  TXT: "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"
#   AS lookup  TXT: "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"

_origin_cache = {}
_holder_cache = {}


def ip_to_origin(ip):
    """Return (origin ASN, announced prefix) for an IP address."""
    if ip in _origin_cache:
        return _origin_cache[ip]
    addr = ipaddress.ip_address(ip)
    rev = addr.reverse_pointer  # e.g. 4.3.2.1.in-addr.arpa
    if addr.version == 4:
        qname = rev.replace(".in-addr.arpa", "") + ".origin.asn.cymru.com"
    else:
        qname = rev.replace(".ip6.arpa", "") + ".origin6.asn.cymru.com"
    result = (None, None)
    ans = query(qname, "TXT")
    if ans:
        parts = [p.strip() for p in ans[0].to_text().strip('"').split("|")]
        if len(parts) >= 2 and parts[0]:
            result = (int(parts[0].split()[0]), parts[1])  # first AS if several
    _origin_cache[ip] = result
    return result


def asn_holder(asn):
    """Return the organisation that owns an AS number (e.g. 'HETZNER-AS, DE')."""
    if asn in _holder_cache:
        return _holder_cache[asn]
    holder = "UNKNOWN"
    ans = query(f"AS{asn}.asn.cymru.com", "TXT")
    if ans:
        parts = [p.strip() for p in ans[0].to_text().strip('"').split("|")]
        if len(parts) >= 5:
            holder = parts[4]  # the last field is the organisation name
    _holder_cache[asn] = holder
    return holder


# ---------------------------------------------------------------- ROA lookup
# RIPEstat's rpki-validation endpoint checks (origin AS, prefix) against
# today's ROAs and returns the matching ones, including their maxLength.

_roa_cache = {}


def roa_info(asn, prefix):
    """Return (ROA state, ROA maxLength). State is VALID / INVALID / UNKNOWN."""
    key = (asn, prefix)
    if key in _roa_cache:
        return _roa_cache[key]
    url = "https://stat.ripe.net/data/rpki-validation/data.json?" + urllib.parse.urlencode(
        {"resource": f"AS{asn}", "prefix": prefix, "sourceapp": SOURCEAPP}
    )
    out = ("ERROR", None)
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.load(resp)["data"]
        state = data.get("status", "unknown").upper()
        # If several ROAs match, keep the LARGEST maxLength: that is the
        # loosest permission an attacker could exploit.
        maxlen = None
        for roa in data.get("validating_roas", []):
            ml = roa.get("max_length")
            if ml is not None and (maxlen is None or ml > maxlen):
                maxlen = ml
        out = (state, maxlen)
    except Exception as e:
        print(f"  ! RIPEstat failed for AS{asn} {prefix}: {e}", file=sys.stderr)
    time.sleep(0.15)  # be polite to the API
    _roa_cache[key] = out
    return out


# ---------------------------------------------------------- per-domain collect


def collect_domain(domain):
    """Gather every fact about one domain. Returns a list of rows, one per
    server IP (web server or nameserver). Domain-level facts (CAA, DNSSEC,
    signature expiry) are repeated on each row so every row is self-contained."""

    # --- domain-level facts: CAA, DNSSEC, signature expiry -----------------
    caa = query(domain, "CAA")
    caa_text = " ".join(rr.to_text() for rr in caa) if caa else "NONE"

    dnssec = "YES" if query(domain, "DS") else "NO"  # DS record at the parent
    expiry = signature_expiry(domain) or "-"

    # --- list the servers: the website itself + each nameserver -------------
    servers = []  # (ROLE, host, ip)
    for ip in get_ips(domain):
        servers.append(("WEB", domain, ip))
    ns_answer = query(domain, "NS")
    if ns_answer:
        for ns in sorted(rr.target.to_text().rstrip(".").lower() for rr in ns_answer):
            for ip in get_ips(ns):
                servers.append(("NS", ns, ip))

    # --- routing facts for every server --------------------------------------
    rows = []
    for role, host, ip in servers:
        asn, prefix = ip_to_origin(ip)
        if asn and prefix:
            prefix_len = int(prefix.split("/")[1])
            holder = asn_holder(asn)
            roa_state, roa_max = roa_info(asn, prefix)
        else:  # IP is not announced in BGP at all
            prefix_len, holder, roa_state, roa_max = None, "-", "NO ROUTE", None

        # THE KEY CHECK: a ROA whose maxLength is bigger than the announced
        # prefix also authorises more-specific prefixes (e.g. ROA /16 up to
        # /24). An attacker can then announce a forged /24 that still counts
        # as RPKI-valid. This is exactly what happened to Hetzner in August.
        vulnerable = roa_max is not None and prefix_len is not None and roa_max > prefix_len

        rows.append(
            {
                "domain": domain,
                "role": role,
                "host": host,
                "caa": caa_text,
                "dnssec": dnssec,
                "sig_expires": expiry,
                "ip": ip,
                "prefix": prefix or "-",
                "prefix_len": prefix_len,
                "origin_asn": f"AS{asn}" if asn else "-",
                "asn_holder": holder,
                "roa_state": roa_state,
                "roa_max": roa_max if roa_max is not None else "-",
                "vulnerable": vulnerable,
            }
        )
    return rows


# ------------------------------------------------------------------ printing

# (column title, key in the row, column width). Titles are in CAPS.
COLUMNS = [
    ("ROLE", "role", 5),
    ("HOST", "host", 26),
    ("CAA RECORD", "caa", 24),
    ("DNSSEC", "dnssec", 6),
    ("SIG EXPIRES", "sig_expires", 11),
    ("IP", "ip", 39),
    ("PREFIX", "prefix", 22),
    ("ORIGIN ASN", "origin_asn", 10),
    ("ASN HOLDER", "asn_holder", 26),
    ("ROA STATE", "roa_state", 9),
    ("ROA MAX", "roa_max", 7),
]


def cut(text, width):
    """Shorten text to fit its column (adds ~ when it is cut)."""
    text = str(text)
    return text if len(text) <= width else text[: width - 1] + "~"


def format_domain(domain, rows, color):
    """Build the text block for one domain: a header line, then one aligned
    row per server. color=True adds red/bold for the screen; color=False
    gives plain text for the saved file."""
    bold, red, reset = (BOLD, RED, RESET) if color else ("", "", "")
    lines = ["", f"{bold}DOMAIN: {domain.upper()}{reset}"]
    if not rows:
        lines.append("  (NO WEB OR NAMESERVER ADDRESSES FOUND)")
        return "\n".join(lines)
    # column header row
    lines.append("  " + "  ".join(title.ljust(w) for title, _, w in COLUMNS))
    lines.append("  " + "  ".join("-" * w for _, _, w in COLUMNS))
    for r in rows:
        line = "  ".join(cut(r[key], w).ljust(w) for _, key, w in COLUMNS)
        # VULNERABLE goes LAST so the colour codes never shift the columns
        if r["vulnerable"]:
            line += f"  {red}{bold}VULNERABLE{reset}"
        lines.append("  " + line)
    return "\n".join(lines)


# ---------------------------------------------------------------------- main


def main():
    # read domeni.txt: one domain per line, blank lines and #comments skipped
    with open(INPUT, encoding="utf-8") as f:
        domains = [
            line.strip().lower().rstrip(".")
            for line in f
            if line.strip() and not line.startswith("#")
        ]
    print(f"{len(domains)} DOMAINS FROM {INPUT}")

    all_rows = []
    plain_blocks = []  # the same report without colours, for report.txt
    for i, domain in enumerate(domains, 1):
        try:
            rows = collect_domain(domain)
        except Exception as e:  # one bad domain must never stop the whole run
            print(f"\n[{i}/{len(domains)}] {domain}: FAILED ({e})", file=sys.stderr)
            continue
        print(format_domain(domain, rows, color=True))  # coloured, on screen
        plain_blocks.append(format_domain(domain, rows, color=False))
        all_rows += rows

    # --- one-line summary ----------------------------------------------------
    vuln_domains = {r["domain"] for r in all_rows if r["vulnerable"]}
    summary = (
        f"SUMMARY: {len(vuln_domains)} OF {len(domains)} DOMAINS "
        f"HAVE AT LEAST ONE VULNERABLE SERVER (ROA MAX > PREFIX)"
    )
    print()
    print(summary.replace("VULNERABLE", f"{RED}VULNERABLE{RESET}"))

    # --- save the readable report (plain text, no colour codes) -------------
    with open("report.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(plain_blocks) + "\n\n" + summary + "\n")
    print("SAVED: report.txt")


if __name__ == "__main__":
    main()