#!/usr/bin/env python3
"""The lab's certificate authority: one domain-validation decision, every check printed.

python3 /lab/ca.py --config /lab/ca.json --account legit|attacker

Order of checks (what a CA does under the CA/B Baseline Requirements):
  1. DNS through the validating resolver, DO+AD set; SERVFAIL anywhere = fail closed.
  2. CAA tree walk (RFC 8659), `issue` tags with RFC 8657 `accounturi` / `validationmethods` parameters.
  3. HTTP-01 from the primary and every remote perspective (bound to its own source address).
  4. MPIC quorum (CA/B SC-067): the primary must corroborate and at most `max_fail` remotes may not.
Exit 0 = ISSUED, 1 = REFUSED.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

PREFIX = "/.well-known/acme-challenge/"


def log(step: str, msg: str) -> None:
    print(f"[{step:<9}] {msg}", flush=True)


# --------------------------------------------------------------------------- DNS


class FailClosed(Exception):
    """A lookup the CA cannot trust; str(e) is the reason for the REFUSED decision."""


def resolve(resolver: str, name: str, rtype: str, cd: bool = False) -> tuple[str, bool, list[str]]:
    """(rcode, AD flag, rdata texts of the answer RRset of `rtype`); `cd` asks the resolver not to validate."""
    q = dns.message.make_query(name, rtype, want_dnssec=True)
    q.flags |= dns.flags.CD if cd else dns.flags.AD
    try:
        r = dns.query.udp(q, resolver, timeout=5)
    except Exception as e:  # noqa: BLE001
        return f"ERROR {type(e).__name__}", False, []
    rcode = dns.rcode.to_text(r.rcode())
    ad = bool(r.flags & dns.flags.AD)
    records = [rd.to_text() for rr in r.answer if rr.rdtype == dns.rdatatype.from_text(rtype) for rd in rr]
    if cd:
        log("dns", f"{name} {rtype} with CD: {rcode} {records}")
    else:
        log("dns", f"{name} {rtype}: {rcode} ad={int(ad)} {records if records else ''}".rstrip())
    return rcode, ad, records


def diagnose(step: str, resolver: str, name: str, rtype: str, rcode: str) -> FailClosed:
    """Why did the lookup fail? Retry once with CD: an answer means the zone is reachable but DNSSEC-bogus."""
    cd_rcode, _, _ = resolve(resolver, name, rtype, cd=True)
    bogus = cd_rcode == "NOERROR"
    log(
        step,
        f"{name}: {rcode} without CD, {cd_rcode} with CD -> "
        f"{'reachable but DNSSEC-bogus' if bogus else 'unreachable or lame'}",
    )
    return FailClosed(
        "DNSSEC validation failed (reachable but bogus)" if bogus else "DNS failure (unreachable or lame)"
    )


# --------------------------------------------------------------------------- CAA


def parse_caa(records: list[str]) -> list[tuple[int, str, str]]:
    """'0 issue "lab-ca; accounturi=..."' -> (flags, tag, value)."""
    out = []
    for rec in records:
        flags, tag, value = rec.split(" ", 2)
        out.append((int(flags), tag.lower(), value.strip().strip('"')))
    return out


KNOWN_TAGS = ("issue", "issuewild", "iodef")


def caa_allows(records: list[str], ca_id: str, account: str, method: str = "http-01") -> tuple[bool, str]:
    """Does this CAA RRset let `ca_id` issue for `account` by `method`? (RFC 8659 §4, RFC 8657 §3-4)

    Each `issue` record naming `ca_id` is a separate permission: issuance is allowed iff any one of
    them admits this account and method, so one unpinned record beside a pinned one still allows.
    """
    parsed = parse_caa(records)
    for flags, tag, v in parsed:
        if flags & 128 and tag not in KNOWN_TAGS:
            return False, f'critical record "{flags} {tag} {v}" has an unknown tag (RFC 8659 §4.1)'
    issue = [v for _, tag, v in parsed if tag == "issue"]
    if not issue:
        return True, "no issue tag: any CA may issue"
    refusals = []
    for v in issue:
        domain, _, params = v.partition(";")
        if domain.strip() != ca_id:
            continue
        kv = dict(p.strip().split("=", 1) for p in params.split(";") if "=" in p)
        if "accounturi" in kv and kv["accounturi"] != account:
            refusals.append(f"accounturi pins {kv['accounturi']}")
            continue
        if "validationmethods" in kv and method not in [m.strip() for m in kv["validationmethods"].split(",")]:
            refusals.append(f"validationmethods permits only {kv['validationmethods']}")
            continue
        return True, f'issue "{v}" permits {ca_id}' + (f" for {kv['accounturi']}" if "accounturi" in kv else "")
    if refusals:
        return False, "; ".join(refusals)
    return False, f"issue permits only {', '.join(d.partition(';')[0].strip() or '<nobody>' for d in issue)}"


def caa_walk(resolver: str, domain: str) -> tuple[str | None, list[str]]:
    """Climb from `domain` to the root until a CAA RRset exists; raises FailClosed when a lookup fails."""
    labels = domain.rstrip(".").split(".")
    for i in range(len(labels) + 1):
        name = ".".join(labels[i:]) or "."
        rcode, ad, records = resolve(resolver, name, "CAA")
        if rcode not in ("NOERROR", "NXDOMAIN"):
            raise diagnose("caa", resolver, name, "CAA", rcode)
        if records:
            log("caa", f"found at {name} (ad={int(ad)}): {records}")
            return name, records
    log("caa", "no CAA anywhere up to the root")
    return None, []


# --------------------------------------------------------------------------- HTTP-01


def http01(ip: str, host: str, token: str, source: str) -> tuple[int | None, str, str]:
    """(status, X-Lab-Host, body) of GET /.well-known/acme-challenge/<token> from `source`."""
    try:
        with socket.create_connection((ip, 80), timeout=3, source_address=(source, 0)) as s:
            s.sendall(f"GET {PREFIX}{token} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            data = b""
            while chunk := s.recv(4096):
                data += chunk
    except OSError as e:
        return None, "", f"{type(e).__name__}: {e}"
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    status = int(lines[0].split()[1]) if len(lines[0].split()) > 1 else None
    labhost = next((ln.split(":", 1)[1].strip() for ln in lines[1:] if ln.lower().startswith("x-lab-host:")), "?")
    return status, labhost, body.decode(errors="replace")


# --------------------------------------------------------------------------- the decision


def validate(cfg: dict, account_name: str) -> bool:
    domain, resolver, ca_id = cfg["domain"], cfg["resolver"], cfg["id"]
    account, token = cfg["accounts"][account_name], cfg["tokens"][account_name]
    log("request", f"{domain} for account {account} ({account_name}) via http-01, CA {ca_id}")

    try:
        _, records = caa_walk(resolver, domain)
    except FailClosed as e:
        log("decision", f"REFUSED: {e}")
        return False
    ok, why = caa_allows(records, ca_id, account)
    log("caa", f"{'allowed' if ok else 'REFUSED'}: {why}")
    if not ok:
        log("decision", f"REFUSED: CAA forbids this issuance ({why})")
        return False

    rcode, ad, addrs = resolve(resolver, domain, "A")
    if rcode not in ("NOERROR", "NXDOMAIN"):
        log("decision", f"REFUSED: {diagnose('dns', resolver, domain, 'A', rcode)}")
        return False
    if rcode != "NOERROR" or not addrs:
        log("decision", f"REFUSED: {domain} A lookup {rcode} (fail closed)")
        return False
    ip = addrs[0]
    expected = f"{token}.{account}"
    results = {}
    for p in cfg["perspectives"]:
        status, labhost, body = http01(ip, domain, token, p["ip"])
        good = status == 200 and body == expected
        results[p["name"]] = good
        detail = f"HTTP {status} from host '{labhost}'" if status else body
        log(
            "http-01",
            f"{p['name']:<7} behind AS{p['asn']} ({p['ip']}) -> {ip}: {detail}: "
            f"{'corroborates' if good else 'does NOT corroborate'}",
        )
    primary = results.pop("primary")
    remotes_ok = sum(results.values())
    failures = len(results) - remotes_ok
    q = cfg["quorum"]
    quorum = primary and len(results) >= q["min_remote"] and failures <= q["max_fail"]
    log(
        "quorum",
        f"primary {'ok' if primary else 'FAILED'}; remotes {remotes_ok}/{len(results)} corroborate "
        f"(need >= {q['min_remote']} remotes, at most {q['max_fail']} failing): {'met' if quorum else 'NOT met'}",
    )
    if not quorum:
        log("decision", "REFUSED: domain control not demonstrated")
        return False
    log("decision", f"ISSUED: certificate for {domain} to {account}")
    return True


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--config", default="/lab/ca.json")
    p.add_argument("--account", required=True)
    a = p.parse_args()
    cfg = json.load(open(a.config))
    return 0 if validate(cfg, a.account) else 1


if __name__ == "__main__":
    sys.exit(main())
