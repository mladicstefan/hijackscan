"""Prove the configured resolver validates before trusting a single AD bit from it."""

from __future__ import annotations

from .dns import Dns

SIGNED_ZONE = "rnids.rs"  # the .rs registry's own name, DNSSEC-signed
BOGUS_ZONE = "dnssec-failed.org"  # deliberately broken signatures; a validator must SERVFAIL


def check_resolver(dns_: Dns) -> dict:
    signed = dns_.query(SIGNED_ZONE, "A")
    bogus = dns_.query(BOGUS_ZONE, "A")
    return {
        "resolver": dns_.address,
        "signed_zone": SIGNED_ZONE,
        "signed_ok": signed.rcode == "NOERROR" and signed.ad,
        "bogus_zone": BOGUS_ZONE,
        "bogus_servfail": bogus.rcode == "SERVFAIL",
    }


def passes(result: dict) -> bool:
    return bool(result["signed_ok"] and result["bogus_servfail"])
