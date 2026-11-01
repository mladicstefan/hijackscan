"""The lab's DNS tree: a local root with its trust anchor, `rs` and `org`, the victim zone (signed or not), the forgery.

Served by Unbound auth-zones on the resolver (root, rs, org, dnssec-failed.org: never reachable through the
fabric) and by NSD on the victim and attacker hosts (victim.rs). `rnids.rs` and `dnssec-failed.org` exist
because hijackscan's collector refuses a resolver that does not return AD for the first and SERVFAIL for the
second (collect/resolver_check.py).
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype

from hijackscan.collect.resolver_check import BOGUS_ZONE, SIGNED_ZONE

from .topology import RESOLVER_IP

TTL = 5  # seconds: scenario rows change zone content, the resolver must not serve the previous row
CONTROL_SOCKET = "/run/unbound.ctl"  # unbound-control socket inside the resolver container (labctl.flush_resolver)
NS_NAME = "ns.lab."  # the in-root name of the resolver's own authoritative side
SOA = f"@ {TTL} IN SOA {NS_NAME} hostmaster.lab. {{serial}} 300 60 86400 {TTL}"
# Signature validity is a fixed window, not "now + 30 days": two renders of one scenario must differ only in
# key material, so that a build can be diffed against a reference build.
INCEPTION = "20260101000000"
EXPIRATION = "20271231235959"


def zone_serial(scenario_name: str) -> int:
    """SOA serial from the scenario name: deterministic, 28 bits (within the 32-bit serial space)."""
    return int(hashlib.sha256(scenario_name.encode()).hexdigest()[:7], 16)


def _zone(origin: str, records: list[str], serial: int) -> str:
    return "\n".join([f"$ORIGIN {origin}", f"$TTL {TTL}", SOA.format(serial=serial), *records]) + "\n"


def _keygen(keys: Path, name: str) -> Path:
    """ECDSA P-256 CSK (KSK flag, used for every RRset); returns the key base path (no extension)."""
    r = subprocess.run(
        ["ldns-keygen", "-a", "ECDSAP256SHA256", "-k", "-r", "/dev/urandom", name],
        cwd=keys,
        capture_output=True,
        text=True,
        check=True,
    )
    return keys / r.stdout.strip()


def _dnskey_line(keybase: Path) -> str:
    # not Path.with_suffix: the key id "+013+12345" would be taken for a suffix
    return next(line for line in Path(f"{keybase}.key").read_text().splitlines() if "DNSKEY" in line)


def _ds(keybase: Path, name: str, *, corrupt: bool = False) -> str:
    """`<name>. DS ...` SHA-256 from the key file; `corrupt` flips the first digest hex digit (bogus chain)."""
    line = _dnskey_line(keybase)
    rdata_text = line.split("DNSKEY", 1)[1].strip()
    key = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, rdata_text)
    ds = dns.dnssec.make_ds(dns.name.from_text(name), key, "SHA256")
    text = ds.to_text()
    if corrupt:
        digest = text.split()[-1]
        flipped = ("0" if digest[0] != "0" else "1") + digest[1:]
        text = text.replace(digest, flipped)
    return f"{name} {TTL} IN DS {text}"


def _sign(unsigned: Path, origin: str, keybase: Path, signed: Path) -> None:
    window = ["-i", INCEPTION, "-e", EXPIRATION]
    subprocess.run(
        ["ldns-signzone", "-o", origin, *window, "-f", str(signed), str(unsigned), str(keybase)],
        check=True,
        capture_output=True,
        text=True,
    )


def _write_zone(d: Path, origin: str, records: list[str], keybase: Path | None, serial: int) -> Path:
    """Write <d>/<file>.zone; signed with `keybase` when given (the unsigned text stays beside it)."""
    stem = "root" if origin == "." else origin.rstrip(".")
    out = d / f"{stem}.zone"
    if keybase is None:
        out.write_text(_zone(origin, records, serial))
    else:
        unsigned = d / f"{stem}.unsigned"
        unsigned.write_text(_zone(origin, records, serial))
        _sign(unsigned, origin, keybase, out)
    return out


def render_dns(sc: dict, build: Path) -> None:
    for tool in ("ldns-keygen", "ldns-signzone"):
        if not shutil.which(tool):
            raise SystemExit(
                f"{tool} not found: install the ldns tools "
                "(Debian/Ubuntu: sudo apt install ldnsutils; Arch: pacman -S ldns)"
            )
    keys = build / "dns" / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    zones = build / "resolver" / "zones"
    zones.mkdir(parents=True, exist_ok=True)
    domain = sc["domain"]
    victim, attacker = build / "victim", build / "attacker"
    victim.mkdir(exist_ok=True)
    attacker.mkdir(exist_ok=True)

    serial = zone_serial(sc["name"])

    k_root, k_rs, k_org, k_failed = (_keygen(keys, n) for n in (".", "rs", "org", BOGUS_ZONE))
    k_victim = _keygen(keys, domain) if sc["dns"]["signed"] else None

    # --- the victim zone (NSD on the victim host) and the attacker's forgery (NSD on the attacker host)
    web, ns_ip = sc["victim"]["web"], sc["victim"]["ns"]
    base = [f"@ NS ns1.{domain}.", f"ns1 A {ns_ip}", f"@ A {web}", f"www A {web}"]
    caa = [f"@ CAA {c}" for c in sc["dns"]["caa"]]
    _write_zone(victim, f"{domain}.", base + caa, k_victim, serial)
    _write_zone(attacker, f"{domain}.", base, None, serial)  # no CAA, no signatures: the "no CAA here" answer
    for host in (victim, attacker):
        # Bound to the nameserver address: a wildcard socket answers from the interface's primary address, which
        # is the web address here, and the resolver drops such replies. ip-freebind because containerlab adds
        # the address after NSD has started.
        (host / "nsd.conf").write_text(
            f"server:\n  ip-address: {ns_ip}\n  ip-address: 127.0.0.1\n  ip-freebind: yes\n  do-ip6: no\n"
            f"  identity: {host.name}\n"
            '  verbosity: 1\n  zonesdir: /lab\n  pidfile: ""\n'
            f"zone:\n  name: {domain}\n  zonefile: {domain}.zone\n"
        )

    # --- the parents, served only on the resolver
    ds_victim = [_ds(k_victim, f"{domain}.")] if k_victim else []
    _write_zone(
        zones,
        "rs.",
        [
            f"@ NS {NS_NAME}",
            f"{SIGNED_ZONE}. A {RESOLVER_IP}",
            f"{domain}. NS ns1.{domain}.",
            f"ns1.{domain}. A {ns_ip}",
            *ds_victim,
        ],
        k_rs,
        serial,
    )
    _write_zone(zones, f"{BOGUS_ZONE}.", [f"@ NS {NS_NAME}", f"@ A {RESOLVER_IP}"], k_failed, serial)
    _write_zone(
        zones,
        "org.",
        [f"@ NS {NS_NAME}", f"{BOGUS_ZONE}. NS {NS_NAME}", _ds(k_failed, f"{BOGUS_ZONE}.", corrupt=True)],
        k_org,
        serial,
    )
    _write_zone(
        zones,
        ".",
        [
            f"@ NS {NS_NAME}",
            f"{NS_NAME} A {RESOLVER_IP}",
            f"rs. NS {NS_NAME}",
            f"org. NS {NS_NAME}",
            _ds(k_rs, "rs."),
            _ds(k_org, "org."),
        ],
        k_root,
        serial,
    )
    (build / "resolver" / "root.key").write_text(_dnskey_line(k_root) + "\n")
    (build / "resolver" / "unbound.conf").write_text(UNBOUND)


UNBOUND = f"""\
# generated by lab/render/dns.py
server:
  verbosity: 1
  use-syslog: no
  logfile: ""
  do-daemonize: no
  username: ""
  chroot: ""
  directory: "/lab"
  pidfile: ""
  interface: 0.0.0.0
  do-ip6: no
  access-control: 0.0.0.0/0 allow
  module-config: "validator iterator"
  trust-anchor-file: "/lab/root.key"
  val-log-level: 2
  cache-max-ttl: 5
  cache-max-negative-ttl: 5
  infra-host-ttl: 10
  val-bogus-ttl: 5
  infra-keep-probing: yes
  serve-expired: no
  harden-dnssec-stripped: yes
  qname-minimisation: no
# labctl flushes the cache between steps (flush_zone, flush_bogus) instead of waiting out TTLs: Unbound keeps a
# key it could not fetch for BOGUS_KEY_TTL (60 s, validator.h, not val-bogus-ttl). Unix socket, no certificates.
remote-control:
  control-enable: yes
  control-interface: "{CONTROL_SOCKET}"
  control-use-cert: no
auth-zone:
  name: "."
  zonefile: "/lab/zones/root.zone"
  for-upstream: yes
  for-downstream: no
auth-zone:
  name: "rs"
  zonefile: "/lab/zones/rs.zone"
  for-upstream: yes
  for-downstream: no
auth-zone:
  name: "org"
  zonefile: "/lab/zones/org.zone"
  for-upstream: yes
  for-downstream: no
auth-zone:
  name: "{BOGUS_ZONE}"
  zonefile: "/lab/zones/{BOGUS_ZONE}.zone"
  for-upstream: yes
  for-downstream: no
"""
