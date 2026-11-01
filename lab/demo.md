# hijackscan validation lab: the before/after demo

A sealed containerlab fabric on one machine. One domain, `victim.rs`, hosted in `203.0.113.0/24` by AS65000.
An attacker in AS65010 announces a forged-origin more-specific of that prefix. For each state of the
domain's configuration the demo runs the **real hijackscan scanner** against the lab and then lets a minimal
**certificate authority** try to issue a certificate to the attacker. The scanner's verdict must predict the
CA's decision. Design and the reasoning behind every choice: [`design/lab.md`](../design/lab.md).

Nothing leaves the machine: private ASNs 65000–65100, RFC 5737 addresses only, a locally generated root
trust anchor and ROA set, a management network without masquerade, and every container's management
default route deleted at start. `labctl check` fails the demo if any of that is not true.

## 1. Prerequisites (once)

```bash
# containerlab (the AUR package is stale): upstream installer, then membership of both groups
curl -sL https://containerlab.dev/setup | sudo -E bash -s "install-containerlab"
sudo usermod -aG docker,clab_admins "$USER"      # log in again afterwards

uv sync                                            # pyyaml for the generator
docker build -t hijackscan-lab:latest lab/image    # Alpine + unbound, nsd, python3/dnspython, stayrtr
docker pull quay.io/frrouting/frr:10.7.1
ldns-signzone -v                                   # ldns tools on the host sign the lab's zones
```

## 2. What is in the fabric

```
                      rpki (StayRTR, management net) ──RTR 8282──┐
                                                                 ▼
  origin AS65000 ─── transit1 AS65002 ─── transit2 AS65003 ─── origin2 AS65010
  203.0.113.0/24     ROV (RTR)            ROV (RTR)              forged /28s, path "65010 65000"
    │ victim host      │ resolver (Unbound)  │ ca r1               │ attacker host
    │ web .10, ns .100 │ ca primary + r4     │                     │ web .10, ns .100
    │ ca r3            │                     │
    └──────────── collector AS65100 (listen-only, the RIS analogue; runs the RIPEstat-shaped feed) ── ca r2
```

Ten containers: five FRR routers, StayRTR, Unbound, the CA, the victim host and the attacker host. The
CA container has four data-plane links so its five validation perspectives sit behind four different ASes.
Addresses: `design/lab.md` §2.7.

## 3. One row by hand

```bash
uv run lab/labctl.py apply lab/scenarios/baseline.yml   # render every config, deploy, wait for BGP, attack off
uv run lab/labctl.py check                               # containment, exit 1 on any violation
uv run lab/labctl.py scan                                # the scanner, pre-attack
uv run lab/labctl.py attack web                          # origin2 announces 203.0.113.0/28 with origin 65000
uv run lab/labctl.py ca attacker                         # the CA tries HTTP-01 for the attacker's account
uv run lab/labctl.py ca legit                            # the owner's account, during the hijack
uv run lab/labctl.py attack off
uv run lab/labctl.py ca legit                            # the control: the owner gets a certificate again
```

Each scenario file is a one-key diff of `baseline.yml`:

| file | change |
|---|---|
| `tight-maxlength.yml` | `roas[0].max_length: 24` (RFC 9319) |
| `caa-unsigned.yml` | `dns.caa: ['0 issue "lab-ca; accounturi=https://ca.lab/acct/legit"']` (RFC 8657) |
| `caa-signed.yml` | the same CAA plus `dns.signed: true` |

`attack` takes `web` (only the web address is hijacked) or `web+ns` (the nameserver too, the "answer no CAA"
attack). Every `attack` prints the control plane (paths at the collector) and the data plane (which host now
answers at the web and nameserver addresses, seen from the resolver's position).

## 4. The matrix

`uv run lab/labctl.py matrix` runs every row below and exits 1 if any cell is not proven. A cell is proven by
four things, all read from captured output: the scanner's label plus a check of the facts it collected (prefix,
RPKI state, ROA maxLength, resolver AD), the data-plane state (who answers the web and nameserver
addresses), the CA's decision line matched against the expected reason, and the host each HTTP-01 perspective
reached. Per-row transcripts live in `lab/logs/<timestamp>-matrix/` (`lab/logs/latest-matrix` points at the newest), the environment in its `manifest.json`.

| scenario | attack | data plane | scanner | evidence | CA → attacker | HTTP-01 hosts | CA → legit (attack off) | expected | ok |
|---|---|---|---|---|---|---|---|---|---|
| baseline | web | web=attacker ns=victim | open-web (CRITICAL 10.0) | complete | ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker | primary=attacker r1=attacker r2=attacker r3=victim r4=attacker | ISSUED | open-web / ISSUED | yes |
| tight-maxlength | web | web=victim ns=victim | contested (LOW 1.1) | complete | REFUSED: domain control not demonstrated | primary=victim r1=victim r2=attacker r3=victim r4=victim | ISSUED | contested / REFUSED | yes |
| caa-unsigned | web | web=attacker ns=victim | caa-erasable (HIGH 8.7) | complete | REFUSED: CAA forbids this issuance (accounturi pins https://ca.lab/acct/legit) | - | ISSUED | caa-erasable / REFUSED | yes |
| caa-unsigned | web+ns | web=attacker ns=attacker | caa-erasable (HIGH 8.7) | complete | ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker | primary=attacker r1=attacker r2=attacker r3=victim r4=attacker | ISSUED | caa-erasable / ISSUED | yes |
| caa-signed | web+ns | web=attacker ns=attacker | closed (NONE 0.0) | complete | REFUSED: DNSSEC validation failed (reachable but bogus) | - | ISSUED | closed / REFUSED | yes |

## 5. Reading the CA log

Every check the CA makes prints one line. The baseline, attacker's request, during the web hijack
(`lab/logs/latest-matrix/baseline-web-attacker.log`):

```
[request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
[dns      ] victim.rs CAA: NOERROR ad=0
[dns      ] rs CAA: NOERROR ad=1
[dns      ] . CAA: NOERROR ad=1
[caa      ] no CAA anywhere up to the root
[caa      ] allowed: no issue tag: any CA may issue
[dns      ] victim.rs A: NOERROR ad=0 ['203.0.113.10']
[http-01  ] primary behind AS65002 (192.0.2.10) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
[http-01  ] r1      behind AS65003 (192.0.2.18) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
[http-01  ] r2      behind AS65100 (192.0.2.22) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
[http-01  ] r3      behind AS65000 (192.0.2.26) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
[http-01  ] r4      behind AS65002 (192.0.2.11) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
[quorum   ] primary ok; remotes 3/4 corroborate (need >= 4 remotes, at most 1 failing): met
[decision ] ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
```

- `dns` lines show the rcode and the AD flag of every lookup through the validating resolver.
- `caa` walks `victim.rs`, `rs`, `.` (RFC 8659) and applies `issue` tags with their `accounturi` and
  `validationmethods` parameters (RFC 8657).
- `http-01` lines show, per perspective, which host answered (`X-Lab-Host`) and whether the body matched the
  expected key authorization. The perspective behind AS65000 is never captured: the forged path carries
  AS65000 itself, so the victim's own router rejects it by AS-path loop detection.
- `quorum` applies CA/B SC-067: the primary must corroborate and at most one of the four remotes may not.
  Four of five positions were captured, so the quorum is met and the certificate is issued. The baseline's
  "yes" therefore rests on exactly one tolerated dissent (design/lab.md §2.4).

### Row 2: tight maxLength (`lab/logs/latest-matrix/tight-maxlength-web-attacker.log`)

```
[request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
[dns      ] victim.rs CAA: NOERROR ad=0
[dns      ] rs CAA: NOERROR ad=1
[dns      ] . CAA: NOERROR ad=1
[caa      ] no CAA anywhere up to the root
[caa      ] allowed: no issue tag: any CA may issue
[dns      ] victim.rs A: NOERROR ad=0 ['203.0.113.10']
[http-01  ] primary behind AS65002 (192.0.2.10) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
[http-01  ] r1      behind AS65003 (192.0.2.18) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
[http-01  ] r2      behind AS65100 (192.0.2.22) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
[http-01  ] r3      behind AS65000 (192.0.2.26) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
[http-01  ] r4      behind AS65002 (192.0.2.11) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
[quorum   ] primary FAILED; remotes 1/4 corroborate (need >= 4 remotes, at most 1 failing): NOT met
[decision ] REFUSED: domain control not demonstrated
```

The /28 is RPKI-invalid; both transits drop it. Only the collector, which does not validate (like RIS), still
carries it, so the one perspective behind it reaches the attacker. The attacker's primary perspective reaches
the real host, which does not know the attacker's token: refused.

### Row 3 and 4: CAA with accounturi, zone unsigned

With only the web address hijacked, the real nameserver still serves the CAA record and the account pin
refuses the attacker (`lab/logs/latest-matrix/caa-unsigned-web-attacker.log`):

```
[request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
[dns      ] victim.rs CAA: NOERROR ad=0 ['0 issue "lab-ca; accounturi=https://ca.lab/acct/legit"']
[caa      ] found at victim.rs (ad=0): ['0 issue "lab-ca; accounturi=https://ca.lab/acct/legit"']
[caa      ] REFUSED: accounturi pins https://ca.lab/acct/legit
[decision ] REFUSED: CAA forbids this issuance (accounturi pins https://ca.lab/acct/legit)
```

With the nameserver hijacked as well, the forged zone answers "no CAA" and nothing stops issuance. This is
the scanner's `caa-erasable` class (`lab/logs/latest-matrix/caa-unsigned-web+ns-attacker.log`):

```
[request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
[dns      ] victim.rs CAA: NOERROR ad=0
[dns      ] rs CAA: NOERROR ad=1
[dns      ] . CAA: NOERROR ad=1
[caa      ] no CAA anywhere up to the root
[caa      ] allowed: no issue tag: any CA may issue
[dns      ] victim.rs A: NOERROR ad=0 ['203.0.113.10']
[http-01  ] primary behind AS65002 (192.0.2.10) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
[http-01  ] r1      behind AS65003 (192.0.2.18) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
[http-01  ] r2      behind AS65100 (192.0.2.22) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
[http-01  ] r3      behind AS65000 (192.0.2.26) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
[http-01  ] r4      behind AS65002 (192.0.2.11) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
[quorum   ] primary ok; remotes 3/4 corroborate (need >= 4 remotes, at most 1 failing): met
[decision ] ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
```

### Row 5: CAA with accounturi, zone signed (`lab/logs/latest-matrix/caa-signed-web+ns-attacker.log`)

```
[request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
[dns      ] victim.rs CAA: SERVFAIL ad=0
[dns      ] victim.rs CAA with CD: NOERROR []
[caa      ] victim.rs: SERVFAIL without CD, NOERROR with CD -> reachable but DNSSEC-bogus
[decision ] REFUSED: DNSSEC validation failed (reachable but bogus)
```

The forged zone cannot produce signatures; the resolver, holding the DS from the signed `rs` zone, returns
SERVFAIL. The CA asks once more with the CD bit: an answer now means the zone is reachable but DNSSEC-bogus
(an unreachable or lame zone fails both ways), and it fails closed either way. This is the project's central
claim: CAA account pinning in a signed zone closes the exposure, and the scanner's `closed` verdict predicted it.

Collateral worth knowing: a validating resolver keeps the bogus verdict for its `val-bogus-ttl` (60 s by
default), so the legitimate owner is also refused for that long after the hijack ends. `attack off` waits it
out before the control run.

## 6. Containment (`lab/logs/latest-matrix/baseline-check.log`)

```
containment: OK
```

## 7. Negative controls (`lab/logs/latest-controls/controls.log`)

`uv run lab/labctl.py controls` removes, one at a time, the mechanism each matrix verdict rests on and checks
that the verdict flips, then restores it and checks that it flips back. Exit 1 if any expected flip is missing.

```
negative controls, 2026-11-01T00:39:50+0100
######## A. caa-signed / web+ns: the REFUSED rests on the resolver validating
    [request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
    [dns      ] victim.rs CAA: SERVFAIL ad=0
    [dns      ] victim.rs CAA with CD: NOERROR []
    [caa      ] victim.rs: SERVFAIL without CD, NOERROR with CD -> reachable but DNSSEC-bogus
    [decision ] REFUSED: DNSSEC validation failed (reachable but bogus)
  [ok  ] A1 validating: REFUSED, reachable but bogus: REFUSED: DNSSEC validation failed (reachable but bogus)
  -- module-config: "iterator" in unbound.conf, kill -HUP unbound
    [request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
    [dns      ] victim.rs CAA: NOERROR ad=0
    [dns      ] rs CAA: NOERROR ad=0
    [dns      ] . CAA: NOERROR ad=0
    [caa      ] no CAA anywhere up to the root
    [caa      ] allowed: no issue tag: any CA may issue
    [dns      ] victim.rs A: NOERROR ad=0 ['203.0.113.10']
    [http-01  ] primary behind AS65002 (192.0.2.10) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [http-01  ] r1      behind AS65003 (192.0.2.18) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [http-01  ] r2      behind AS65100 (192.0.2.22) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [http-01  ] r3      behind AS65000 (192.0.2.26) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
    [http-01  ] r4      behind AS65002 (192.0.2.11) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [quorum   ] primary ok; remotes 3/4 corroborate (need >= 4 remotes, at most 1 failing): met
    [decision ] ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
  [ok  ] A2 validation off: ISSUED: ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
  -- validator restored
    [request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
    [dns      ] victim.rs CAA: SERVFAIL ad=0
    [dns      ] victim.rs CAA with CD: NOERROR []
    [caa      ] victim.rs: SERVFAIL without CD, NOERROR with CD -> reachable but DNSSEC-bogus
    [decision ] REFUSED: DNSSEC validation failed (reachable but bogus)
  [ok  ] A3 validating again: REFUSED: REFUSED: DNSSEC validation failed (reachable but bogus)
######## B. tight-maxlength / web: the REFUSED rests on ROV at the transits
  [ok  ] B1 transit2 drops 203.0.113.0/28 (ROV): % Network not in table
    [request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
    [dns      ] victim.rs CAA: NOERROR ad=0
    [dns      ] rs CAA: NOERROR ad=1
    [dns      ] . CAA: NOERROR ad=1
    [caa      ] no CAA anywhere up to the root
    [caa      ] allowed: no issue tag: any CA may issue
    [dns      ] victim.rs A: NOERROR ad=0 ['203.0.113.10']
    [http-01  ] primary behind AS65002 (192.0.2.10) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
    [http-01  ] r1      behind AS65003 (192.0.2.18) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
    [http-01  ] r2      behind AS65100 (192.0.2.22) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [http-01  ] r3      behind AS65000 (192.0.2.26) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
    [http-01  ] r4      behind AS65002 (192.0.2.11) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
    [quorum   ] primary FAILED; remotes 1/4 corroborate (need >= 4 remotes, at most 1 failing): NOT met
    [decision ] REFUSED: domain control not demonstrated
  [ok  ] B2 with ROV: REFUSED, domain control not demonstrated: REFUSED: domain control not demonstrated
  -- no route-map ROV in on transit2<-origin2 and transit1<-transit2, soft out from origin2
  [ok  ] B3 transit1 carries 203.0.113.0/28 as rpki invalid: shown
    [request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
    [dns      ] victim.rs CAA: NOERROR ad=0
    [dns      ] rs CAA: NOERROR ad=1
    [dns      ] . CAA: NOERROR ad=1
    [caa      ] no CAA anywhere up to the root
    [caa      ] allowed: no issue tag: any CA may issue
    [dns      ] victim.rs A: NOERROR ad=0 ['203.0.113.10']
    [http-01  ] primary behind AS65002 (192.0.2.10) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [http-01  ] r1      behind AS65003 (192.0.2.18) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [http-01  ] r2      behind AS65100 (192.0.2.22) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [http-01  ] r3      behind AS65000 (192.0.2.26) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
    [http-01  ] r4      behind AS65002 (192.0.2.11) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [quorum   ] primary ok; remotes 3/4 corroborate (need >= 4 remotes, at most 1 failing): met
    [decision ] ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
  [ok  ] B4 ROV removed: ISSUED: ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
  -- route-map ROV restored
    [request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
    [dns      ] victim.rs CAA: NOERROR ad=0
    [dns      ] rs CAA: NOERROR ad=1
    [dns      ] . CAA: NOERROR ad=1
    [caa      ] no CAA anywhere up to the root
    [caa      ] allowed: no issue tag: any CA may issue
    [dns      ] victim.rs A: NOERROR ad=0 ['203.0.113.10']
    [http-01  ] primary behind AS65002 (192.0.2.10) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
    [http-01  ] r1      behind AS65003 (192.0.2.18) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
    [http-01  ] r2      behind AS65100 (192.0.2.22) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [http-01  ] r3      behind AS65000 (192.0.2.26) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
    [http-01  ] r4      behind AS65002 (192.0.2.11) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
    [quorum   ] primary FAILED; remotes 1/4 corroborate (need >= 4 remotes, at most 1 failing): NOT met
    [decision ] REFUSED: domain control not demonstrated
  [ok  ] B5 ROV back: REFUSED: REFUSED: domain control not demonstrated
######## C. baseline / web: the ISSUED rests on the attacker serving; the feed reads the live table
  -- feed network-info 203.0.113.10 before the attack: {'prefix': '203.0.113.0/24', 'asns': ['65000']}
  [ok  ] C1 feed shows the forged more-specific with the victim's origin: {'prefix': '203.0.113.0/28', 'asns': ['65000']}
    [request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
    [dns      ] victim.rs CAA: NOERROR ad=0
    [dns      ] rs CAA: NOERROR ad=1
    [dns      ] . CAA: NOERROR ad=1
    [caa      ] no CAA anywhere up to the root
    [caa      ] allowed: no issue tag: any CA may issue
    [dns      ] victim.rs A: NOERROR ad=0 ['203.0.113.10']
    [http-01  ] primary behind AS65002 (192.0.2.10) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [http-01  ] r1      behind AS65003 (192.0.2.18) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [http-01  ] r2      behind AS65100 (192.0.2.22) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [http-01  ] r3      behind AS65000 (192.0.2.26) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
    [http-01  ] r4      behind AS65002 (192.0.2.11) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [quorum   ] primary ok; remotes 3/4 corroborate (need >= 4 remotes, at most 1 failing): met
    [decision ] ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
  [ok  ] C2 attacker serving: ISSUED: ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
  -- ip addr del 203.0.113.10/28 dev eth1 on the attacker (hijack still announced)
    [request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
    [dns      ] victim.rs CAA: NOERROR ad=0
    [dns      ] rs CAA: NOERROR ad=1
    [dns      ] . CAA: NOERROR ad=1
    [caa      ] no CAA anywhere up to the root
    [caa      ] allowed: no issue tag: any CA may issue
    [dns      ] victim.rs A: NOERROR ad=0 ['203.0.113.10']
    [http-01  ] primary behind AS65002 (192.0.2.10) -> 203.0.113.10: OSError: [Errno 113] Host is unreachable: does NOT corroborate
    [http-01  ] r1      behind AS65003 (192.0.2.18) -> 203.0.113.10: OSError: [Errno 113] Host is unreachable: does NOT corroborate
    [http-01  ] r2      behind AS65100 (192.0.2.22) -> 203.0.113.10: OSError: [Errno 113] Host is unreachable: does NOT corroborate
    [http-01  ] r3      behind AS65000 (192.0.2.26) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
    [http-01  ] r4      behind AS65002 (192.0.2.11) -> 203.0.113.10: OSError: [Errno 113] Host is unreachable: does NOT corroborate
    [quorum   ] primary FAILED; remotes 0/4 corroborate (need >= 4 remotes, at most 1 failing): NOT met
    [decision ] REFUSED: domain control not demonstrated
  [ok  ] C3 attacker silent: REFUSED, unreachable: REFUSED: domain control not demonstrated
    [request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
    [dns      ] victim.rs CAA: NOERROR ad=0
    [dns      ] rs CAA: NOERROR ad=1
    [dns      ] . CAA: NOERROR ad=1
    [caa      ] no CAA anywhere up to the root
    [caa      ] allowed: no issue tag: any CA may issue
    [dns      ] victim.rs A: NOERROR ad=0 ['203.0.113.10']
    [http-01  ] primary behind AS65002 (192.0.2.10) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [http-01  ] r1      behind AS65003 (192.0.2.18) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [http-01  ] r2      behind AS65100 (192.0.2.22) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [http-01  ] r3      behind AS65000 (192.0.2.26) -> 203.0.113.10: HTTP 404 from host 'victim': does NOT corroborate
    [http-01  ] r4      behind AS65002 (192.0.2.11) -> 203.0.113.10: HTTP 200 from host 'attacker': corroborates
    [quorum   ] primary ok; remotes 3/4 corroborate (need >= 4 remotes, at most 1 failing): met
    [decision ] ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
  [ok  ] C4 address restored: ISSUED: ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
######## D. baseline: the scanner's verdict follows the ROA day it is given
  [ok  ] D1 ROA day as rendered: open-web: open-web (CRITICAL 10.0)
  -- rewrite the ROA day: every maxLength = the prefix length
  [ok  ] D2 tight ROA day: contested: contested (LOW 1.1)
  [ok  ] D3 ROA day restored: open-web: open-web (CRITICAL 10.0)
controls: all expected flips observed
```

## 8. Tear down

```bash
uv run lab/labctl.py destroy
```
