# hijackscan validation lab: the before/after demo

A sealed containerlab fabric on one machine. One domain, `victim.rs`, hosted in `203.0.113.0/24` by AS65000.
An attacker in AS65010 announces a forged-origin more-specific of that prefix. For each state of the
domain's configuration the demo runs the **real hijackscan scanner** against the lab and then lets a minimal
**certificate authority** try to issue a certificate to the attacker. The scanner's verdict must predict the
CA's decision. Design and the reasoning behind every choice: [`design/lab.md`](../design/lab.md).

Nothing leaves the machine: private ASNs 65000–65100, RFC 5737 addresses only, a locally generated root
trust anchor and ROA set, a management network without masquerade, and every container's management
default route deleted at start. `labctl check` fails the demo if any of that is not true.

**In a hurry?** Section 4 is the key to the transcripts, section 5 the five-row result, section 6 the one
log per row with what to look at. Everything below the tables is the evidence those tables were read from.

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
uv run lab/labctl.py scan                                # the scanner, pre-attack: prints `victim.rs  CRITICAL 10.0  open-web`
uv run lab/labctl.py attack web                          # origin2 announces 203.0.113.0/28 with origin 65000
uv run lab/labctl.py ca attacker                         # the CA tries HTTP-01 for the attacker's account: ISSUED
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

## 4. How to read the transcripts

Every transcript below is made of a few kinds of line. Once these are familiar the logs read quickly; on a
terminal the same lines are coloured (host `attacker` red, `victim` green, `SERVFAIL` yellow, ✔/✘ verdicts).

**The scanner's verdict line**, the first line `labctl scan` prints:

```
victim.rs  CRITICAL 10.0  open-web
   │         │       │      └ the label: what drives the score (open-web, contested, caa-erasable, closed)
   │         │       └ the risk score 0–10
   │         └ the CVSS severity word
   └ the domain
```

The label is what the matrix compares with the CA's decision. `open-web` and `caa-erasable` predict ISSUED
(`caa-erasable` only once the nameserver is hijacked too), `contested` and `closed` predict REFUSED.

**The CA's transcript**, one line per check, in the order a CA makes them under the CA/B Baseline Requirements:

| line | what it shows | what to look at |
|---|---|---|
| `[request  ]` | the domain, the ACME account (`attacker` or `legit`) and the method | which account is asking |
| `[dns      ]` | one lookup through the validating resolver: rcode and the AD flag | `ad=1` validated, `ad=0` unsigned, `SERVFAIL` the resolver refuses to answer (DNSSEC-bogus) |
| `[caa      ]` | the CAA walk `victim.rs` → `rs` → `.` (RFC 8659) and what the `issue` tag allows (RFC 8657) | `no CAA anywhere` (any CA may issue) or `accounturi pins …` (only the owner's account may) |
| `[http-01  ]` | one validation perspective: behind which AS it sits and **which host answered** | `host 'attacker'` = the forged route won that perspective; `host 'victim'` = the real server; `corroborates` = the answer matched the requester's token |
| `[quorum   ]` | the CA/B multi-perspective rule: the primary and at least 3 of 4 remotes must corroborate | `met` or `NOT met` |
| `[decision ]` | `ISSUED` or `REFUSED` and the reason | **this is the line the matrix checks** |

The shape of a decision, in three sentences. A certificate is ISSUED to the attacker only when the primary and
at least three of the four remote perspectives were answered by the attacker; the perspective behind AS65000
(`r3`) is never captured because the forged path carries AS65000 itself and the victim's own router rejects it
(AS-path loop detection), so the baseline's ISSUED rests on exactly the one dissent the quorum tolerates. A
REFUSED can come before any HTTP-01 runs, when CAA or DNSSEC stops the request at the `[caa]` or `[dns]` stage.
A REFUSED after HTTP-01 (`domain control not demonstrated`) means the forged route did not reach enough
perspectives.

**The attack lines** (`*-attack.log`), printed by `labctl attack`:

```
attack web: 203.0.113.0/28 (web) 3 path(s) at the collector: ...     control plane: the forged route, seen 3 times = it passed ROV
attack web: 203.0.113.96/28 (ns) withdrawn                           the nameserver prefix is not hijacked in this mode
attack web: 203.0.113.10 (web) is answered by host 'attacker'        data plane: who really answers at the web address now
attack web: 203.0.113.100 (ns) is answered by host 'victim'          and at the nameserver address
attack web: resolver cache flushed: ...                              the resolver forgets the previous state before the CA asks
attack web: resolver answers victim.rs A with NOERROR                 what the validating resolver now says (SERVFAIL = bogus)
```

A forged route that ROV drops is seen once at the collector (the collector does not validate, like RIS), and
the data plane then stays with the victim; `UNEXPECTED` marks any observation that differs from what the
scenario implies, and the row fails.

**The controls log** (section 8) adds three markers: `######## A. …` opens one control, `-- …` is the
mechanism being removed or restored (a config edit, a route-map, an address, the ROA day), and
`[ok  ] A1 <expectation>  ->  <observed>` is one expectation checked (`[MISS]` if it failed). The indented
CA lines between them are the CA's transcript in that state.

## 5. The matrix

`uv run lab/labctl.py matrix` runs every row below and exits 1 if any cell is not proven. A cell is proven by
four things, all read from captured output: the scanner's label plus a check of the facts it collected (prefix,
RPKI state, ROA maxLength, resolver AD), the data-plane state (who answers the web and nameserver
addresses), the CA's decision line matched against the expected reason, and the host each HTTP-01 perspective
reached. Per-row transcripts live in `lab/logs/<timestamp>-matrix/` (`lab/logs/latest-matrix` points at the newest), the environment in its `manifest.json`.

| scenario | attack | scanner says | CA to the attacker | expected | proven |
|---|---|---|---|---|---|
| baseline | web | open-web (CRITICAL 10.0) | ISSUED | open-web / ISSUED | ✔ yes |
| tight-maxlength | web | contested (LOW 1.1) | REFUSED | contested / REFUSED | ✔ yes |
| caa-unsigned | web | caa-erasable (HIGH 8.7) | REFUSED | caa-erasable / REFUSED | ✔ yes |
| caa-unsigned | web+ns | caa-erasable (HIGH 8.7) | ISSUED | caa-erasable / ISSUED | ✔ yes |
| caa-signed | web+ns | closed (NONE 0.0) | REFUSED | closed / REFUSED | ✔ yes |

<details>
<summary>The full table: data plane, evidence check, the host behind every HTTP-01 perspective, the owner's control run</summary>

| scenario | attack | data plane | scanner | evidence | CA → attacker | HTTP-01 hosts | CA → legit (attack off) | expected | ok |
|---|---|---|---|---|---|---|---|---|---|
| baseline | web | web=attacker ns=victim | open-web (CRITICAL 10.0) | complete | ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker | primary=attacker r1=attacker r2=attacker r3=victim r4=attacker | ISSUED | open-web / ISSUED | yes |
| tight-maxlength | web | web=victim ns=victim | contested (LOW 1.1) | complete | REFUSED: domain control not demonstrated | primary=victim r1=victim r2=attacker r3=victim r4=victim | ISSUED | contested / REFUSED | yes |
| caa-unsigned | web | web=attacker ns=victim | caa-erasable (HIGH 8.7) | complete | REFUSED: CAA forbids this issuance (accounturi pins https://ca.lab/acct/legit) | - | ISSUED | caa-erasable / REFUSED | yes |
| caa-unsigned | web+ns | web=attacker ns=attacker | caa-erasable (HIGH 8.7) | complete | ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker | primary=attacker r1=attacker r2=attacker r3=victim r4=attacker | ISSUED | caa-erasable / ISSUED | yes |
| caa-signed | web+ns | web=attacker ns=attacker | closed (NONE 0.0) | complete | REFUSED: DNSSEC validation failed (reachable but bogus) | - | ISSUED | closed / REFUSED | yes |

</details>

## 6. Reading the CA log, row by row

### Row 1: baseline (`lab/logs/latest-matrix/baseline-web-attacker.log`)

Loose ROA (`/24` with maxLength 28), no CAA, unsigned zone. Look at: the `[caa]` lines find nothing, so any CA
may issue; four of the five `[http-01]` lines say `host 'attacker'`, only `r3` behind the victim's own AS says
`victim`; the quorum is met; ISSUED.

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

### Row 2: tight maxLength (`lab/logs/latest-matrix/tight-maxlength-web-attacker.log`)

One change: ROA maxLength 24. Look at: the same request, but now four `[http-01]` lines say `host 'victim'`
(HTTP 404: the real server does not know the attacker's token) and only `r2`, behind the non-validating
collector, says `attacker`; the primary failed, the quorum is NOT met; REFUSED.

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

### Rows 3 and 4: CAA with accounturi, zone unsigned

With only the web address hijacked, the real nameserver still serves the CAA record and the account pin
refuses the attacker. Look at: the `[dns]` line returns the CAA record, the `[caa]` line says `accounturi pins
…/legit`, and there is no `[http-01]` at all: the CA never got that far
(`lab/logs/latest-matrix/caa-unsigned-web-attacker.log`):

```
[request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
[dns      ] victim.rs CAA: NOERROR ad=0 ['0 issue "lab-ca; accounturi=https://ca.lab/acct/legit"']
[caa      ] found at victim.rs (ad=0): ['0 issue "lab-ca; accounturi=https://ca.lab/acct/legit"']
[caa      ] REFUSED: accounturi pins https://ca.lab/acct/legit
[decision ] REFUSED: CAA forbids this issuance (accounturi pins https://ca.lab/acct/legit)
```

With the nameserver hijacked as well, the forged zone answers "no CAA" and nothing stops issuance. Look at:
the `[dns]` line for `victim.rs CAA` is now empty with `ad=0` (the zone is unsigned, so the resolver cannot
tell a forged nameserver from the real one), `[caa]` finds nothing, and the rest is row 1 again. This is the
scanner's `caa-erasable` class (`lab/logs/latest-matrix/caa-unsigned-web+ns-attacker.log`):

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

Same attack as row 4, but the zone is signed. Look at: the very first `[dns]` line is `SERVFAIL`; the CA asks
once more with the CD bit and gets an answer, so the `[caa]` line says `reachable but DNSSEC-bogus`; REFUSED
after two lookups, no HTTP-01.

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

Collateral worth knowing: a validating resolver keeps the bogus verdict after the hijack ends, so the legitimate
owner is also refused through that resolver for a while. In Unbound the DNSKEY it could not fetch from the forged
nameserver is held for `BOGUS_KEY_TTL`, 60 s hard-coded in `validator/validator.h`; `val-bogus-ttl` does not shorten
it (measured: 63 s). The lab flushes the resolver's cache between steps instead of waiting (`unbound-control
flush_zone`/`flush_bogus`, logged in each `*-attack.log`); `labctl --measure-lockout matrix` times the lockout first.

## 7. Containment (`lab/logs/latest-matrix/baseline-check.log`)

Five checks on the deployed fabric: no default route off it, all ASNs private, all BGP neighbours in RFC 5737
space, management network without masquerade, egress probes fail. One line means all five passed.

```
containment: OK
```

## 8. Negative controls (`lab/logs/latest-controls/controls.log`)

`uv run lab/labctl.py controls` removes, one at a time, the mechanism each matrix verdict rests on and checks
that the verdict flips, then restores it and checks that it flips back. Exit 1 if any expected flip is missing.

| control | mechanism removed | expected flip |
|---|---|---|
| A `caa-signed`, `web+ns` | Unbound's validator module | REFUSED (reachable but bogus) → ISSUED → REFUSED |
| B `tight-maxlength`, `web` | `route-map ROV in` on both transits | the /28 absent from transit2 → present on transit1 as `rpki validation-state: invalid`; REFUSED → ISSUED → REFUSED |
| C `baseline`, `web` | the attacker's address on its interface (hijack still announced) | the feed shows the forged /28 with origin 65000; ISSUED → REFUSED (unreachable) → ISSUED |
| D `baseline` | the ROA day: every maxLength set to the prefix length | scanner `open-web` → `contested` → `open-web` |

Every expectation the last run checked, read from the log below:

| | expectation | observed |
|---|---|---|
| ✔ | A1 validating: REFUSED, reachable but bogus | REFUSED: DNSSEC validation failed (reachable but bogus) |
| ✔ | A2 validation off: ISSUED | ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker |
| ✔ | A3 validating again: REFUSED | REFUSED: DNSSEC validation failed (reachable but bogus) |
| ✔ | B1 transit2 drops 203.0.113.0/28 (ROV) | % Network not in table |
| ✔ | B2 with ROV: REFUSED, domain control not demonstrated | REFUSED: domain control not demonstrated |
| ✔ | B3 transit1 carries 203.0.113.0/28 as rpki invalid | shown |
| ✔ | B4 ROV removed: ISSUED | ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker |
| ✔ | B5 ROV back: REFUSED | REFUSED: domain control not demonstrated |
| ✔ | C1 feed shows the forged more-specific with the victim's origin | {'prefix': '203.0.113.0/28', 'asns': ['65000']} |
| ✔ | C2 attacker serving: ISSUED | ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker |
| ✔ | C3 attacker silent: REFUSED, unreachable | REFUSED: domain control not demonstrated |
| ✔ | C4 address restored: ISSUED | ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker |
| ✔ | D1 ROA day as rendered: open-web | open-web (CRITICAL 10.0) |
| ✔ | D2 tight ROA day: contested | contested (LOW 1.1) |
| ✔ | D3 ROA day restored: open-web | open-web (CRITICAL 10.0) |

<details>
<summary>The full controls log: every CA transcript in every state (markers explained in section 4)</summary>

```
  -- lab already running scenario caa-signed: reused, reset with attack off
negative controls, 2026-11-01T10:49:56+0100
######## A. caa-signed / web+ns: the REFUSED rests on the resolver validating
    [request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
    [dns      ] victim.rs CAA: SERVFAIL ad=0
    [dns      ] victim.rs CAA with CD: NOERROR []
    [caa      ] victim.rs: SERVFAIL without CD, NOERROR with CD -> reachable but DNSSEC-bogus
    [decision ] REFUSED: DNSSEC validation failed (reachable but bogus)
  [ok  ] A1 validating: REFUSED, reachable but bogus  ->  REFUSED: DNSSEC validation failed (reachable but bogus)
  -- module-config: "iterator" in unbound.conf, kill -HUP unbound
  -- resolver reloaded, answers rnids.rs with NOERROR after 0.0s
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
  [ok  ] A2 validation off: ISSUED  ->  ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
  -- validator restored
  -- resolver reloaded, answers rnids.rs with NOERROR ad after 0.0s
    [request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
    [dns      ] victim.rs CAA: SERVFAIL ad=0
    [dns      ] victim.rs CAA with CD: NOERROR []
    [caa      ] victim.rs: SERVFAIL without CD, NOERROR with CD -> reachable but DNSSEC-bogus
    [decision ] REFUSED: DNSSEC validation failed (reachable but bogus)
  [ok  ] A3 validating again: REFUSED  ->  REFUSED: DNSSEC validation failed (reachable but bogus)
######## B. tight-maxlength / web: the REFUSED rests on ROV at the transits
  [ok  ] B1 transit2 drops 203.0.113.0/28 (ROV)  ->  % Network not in table
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
  [ok  ] B2 with ROV: REFUSED, domain control not demonstrated  ->  REFUSED: domain control not demonstrated
  -- no route-map ROV in on transit2<-origin2 and transit1<-transit2, soft out from origin2
  -- ROV off: transit tables settled after 0.6s, 203.0.113.10 answered by 'attacker' after 0.0s
  [ok  ] B3 transit1 carries 203.0.113.0/28 as rpki invalid  ->  shown
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
  [ok  ] B4 ROV removed: ISSUED  ->  ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
  -- route-map ROV restored
  -- ROV on: transit tables settled after 0.6s, 203.0.113.10 answered by 'victim' after 0.0s
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
  [ok  ] B5 ROV back: REFUSED  ->  REFUSED: domain control not demonstrated
######## C. baseline / web: the ISSUED rests on the attacker serving; the feed reads the live table
  -- feed network-info 203.0.113.10 before the attack: {'prefix': '203.0.113.0/24', 'asns': ['65000']}
  [ok  ] C1 feed shows the forged more-specific with the victim's origin  ->  {'prefix': '203.0.113.0/28', 'asns': ['65000']}
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
  [ok  ] C2 attacker serving: ISSUED  ->  ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
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
  [ok  ] C3 attacker silent: REFUSED, unreachable  ->  REFUSED: domain control not demonstrated
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
  [ok  ] C4 address restored: ISSUED  ->  ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
######## D. baseline: the scanner's verdict follows the ROA day it is given
  [ok  ] D1 ROA day as rendered: open-web  ->  open-web (CRITICAL 10.0)
  -- rewrite the ROA day: every maxLength = the prefix length
  [ok  ] D2 tight ROA day: contested  ->  contested (LOW 1.1)
  [ok  ] D3 ROA day restored: open-web  ->  open-web (CRITICAL 10.0)
controls: all expected flips observed
```

</details>

## 9. Tear down

```bash
uv run lab/labctl.py destroy
```
