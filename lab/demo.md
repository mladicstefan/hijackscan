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

`uv run lab/labctl.py matrix` runs every row below and exits 1 if any cell differs from the expected one.
The scanner column is the risk label and score of `hijackscan victim.rs`; the CA columns are the decision of
`ca.py` for the attacker's account during the attack and for the owner's account after it.

| scenario | attack | scanner | CA → attacker | CA → legit (attack off) | expected | ok |
|---|---|---|---|---|---|---|
| baseline | web | open-web (CRITICAL 10.0) | ISSUED | ISSUED | open-web / ISSUED | yes |
| tight-maxlength | web | contested (LOW 1.1) | REFUSED | ISSUED | contested / REFUSED | yes |
| caa-unsigned | web | caa-erasable (HIGH 8.7) | REFUSED | ISSUED | caa-erasable / REFUSED | yes |
| caa-unsigned | web+ns | caa-erasable (HIGH 8.7) | ISSUED | ISSUED | caa-erasable / ISSUED | yes |
| caa-signed | web+ns | closed (NONE 0.0) | REFUSED | ISSUED | closed / REFUSED | yes |

## 5. Reading the CA log

Every check the CA makes prints one line. The baseline, attacker's request, during the web hijack:

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
  Four of five positions were captured, so the quorum is met and the certificate is issued.

### Row 2: tight maxLength

```
[request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
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
refuses the attacker:

```
[dns      ] victim.rs CAA: NOERROR ad=0 ['0 issue "lab-ca; accounturi=https://ca.lab/acct/legit"']
[caa      ] found at victim.rs (ad=0): ['0 issue "lab-ca; accounturi=https://ca.lab/acct/legit"']
[caa      ] REFUSED: accounturi pins https://ca.lab/acct/legit
[decision ] REFUSED: CAA forbids this issuance (accounturi pins https://ca.lab/acct/legit)
```

With the nameserver hijacked as well, the forged zone answers "no CAA" and nothing stops issuance. This is
the scanner's `caa-erasable` class:

```
[dns      ] victim.rs CAA: NOERROR ad=0
[dns      ] rs CAA: NOERROR ad=1
[dns      ] . CAA: NOERROR ad=1
[caa      ] no CAA anywhere up to the root
[caa      ] allowed: no issue tag: any CA may issue
[quorum   ] primary ok; remotes 3/4 corroborate (need >= 4 remotes, at most 1 failing): met
[decision ] ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker
```

### Row 5: CAA with accounturi, zone signed

```
[request  ] victim.rs for account https://ca.lab/acct/attacker (attacker) via http-01, CA lab-ca
[dns      ] victim.rs CAA: SERVFAIL ad=0
[caa      ] victim.rs: SERVFAIL -> cannot evaluate CAA, fail closed
[decision ] REFUSED: DNSSEC validation failed during the CAA lookup (fail closed)
```

The forged zone cannot produce signatures; the resolver, holding the DS from the signed `rs` zone, returns
SERVFAIL and the CA fails closed. This is the project's central claim: CAA account pinning in a signed zone
closes the exposure, and the scanner's `closed` verdict predicted it.

Collateral worth knowing: a validating resolver keeps the bogus verdict for its `val-bogus-ttl` (60 s by
default), so the legitimate owner is also refused for that long after the hijack ends. `attack off` waits it
out before the control run.

## 6. Containment

```
$ uv run lab/labctl.py check
  check: no default route off the fabric
  check: all ASNs private
  check: all BGP neighbours in RFC 5737 space
  check: management network without masquerade
  check: egress probes fail
containment: OK
```

## 7. Tear down

```bash
uv run lab/labctl.py destroy
```
