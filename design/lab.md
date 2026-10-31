# Containerlab validation lab: design decisions

Status: design, 2026-10-31. Spec: `.claude/prompt.md` (the build prompt). This file records what the
prompt left open and where the implementation deviates from it, and why.

## 1. What the lab proves

One domain, `victim.rs`, hosted in `203.0.113.0/24` (AS65000), under four scenario states. For each
state the real scanner is run against the lab (through its two existing data seams: a RIPEstat-shaped
feed and a local ROA archive day) and a minimal CA tries to issue a certificate to an attacker who has
hijacked a more-specific of the victim's prefix. The scanner's verdict must predict the CA's decision.

## 2. Decisions

### 2.1 The attack is a forged-origin more-specific (path `65010 65000`)

The prompt says the /28 is "originated by AS65010". A /28 with origin 65010 is RPKI-invalid even at
maxLength 28, because the ROA names AS65000. The condition under test is the Hetzner one: the attacker
announces the more-specific with the victim's AS appended (`set as-path prepend 65000` on origin-2's
export), so the route is RPKI-valid wherever maxLength allows the length. ROV therefore stays **on**
in every row (scenario key `rov: true`); the baseline shows a valid more-specific passing ROV, and the
maxLength change alone flips the result. The prompt's "ROV off in the baseline" would prove less.

### 2.2 The attack is a toggle; the scanner scans the pre-attack state

The feed reads the route-collector's live table (`vtysh show bgp ... json`), exactly as RIPEstat reads
RIS. If the /28 is live while the scanner runs, `network-info` returns the /28 itself and the scanner
sees nothing more specific to forge. That is correct behaviour (a scan during a hijack reports the
hijacked state), but the matrix measures what the scanner says *before* the attack. So each row runs:

    lab apply <scenario>     render configs, deploy (or redeploy) the fabric, attack off
    lab scan                 the scanner, pre-attack, via the lab resolver + feed + ROA day
    lab attack web|web+ns    origin-2 announces the more-specific(s)
    lab ca attacker          the CA tries HTTP-01 for the attacker's account
    lab attack off

`lab matrix` runs all rows and prints the table. The scenario key `attacker.announce` holds the
rendered initial state (empty by default); `lab attack` changes it live through vtysh.

### 2.3 Two more-specifics: web and nameserver

With the web host and the nameserver in the same /28, the attacker always captures both and the
"CAA in an unsigned zone" row cannot be told apart from the signed one at the CA. So:

| Address | Role | Hijacked by |
|---|---|---|
| 203.0.113.10 | web (HTTP-01 target) | `203.0.113.0/28` |
| 203.0.113.100 | `ns1.victim.rs` | `203.0.113.96/28` |

`lab attack web` announces the first, `lab attack web+ns` both. The parent zones (root, `rs`, `org`)
are served on the resolver node itself (Unbound `auth-zone`), so the attacker can never capture the
parent; only the delegation `victim.rs` is reachable through the fabric.

### 2.4 Validation matrix (extends the prompt's table)

| State | Attack | Scanner (exposure class) | CA issues to attacker? |
|---|---|---|---|
| baseline: maxLength 28, unsigned, no CAA | web | open | yes |
| tight maxLength 24 (RFC 9319) | web | contested-only (not forgeable) | no: /28 RPKI-invalid, dropped |
| CAA accounturi, unsigned | web | caa-erasable | no: CAA from the real NS refuses the account |
| CAA accounturi, unsigned | web+ns | caa-erasable | **yes**: forged NS answers "no CAA" |
| CAA accounturi, signed | web+ns | closed | no: resolver returns SERVFAIL (bogus), CA fails closed |

The legitimate account is run as a control in every row and must always be issued. "Not forgeable"
in the prompt is the scanner's `contested-only` class (nothing more specific can be forged; the
exact-prefix contest remains, which the scanner always reports absent ASPA). ASPA is out of scope
(prompt §"ASPA is deliberately out of scope").

The baseline's "yes" relies on exactly one tolerated dissent: `r3` (behind the victim's own AS, §2.5) never
sees the forgery, and the quorum in force today (4 remotes, at most 1 non-corroborating) absorbs exactly that
one. A second immune remote, or `max_fail: 0`, would flip the row to "no" without any defence being deployed.

### 2.5 Five perspectives from one CA container, on four links

A single CA container with one interface would give five perspectives the same route, and the SC-067
quorum would never be exercised. Separate perspective containers would add five nodes. Middle ground:
the `ca` container has four data-plane links, one behind each of AS65002 (primary + remote `r4` as a
secondary address), AS65003 (`r1`), AS65100 (`r2`) and AS65000 (`r3`). Each remote binds its source
address and a per-source policy-routing table sends it out of its own link. The five positions are not
equivalent, and the matrix depends on that:

- `primary` and `r4` share the transit1 link: same AS (65002), same route. `r4` is a second vote from the
  primary's position, not a second vantage point; it exists to reach the four remotes the quorum needs.
- `r1` sits behind transit2 (AS65003), the other validating transit.
- `r2` sits behind the collector (AS65100), which never filters (like RIS): it is captured whenever origin2
  announces, RPKI-valid or not.
- `r3` sits behind the victim's own AS65000 and is never captured: the forged path `… 65010 65000` contains
  that AS, so AS65000 rejects it by AS-path loop detection and keeps routing to its own host, whatever the
  ROA says.

So ROV decides only two positions, primary/`r4` and `r1`. In the baseline row (/28 RPKI-valid) they are
captured along with `r2`, `r3` dissents, and one dissent is what SC-067 tolerates, so the CA still issues:
the demo shows MPIC working as specified and still not helping. In the tight-maxLength row (/28 invalid)
they keep the victim, so the primary itself is not fooled and nothing is issued, with `r2` captured
regardless. The log shows each perspective's verdict. A partial row (ROV on one transit only) would split
primary/`r4` from `r1` and can be added later as a scenario.

The quorum (`min_remote`, `max_fail` in `ca.json`) is not a lab constant: `render/hosts.py` takes it from
`RiskParams.for_date(today)` in `src/hijackscan/risk.py`, so the lab CA and the scanner apply the same
BR 3.2.2.9 numbers (4 remotes / 1 dissent since 2026-06-15). From 2026-12-15 five remotes are required and
`render` refuses to run until an `r5` perspective is added to `topology.py`, rather than silently passing.

### 2.6 Nodes (ten, not nine)

The FRR image has no DNS server, and the feed must read the collector's table. So:

| Node | Image | Role |
|---|---|---|
| origin (AS65000) | FRR 10.7.1 | announces 203.0.113.0/24 and 192.0.2.24/30 |
| transit1 (AS65002), transit2 (AS65003) | FRR | ROV (`match rpki invalid` deny), RTR to `rpki` |
| origin2 (AS65010) | FRR | announces the /28s with `65000` appended, when told to |
| collector (AS65100) | FRR | peers with all four, exports only its CA link 192.0.2.20/30; runs `feed.py` |
| rpki | rpki/stayrtr | serves `rpki.json` over RTR (port 8282, management network) |
| resolver | lab image | Unbound, local root trust anchor, auth-zones for root/rs/org |
| ca | lab image | `ca.py`, four links, policy routing |
| victim | lab image | NSD (`victim.rs`) + `web.py` on .10/.100, behind origin |
| attacker | lab image | NSD (forged `victim.rs`, no CAA) + `web.py` on .10/.100 of the /28s, behind origin2 |

The lab image is `alpine:3.22 + unbound nsd python3 py3-dnspython bind-tools curl`, built locally.

### 2.7 Addressing

Inter-AS links (198.51.100.0/24, /30 each, router listed first):

| Link | Subnet | A | B |
|---|---|---|---|
| origin–transit1 | .0/30 | origin .1 | transit1 .2 |
| transit1–transit2 | .4/30 | transit1 .5 | transit2 .6 |
| transit2–origin2 | .8/30 | transit2 .9 | origin2 .10 |
| origin–collector | .12/30 | origin .13 | collector .14 |
| transit1–collector | .16/30 | transit1 .17 | collector .18 |
| transit2–collector | .20/30 | transit2 .21 | collector .22 |
| origin2–collector | .24/30 | origin2 .25 | collector .26 |

Service links (192.0.2.0/24), each announced by its router:

| Link | Subnet | Router | Host |
|---|---|---|---|
| transit1–resolver | .0/30 | transit1 .1 | resolver .2 |
| transit1–ca (primary, r4) | .8/29 | transit1 .9 | ca .10, .11 |
| transit2–ca (r1) | .16/30 | transit2 .17 | ca .18 |
| collector–ca (r2) | .20/30 | collector .21 | ca .22 |
| origin–ca (r3) | .24/30 | origin .25 | ca .26 |

Victim LAN: origin 203.0.113.1/24, victim 203.0.113.10 and .100. Attacker link: origin2
203.0.113.1/28 + .97/28, attacker 203.0.113.10/28 + .100/28.

The scenario file repeats the ASes and these host addresses (`victim.asn/prefix/web/ns`, `attacker.asn`,
`attacker.more_specifics`, `transits`, `collector`) because the scanner reads them from its output; `render`
checks them against the tables above and refuses a scenario that disagrees, listing every mismatch
(`render/__init__.py: check_topology`).

Management network `172.31.40.0/24`, masquerade off, fixed addresses per node; the RTR session and the
scanner's access to the resolver (port 53) and feed (port 8080) use it. Every node's management default
route is deleted at start, so no container holds a route off the box; hosts get a default via their
in-fabric router instead.

### 2.8 Scanner wiring (the only scanner changes)

- `Config.routable_cap_v4 = 24`, `routable_cap_v6 = 48`; `derive_address(ip, raw, caps=(24, 48))`;
  `score(rec, overrides, caps=...)`; callers pass `cfg.routable_caps`. CLI `--routable-cap-v4/-v6`.
- `Config.ripestat_url = "https://stat.ripe.net/data/{call}/data.json"`; CLI `--ripestat-url`.
- The collector skips the archive download when `data/rpki/<day>/` already holds a `roas.csv.xz`
  (needed because the day name `lab` is not a date). The lab writes
  `lab/build/data/rpki/lab/lab/roas.csv.xz` in the RIPE archive CSV format.
- The collector's resolver gate (AD on `rnids.rs`, SERVFAIL on `dnssec-failed.org`) is left as is;
  the lab's DNS tree contains both names, `dnssec-failed.org` made bogus by a mismatched DS in `org`.

The scanner runs on the host: `lab scan` calls `hijackscan victim.rs --data-dir lab/build/data
--resolver <resolver mgmt ip>:53 --rpki-date lab --ripestat-url http://<collector mgmt ip>:8080/data/{call}/data.json
--routable-cap-v4 28 --force`.

### 2.9 Containment (`lab check`)

Fails unless, on the live lab: every router's local AS and every BGP neighbour AS is in 64512–65534;
every neighbour address is in RFC 5737 space; no container has a default route except via an RFC 5737
next hop; the management network reports `enable_ip_masquerade: false`; and an egress probe
(`wget http://1.1.1.1`, 3 s) from one router and one host fails.

## 3. Files

    lab/scenarios/{baseline,tight-maxlength,caa-unsigned,caa-signed}.yml
    lab/labctl.py            render | apply | deploy | destroy | check | attack | scan | ca | matrix
    lab/matrix.py            the validation matrix with its expected results (logs in lab/logs/<timestamp>-matrix/)
    lab/check.py             containment (§2.9)
    lab/render/              generator: topology.py (constants), frr.py, rpki.py, dns.py, hosts.py, clab.py
    lab/image/               Dockerfile (Alpine + unbound, nsd, python3, stayrtr), web.py, entry scripts
    lab/ca.py  lab/feed.py   copied / bind-mounted into the ca and collector containers
    lab/build/               rendered output (git-ignored): clab topology, per-node configs, data/
    lab/demo.md              the walk-through with the observed results
