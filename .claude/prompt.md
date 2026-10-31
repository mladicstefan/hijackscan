# Build prompt: offline containerlab validation testbed for hijackscan

## Project summary: a defensive measurement and hardening tool

`hijackscan` is an open-source **defensive security tool** built by team dogma for the
DNS SEC(urity) Hackathon 2026, in support of the `.rs`/`.срб` registry (RNIDS). Its job
is to help a registry and its domain owners **find and close a gap before anyone can use
it**. Concretely, it measures how much of a ccTLD namespace could suffer certificate
mis-issuance when Internet routing is disturbed below the DNS layer, explains why for
each name, and ranks the defences that remove the exposure — tight RPKI ROA maxLength
(RFC 9319), DNSSEC signing, and CAA account pinning (RFC 8657) — by how much each
one helps and by who is able to deploy it (domain owner, DNS host, hosting provider, or
registrar). It is a read-only assessment and reporting tool: it inspects public
configuration facts (announced prefixes, ROAs, ASPA, CAA, DS/DNSKEY) and scores them. It
issues no announcements, sends no attack traffic, and touches no third-party system.

This task adds the tool's **validation harness**: a reproducible, fully isolated, offline
lab whose only purpose is to confirm that the scanner's findings and its remediation
advice are correct. We stand up a baseline configuration that the tool should flag,
confirm it flags it, then apply each recommended defence and verify that both the
scanner's verdict and a certificate authority's issuance decision improve exactly as the
tool predicts. This is the quality-assurance step for defensive advice: it lets RNIDS and
domain owners trust that "apply this fix" genuinely removes the exposure. There is no live
target, no third party, and nothing leaves the machine. The proposal lists it as the
optional containerlab demonstration.

What the lab reconstructs is the **misconfiguration class**, not an attack method: a
permissive ROA maxLength that allows an RPKI-valid more-specific route, combined with an
unsigned zone and absent CAA. These are the same conditions present in publicly
documented 2026 routing incidents, and they are precisely the conditions the registry can
remediate. Modelling them in a sealed testbed is how we show, concretely and safely, that
the remediations work.

## Hard containment requirements (non-negotiable)

- Runs entirely on local hardware inside containerlab on Docker. No BGP session, no
  route announcement, and no validation traffic ever reaches the Internet.
- Private ASNs only: 64512–65534.
- RFC 5737 documentation address space only: 192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24.
- All RPKI objects, ROAs, zone data and trust anchors are generated locally. No public
  RPKI repository, no public resolver, no public CA.
- Every node (origins, transits, resolver, CA, RPKI cache, data feed) is one we run.
- The management network has IP masquerade disabled so containers cannot egress
  through the host, and a `lab check` step must fail the demo if any node has a
  default route off-box, any BGP neighbour is outside RFC 5737, or any ASN is outside
  the private range.

## Scanner changes this lab requires

The scanner stays correct for real-world scans; the lab needs one small change plus
two configuration hooks that it already half-supports. None of this weakens the tool's
production behaviour — the defaults preserve it exactly.

### 1. Make the routable-prefix cap configurable (keep the safe default)

`derive_address` in `src/hijackscan/score.py` caps the "routable more-specific" length
at /24 for IPv4 and /48 for IPv6 (`limit = 24 if net.version == 4 else 48`). This cap
is correct and should **stay the default**: network operators filter announcements
more specific than /24 and /48, so a longer prefix would not propagate on the real
Internet, and flagging one as exposed would be a false positive. The cap is good
defensive hygiene — it keeps the tool from over-reporting. The only change is to make
it a parameter so the sealed lab can raise it:

- Add `routable_cap_v4: int = 24` and `routable_cap_v6: int = 48` to `Config`.
- Have `derive_address` read those fields instead of the hard-coded literals.
- Lab mode sets the v4 cap to 28, because RFC 5737 only provides /24 documentation
  blocks, so the lab's more-specific has to be a /28. Inside the sealed fabric every
  router is ours, so a /28 routes there even though it never would on the Internet.
  This change is scoped to lab mode; real scans are unaffected.

### 2. Point the two existing data inputs at the lab (no new code paths)

The scanner already reads routing and RPKI facts through two seams, so the lab feeds it
without touching the collection, scoring, risk or reporting logic:

- **RPKI archive**: the on-disk ROA archive at `data/rpki/<date>/<ta>/roas.csv`. The
  lab generator writes a `data/rpki/lab/` day from the same `rpki.json` the RPKI cache
  node serves, so the scanner and the routers agree on the ground truth.
- **RIPEstat base URL**: `src/hijackscan/collect/ripestat.py` builds requests from a
  single URL constant. Make it a `Config` field (default the public endpoint) so lab
  mode can point it at the in-lab feed node. This is a routine config extraction, and
  the public default keeps existing behaviour identical.

Nothing in `collect/`, the core of `score.py`, `risk.py` or `report/` changes. The
point of routing through the existing inputs is that the lab validates *the real
scanner*, not a modified one.

## Topology (lab infrastructure, nine nodes)

```
                         rpki (StayRTR)  ──RTR 323──┐
                         serves rpki.json           │
                                                    ▼
  AS65000 origin  ──eBGP──  AS65002 transit ──eBGP── AS65003 transit ──eBGP──  AS65010 origin-2
  FRR, hosts web            FRR                   FRR                         FRR
  + authoritative NS        (ROV: drop invalid)   (ROV: drop invalid)         announces the
  announces the /24               │                      │                    more-specific /28
         │                        └────── eBGP ──────────┘                          │
         └───────────────── eBGP (listen-only) ───────────────────────────────────┘
                                   │
                         AS65100 route-collector (FRR, listen-only; the RIS analogue)
                                   │
   ┌───────────────┬──────────────┴───────────────┬────────────────────┐
   resolver        ca                              scanner-feed
   Unbound,        mini-CA validation oracle,      RIPEstat-shaped HTTP stub,
   local root      5 vantage points, CAA walk,     answers network-info / rpki-validation /
   trust anchor    accounturi, DNSSEC-aware        routing-status / as-overview
```

### Addressing

- Victim prefix `203.0.113.0/24` originated by AS65000.
- The more-specific `203.0.113.0/28` originated by AS65010 (the condition under test).
- Service hosts (web, resolver, CA, feed) in `192.0.2.0/24`.
- Inter-AS point-to-point links in `198.51.100.0/24`.
- Every ASN in 64512–65534.

### Node roles

- **AS65000 origin** (FRR): legitimate origin of the /24; runs the authoritative DNS
  zone and the web host that the CA validates against.
- **AS65010 origin-2** (FRR): originates the more-specific /28. Whether this route is
  selected and validated is exactly what the remediations change.
- **AS65002 / AS65003 transit** (FRR): carry the routes and hold the one routing-layer
  remediation — RPKI origin validation on or off. With ROV off they accept the /28;
  with ROV on and a tight maxLength they drop it as RPKI-invalid (`match rpki invalid`
  → deny, fed by the RPKI cache). Plain FRR is enough; no OpenBGPD is needed.
- **rpki** (StayRTR, image `rpki/stayrtr`): serves one `rpki.json`
  (`{"roas":[{"prefix","maxLength","asn"}]}`) over RTR to both transits. Changing
  maxLength from 28 to 24 in that file is the RFC 9319 remediation.
- **AS65100 route-collector** (FRR, listen-only): peers with everyone and only
  listens; the lab's RIPE RIS analogue. The scanner-feed reads its table so the demo
  can report the share of the fabric carrying each route.
- **resolver** (Unbound): validates DNSSEC against a locally generated root trust
  anchor so the chain works fully offline.
- **ca** (small purpose-built validator): the oracle that turns routing state into a
  yes/no certificate decision. It resolves through Unbound and honours the AD flag,
  walks the CAA records (including `accounturi` per RFC 8657), then performs HTTP-01
  from a primary plus four perspective positions and applies the SC-067 quorum
  (≥4 remote perspectives, at most one disagreeing). Every check it makes prints to
  the demo log — that visibility is the point. Pebble is unsuitable (no CAA checking);
  Boulder does CAA + account pinning + multi-perspective but is a ten-service stack,
  so a minimal validator is the right size for a demo.

## Single source of truth

`lab/scenarios/baseline.yml` holds the ASes, prefixes, ROAs, zone signing state and
CAA policy. A generator renders every node's config (FRR, StayRTR `rpki.json`, the zone
file and its DNSSEC signing, Unbound trust anchor, CA policy, and the scanner's
`data/rpki/lab/` archive day) from that one file. Each remediation is a diff of the
scenario file, never a hand edit across nine containers.

## Before/after validation matrix

Each row is a one-line change to the scenario file followed by re-running the scanner
and the CA. Expected results:

| State | Scanner verdict | CA issues? |
|---|---|---|
| Baseline: maxLength 28, unsigned, no CAA | forgeable / open | yes |
| Tight maxLength 24 (RFC 9319) | not forgeable | no |
| CAA with accounturi, zone unsigned | forgeable / caa-erasable | refused on web path |
| CAA with accounturi, zone signed | forgeable / closed | no |

The last row is the central claim of the project and needs a CA that validates
DNSSEC and honours `accounturi` to demonstrate.

ASPA is deliberately out of scope for this lab. The scanner models RPKI origin
validation (maxLength), not AS_PATH validation, so it has no ASPA input, and adding one
honestly needs the BGPy path simulation from the proposal rather than lab work. The
four remediations above exercise every part of the current scanner.

## Verified tooling facts (checked 2026-10-31)

- **StayRTR** v0.6.4 (`rpki/stayrtr`): serves ROAs over RTR from one local
  `rpki.json`. All the lab needs.
- **FRR** 10.7.x (`quay.io/frrouting/frr`; Docker Hub `frrouting/frr` is stale at 8.x):
  `-M rpki`, `rpki cache tcp HOST PORT preference N`, `match rpki valid|invalid|notfound`.
  This gives ROV for both the baseline (ROV off, /28 accepted) and the maxLength
  remediation (ROV on, /28 dropped). FRR runs every router in the lab.
- **Unbound**, `ldns-signzone`, `named-checkzone` and `dig` are available locally;
  `kdig`/`knotc` are not.
- **containerlab** is not yet installed; install from the upstream `get.sh` (the AUR
  package is stale). Host has 14 cores and ~30 GB RAM.
- Management-network egress: set
  `mgmt.driver-opts { "com.docker.network.bridge.enable_ip_masquerade": "false" }`.

## Deliverables

1. The `routable_cap_*` config change in the scanner (and lab mode wiring it to 28).
2. `lab/scenarios/baseline.yml` plus the config generator.
3. The containerlab topology file and per-node configs for the nine nodes.
4. The minimal DNSSEC-aware, CAA-aware CA validator with a readable demo log.
5. The RIPEstat-shaped feed and the `data/rpki/lab/` archive-day generator.
6. The `lab check` containment script.
7. A `demo.md` walking through the before/after matrix.

## Rules of engagement (from the project proposal)

- Adversarial demonstrations run only inside this isolated containerlab on our own
  hardware, with private ASNs, RFC 5737 addresses and locally synthesised RPKI
  objects. No BGP session or test traffic reaches the Internet.
- Public datasets used elsewhere in the tool are read-only and within published
  limits; this lab uses none of them live — everything is generated locally.
- Namespace results are published only in aggregate; anything about named operators or
  registry infrastructure goes privately to the organisers.

## Skills to load

- `containerlab` and `docker` (in `.claude/skills/`): the topology schema, pinned
  images, FRR-with-rpki setup, and the offline-containment settings for this lab. Load
  them before writing any `.clab.yml`, `daemons`/`frr.conf`, or container config.
- Four read-only reviewers are in `.claude/agents/` (`review-design`, `review-bugs`,
  `review-standards`, `review-reproducibility`); run them before merging a workstream.

## Process

Work through the Superpowers skills: this is a project with a written design, so
start from `superpowers:brainstorming` only if anything above is unclear, otherwise go
to `superpowers:writing-plans`, then implement. Commits wait for the user's review
(`git-review-gate`); do not push or co-sign. No test suite is expected; verify by
running the lab and the scanner against the matrix above.
