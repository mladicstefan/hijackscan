# The validation lab, end to end

`lab/` is a sealed containerlab fabric that runs the **unmodified scanner** against one domain, `victim.rs`,
and then lets a minimal certificate authority try to issue a certificate to an attacker who is hijacking the
domain's address space. The scanner's verdict must predict the CA's decision in every row of a matrix, and
every verdict must flip when the mechanism it rests on is removed. This page is the whole process; the
reasoning behind each decision is in [design/lab.md](../design/lab.md), the generated walk-through with the
last run's transcripts is [lab/demo.md](../lab/demo.md).

## 1. What is being proven

The scanner says a domain is `open-web` when a forged, RPKI-valid more-specific of its web prefix would be
the longest match everywhere, so a CA's HTTP-01 check lands on the attacker. The lab makes that attack
happen on real routers (FRR with ROV from a StayRTR cache), a real validating resolver (Unbound with a local
root), real authoritative servers (NSD on the victim and on the attacker) and a CA that does CAA (RFC 8659,
RFC 8657 `accounturi`) plus multi-perspective HTTP-01 with the CA/B quorum in force today. Four scenario files
differ from the baseline by one key each:

| scenario | one-key change | scanner says | CA to the attacker |
|---|---|---|---|
| `baseline` | loose ROA (`/24` with maxLength 28), no CAA, unsigned | `open-web` | ISSUED |
| `tight-maxlength` | ROA maxLength 24 (RFC 9319) | `contested` | REFUSED |
| `caa-unsigned` | CAA `issue "lab-ca; accounturi=…/legit"`, unsigned | `caa-erasable` | REFUSED with only the web hijacked, ISSUED when the nameserver is hijacked too |
| `caa-signed` | the same CAA, zone signed with a DS in `rs` | `closed` | REFUSED (DNSSEC-bogus) |

## 2. The fabric

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

Ten containers: five FRR routers (`quay.io/frrouting/frr:10.7.1`, pinned by digest), and five from one
Alpine image built in `lab/image/` (Unbound resolver, NSD + a tiny web server on the victim and on the
attacker, the CA, StayRTR). Everything is RFC 5737 space and private ASNs; the management network has no
masquerade and every container's management default route is deleted at start. `lab/render/topology.py` is
the single source for nodes, links, addresses and the CA's five perspectives; a scenario file repeats the
facts the scanner needs and `render` refuses one that disagrees with the topology.

The attack is a forged-origin more-specific: origin2 announces `203.0.113.0/28` (and, for `web+ns`,
`203.0.113.96/28`) with AS-path `65010 65000`, so the route is RPKI-valid under the loose ROA and invalid
under the tight one. The victim's own AS never accepts it (AS-path loop detection), which is why one of the
CA's five perspectives, `r3`, always reaches the real host and why the baseline's ISSUED rests on exactly the
one dissent the quorum tolerates.

## 3. How the scanner is wired in

The scanner is not modified for the lab. `labctl scan` runs it with flags that point every input at the
fabric (`lab/labctl.py: scan_cmd`):

```
uv run hijackscan --data-dir lab/build/data --resolver 172.31.40.20:53 --rpki-date lab \
  --ripestat-url http://172.31.40.15:8080/data/{call}/data.json --routable-cap-v4 28 \
  domain victim.rs --force --details
```

- The resolver is the lab's Unbound, which validates against the lab root trust anchor.
- The routing feed is `lab/feed.py` on the collector: it answers the four RIPEstat calls the scanner makes
  (`network-info`, `rpki-validation`, `routing-status`, `as-overview`) from the collector's **live** BGP table.
- The ROA day `lab` is a local archive in the RIPE NCC CSV format rendered from the scenario's `roas:` list.
- `--routable-cap-v4 28` admits the lab's /28s (RFC 5737 blocks are /24s). Production defaults stay 24/48.

Every record the scanner writes carries this provenance (`routing_source`, `rpki_source`, `routable_caps`),
and the report footer prints it, so a lab report is never mistaken for a real one.

## 4. Commands

```bash
# once: containerlab, membership of the docker and clab_admins groups, the lab image, ldns on the host
# (ldns: Debian/Ubuntu `sudo apt install ldnsutils`, Arch `pacman -S ldns`)
curl -sL https://containerlab.dev/setup | sudo -E bash -s "install-containerlab"
sudo usermod -aG docker,clab_admins "$USER"
docker build -t hijackscan-lab:latest lab/image
docker pull quay.io/frrouting/frr:10.7.1
ldns-signzone -v

uv run lab/labctl.py apply lab/scenarios/baseline.yml   # render every config, deploy, wait, attack off
uv run lab/labctl.py check                               # containment, exit 1 on any violation
uv run lab/labctl.py scan [--details]                    # the scanner, pre-attack state
uv run lab/labctl.py attack web|web+ns|off               # origin2 announces or withdraws the forged routes
uv run lab/labctl.py ca attacker|legit                   # the CA tries to issue for that account
uv run lab/labctl.py matrix [--rows ROW ...]             # every row (about 4 min), evidence in lab/logs/<timestamp>-matrix/ (latest-matrix links to the newest run)
uv run lab/labctl.py controls                            # the negative controls (about 5 min)
uv run lab/labctl.py destroy
```

`render` writes every node's config to `lab/build/` (git-ignored). The build directory is bind-mounted into
the running containers, so while the lab is deployed always use `apply` (render + redeploy), never `render`
alone; for a dry render use `--build <other dir>`.

## 5. What one row does, step by step

`labctl matrix` runs this for every row of `lab/matrix.py: ROWS`:

1. **Render and deploy** the scenario: keys and signed zones (`ldns-signzone`, fixed inception and expiration
   so two renders differ only in key material), FRR configs with `route-map ROV` on the transits, Unbound
   with the lab root, the ROA archive and the feed table, `ca.json` with the quorum from the scanner's own
   `RiskParams.for_date(today)`, and the containerlab topology. `deploy` waits until every BGP session is
   Established and every ROV transit reports its RTR cache connected (ROV without a cache lets everything
   through as `notfound`).
2. **Containment check** (`lab/check.py`): no default route off the fabric, all ASNs private, all BGP
   neighbours in RFC 5737 space, management network without masquerade, egress probes fail. Any violation
   fails the whole run.
3. **Scan** the pre-attack state with `--details`. The label is read from the summary line, and the collected
   record is opened to confirm the facts the label rests on: no `errors`, the web address seen in the
   victim's prefix, RPKI state `valid`, a covering ROA with the scenario's maxLength, the resolver check
   passing. A scanner that printed the right label from a dead feed fails here.
4. **Attack** (`web` or `web+ns`). `attack()` shows the forged routes at the collector and then asks, from
   the resolver's position, which host answers at the web address (`X-Lab-Host` header) and at the
   nameserver address (`hostname.bind`). The row states the expected data plane explicitly and fails if the
   observed one differs.
5. **CA for the attacker's account.** `ca.py` walks CAA from `victim.rs` up to the root through the
   validating resolver, applies `issue`/`accounturi`/`validationmethods`, resolves the A record, then runs
   HTTP-01 from the primary and four remote perspectives, each bound to its own source address and routed
   out of its own link, and applies the quorum. The matrix matches the decision line against the row's
   expected reason (for example `reachable but bogus`, `accounturi pins …`, `domain control not
   demonstrated`) and the host that answered each perspective against the expected set.
6. **Attack off**, wait until the resolver validates the domain again, then **CA for the owner's account**:
   must be ISSUED and every perspective must have reached the victim.

Every run gets its own `lab/logs/<UTC timestamp>-matrix/`, with `lab/logs/latest-matrix` linked to the newest, so no
earlier run is overwritten. Each row writes `<scenario>-<mode>-{scan,attack,attacker,legit}.log` there, each scenario
`<scenario>-check.log`; the run writes `matrix.md` (the table) and `manifest.json` (git head and dirtiness,
sha256 of every scenario file, image IDs, containerlab and ldns versions, start and end time). A full,
passing run regenerates `lab/demo.md` from `lab/demo_template.md` and those logs; the demo is never edited by
hand.

When a lookup fails the CA says why: on SERVFAIL it asks once more with the CD bit, and an answer means the
zone is reachable but DNSSEC-bogus while a second failure means unreachable or lame. Both are REFUSED (fail
closed), but only the first is the `caa-signed` row's claim, and the matrix requires it.

## 6. The negative controls

`labctl controls` (`lab/controls.py`) removes, one at a time, the mechanism each verdict rests on and
checks the flip and the restore. All transcripts go to `lab/logs/<UTC timestamp>-controls/controls.log` (`latest-controls` links to the newest); exit 1 if any flip is
missing.

| control | mechanism removed | expected flip |
|---|---|---|
| A `caa-signed`, `web+ns` | Unbound's validator module (`module-config: "iterator"`, HUP) | REFUSED (reachable but bogus) → ISSUED → REFUSED |
| B `tight-maxlength`, `web` | `route-map ROV in` on both transits, soft-out from origin2 | the /28 absent from transit2 → present on transit1 as `rpki validation-state: invalid`; REFUSED → ISSUED → REFUSED |
| C `baseline`, `web` | the attacker's address on its interface (hijack still announced) | the feed shows the forged /28 with origin 65000; ISSUED → REFUSED (unreachable) → ISSUED |
| D `baseline` | the ROA day: every maxLength set to the prefix length | scanner `open-web` → `contested` → `open-web` |

## 7. Reproducibility

- Images pinned by digest: FRR in `lab/render/topology.py`, StayRTR and Alpine in `lab/image/Dockerfile`;
  the lab image rebuilds to the same ID.
- DNSSEC signatures use a fixed window (2026-01-01 to 2027-12-31) and the SOA serial is a hash of the
  scenario name; the ROA archive's `generated`/`valid` timestamps are constants. Two renders of one scenario
  differ only in freshly generated key material.
- The quorum is not a lab constant: it comes from `src/hijackscan/risk.py`. From 2026-12-15 five remotes are
  required and `render` refuses to run until an `r5` perspective is added to the topology.
- `manifest.json` in each run directory records what every run was made with.

## 8. Troubleshooting

- `permission denied … docker.sock` or `containerlab: permission denied`: the shell lacks the `docker` /
  `clab_admins` groups; log in again, or run the command through `newgrp`.
- A node has no interfaces or can reach the Internet: the containment check names it; see design/lab.md §2.9.
- `BGP sessions not established` or `RTR cache not connected` after 90 s: `docker logs clab-hijackscan-rpki`
  and `vtysh -c "show rpki cache-connection"` on a transit.
- A `--rows` run keeps the deployed lab if it already runs that scenario, so a state made by hand (an
  address removed, the feed killed) survives into the row: that is how the matrix's own negative runs are
  made.
