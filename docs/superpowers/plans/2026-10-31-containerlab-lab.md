# Containerlab Validation Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A sealed containerlab fabric plus a minimal CA oracle that confirms, row by row, that the real hijackscan scanner's verdict predicts whether an attacker holding a forged-origin more-specific can get a certificate.

**Architecture:** One scenario file renders every node config (FRR ×5, StayRTR, Unbound, NSD, web, CA policy, the scanner's ROA archive day). The scanner is unmodified except for three config seams and runs on the host against the lab's resolver and a RIPEstat-shaped feed running inside the route-collector. A `labctl.py` CLI drives render → deploy → scan → attack → CA.

**Tech Stack:** Python 3.11+ (uv project), PyYAML, containerlab 0.82, Docker, `quay.io/frrouting/frr:10.7.1`, `rpki/stayrtr`, a local Alpine image (unbound, nsd, python3, dnspython), `ldns-keygen`/`ldns-signzone` on the host.

**Spec:** `.claude/prompt.md` (build prompt) and `design/lab.md` (decisions; the plan argues from both).

## Global Constraints

- Private ASNs only: 65000, 65002, 65003, 65010, 65100 (all within 64512–65534).
- Addresses only from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, plus the management net 172.31.40.0/24.
- No node may keep a default route via the management gateway; management network `enable_ip_masquerade: "false"`.
- Scanner defaults unchanged: cap 24/48, RIPEstat public URL; lab passes flags explicitly.
- No test suite; verify by running the lab and the scanner (prompt §Process). `ruff check` and `ruff format` clean.
- Commits wait for the user's review (git-review-gate): stage, show the diff, stop. Never push, never co-sign.
- Privileged commands run through `echo '<cmd>' | newgrp docker` nested in `newgrp clab_admins` when the shell lacks the groups.
- Generated output goes to `lab/build/` (git-ignored); every rendered artifact is reproducible from the scenario.

## Review Focus

1. Scanner output for a real, previously collected record must be byte-identical before and after Task 1 (caps default 24/48): pinned by Task 1 step 6.
2. A `rpki_date` that is a real date must still download the archive when the directory is missing: pinned by Task 1 step 5.
3. `lab check` must fail, not pass vacuously, when a node still has the management default route: pinned by Task 7 step 6 (negative run against a deliberately broken topology).
4. The resolver must answer `dnssec-failed.org` with SERVFAIL and `rnids.rs` with AD, or the collector refuses to run: pinned by Task 7 step 4.
5. The CA must refuse when the resolver returns SERVFAIL for any CAA or A lookup (fail closed), not treat it as "no CAA": pinned by Task 8 row 5.

---

### Task 1: Scanner seams (caps, RIPEstat URL, archive guard)

**Files:**
- Modify: `src/hijackscan/config.py:22-45`
- Modify: `src/hijackscan/score.py:42-72` (derive_address), `:156-158` (score)
- Modify: `src/hijackscan/collect/ripestat.py:17,38`
- Modify: `src/hijackscan/collect/__init__.py:28-39`
- Modify: `src/hijackscan/__init__.py:21-33,63-80`
- Modify: `src/hijackscan/report/domain.py:47`, `report/zone.py:34,121,123`, `report/listing.py:33`

**Interfaces:**
- Produces: `Config.routable_cap_v4: int = 24`, `Config.routable_cap_v6: int = 48`, `Config.ripestat_url: str = "https://stat.ripe.net/data/{call}/data.json"`, property `Config.routable_caps -> tuple[int, int]`.
- Produces: `derive_address(ip: str, raw: dict, caps: tuple[int, int] = (24, 48)) -> AddressDerived`; `score(rec: dict, overrides: dict | None = None, caps: tuple[int, int] = (24, 48)) -> Scored`.
- Produces: `RipeStat(cache_dir: Path, concurrency: int, url: str = URL)`.
- CLI flags: `--routable-cap-v4 N`, `--routable-cap-v6 N`, `--ripestat-url TEMPLATE`.

- [ ] **Step 1: Record the baseline output** — `uv run hijackscan list --json > /tmp/claude-1000/.../scratchpad/list-before.jsonl` (reads data/collected only, no network).
- [ ] **Step 2: Config fields and property** in `config.py`; `routable_caps` returns `(self.routable_cap_v4, self.routable_cap_v6)`.
- [ ] **Step 3: Thread caps** — `derive_address` uses `caps[0] if net.version == 4 else caps[1]`; `score` passes `caps` to `derive_address`; the five callers pass `caps=cfg.routable_caps` (zone.py `build()` already receives `cfg`).
- [ ] **Step 4: RIPEstat URL** — `RipeStat.__init__` takes `url`; `call()` formats `self.url`; `Collector.__init__` passes `cfg.ripestat_url`.
- [ ] **Step 5: Archive guard** in `Collector.__init__`: replace the unconditional `ensure_archive(...)` with: if `cfg.rpki_dir` exists and `any(cfg.rpki_dir.glob("*/roas.csv.xz"))` skip, else `ensure_archive`. Keep the `latest` resolution before it. Check with `uv run python -c "from hijackscan.collect import Collector"` plus a dry call: `Config(rpki_date="2026-10-31")` must still resolve the existing day without network, and `Config(rpki_date="lab", data_dir=Path("lab/build/data"))` must raise only because the resolver gate fails, not from `date.split`.
- [ ] **Step 6: CLI flags** in `parser()` and the `replace` loop in `main()`.
- [ ] **Step 7: Verify unchanged behaviour** — `uv run hijackscan list --json > .../list-after.jsonl; diff list-before.jsonl list-after.jsonl` → empty. `uv run hijackscan --help` shows the three flags. `uv run ruff check src && uv run ruff format --check src` clean.
- [ ] **Step 8: Commit (review gate)** — stage the six files, show `git diff --cached --stat`, stop for the user.

### Task 2: Scenario files and the generator core (topology, FRR, RPKI, feed data)

**Files:**
- Create: `lab/scenarios/baseline.yml`, `tight-maxlength.yml`, `caa-unsigned.yml`, `caa-signed.yml`
- Create: `lab/render/__init__.py` (`load_scenario`, `render_all`), `lab/render/topology.py` (constants from design §2.7 and the clab YAML), `lab/render/frr.py`, `lab/render/rpki.py`
- Create: `lab/labctl.py` (argparse: `render` only in this task)
- Modify: `pyproject.toml` (dev group `pyyaml>=6`), `.gitignore` (`lab/build/`)

**Interfaces:**
- Scenario schema (baseline values):
  ```yaml
  name: baseline
  domain: victim.rs
  victim: {asn: 65000, prefix: 203.0.113.0/24, web: 203.0.113.10, ns: 203.0.113.100}
  attacker: {asn: 65010, announce: [], more_specifics: {web: 203.0.113.0/28, ns: 203.0.113.96/28}}
  transits: [65002, 65003]
  collector: 65100
  rov: true
  roas: [{prefix: 203.0.113.0/24, asn: 65000, max_length: 28}]
  dns: {signed: false, caa: []}
  ca: {id: lab-ca, accounts: {legit: "https://ca.lab/acct/legit", attacker: "https://ca.lab/acct/attacker"}, tokens: {legit: legit-token, attacker: attacker-token}}
  as_names: {65000: LAB-VICTIM-HOSTING, 65002: LAB-TRANSIT-1, 65003: LAB-TRANSIT-2, 65010: LAB-ATTACKER, 65100: LAB-COLLECTOR}
  ```
  Other scenario files: `extends: baseline.yml` plus the one changed key (`roas[0].max_length: 24`; `dns.caa: ['0 issue "lab-ca; accounturi=https://ca.lab/acct/legit"']`; the same plus `dns.signed: true`).
- `load_scenario(path: Path) -> dict` (deep-merge over `extends`).
- `render_all(sc: dict, build: Path) -> None` writes `build/lab.clab.yml`, `build/<node>/frr.conf` + `daemons`, `build/rpki/rpki.json`, `build/data/rpki/lab/lab/roas.csv.xz`, `build/feed.json` (as_names + roas for the feed), `build/scenario.json` (the merged scenario, read by `labctl` later).
- `topology.py` exports `NODES: dict[str, Node]`, `LINKS: list[Link]`, `MGMT: dict[str, str]` (node → 172.31.40.x), `PERSPECTIVES: list[Perspective]` (name, position AS, source ip, gateway) exactly as design §2.7 and §2.5.
- FRR per node: `router bgp <asn>`, `no bgp ebgp-requires-policy`, `bgp router-id`, neighbours with `remote-as`, `address-family ipv4 unicast` with `network` statements for the node's own prefixes (origin: victim /24 + 192.0.2.24/30; transits: their service links; collector: 192.0.2.20/30; origin2: the `announce`d more-specifics). Transits: `rpki` block with `rpki cache tcp <rpki mgmt ip> 8282 preference 1`, route-map `ROV` `deny` on `match rpki invalid` applied `in` on every neighbour when `rov` is true. Origin2: outbound route-map `FORGE` with `set as-path prepend 65000` on the more-specific prefix-list. Collector: `route-map DENY-ALL` out on every neighbour except the CA link prefix. `daemons` file: `bgpd=yes`, `bgpd_options="  -A 127.0.0.1 -M rpki"`.
- clab YAML: `name: hijackscan`, `mgmt` block per design, FRR nodes `kind: linux`, `image: quay.io/frrouting/frr:10.7.1`, `binds: [<build>/<node>/:/etc/frr/]` (the image's `docker-start` reads `/etc/frr/daemons`), `exec: ["ip route del default", ...link addresses...]`; every node `mgmt-ipv4`. Hosts/resolver/ca use image `hijackscan-lab:latest` (Task 4) with their binds; `rpki` uses `rpki/stayrtr:latest` with `cmd: -cache /rpki/rpki.json -checktime=false -refresh 10 -bind :8282` and `binds: [<build>/rpki/:/rpki/:ro]`.

- [ ] **Step 1: Add pyyaml** — `uv add --group dev pyyaml`; `.gitignore` gets `lab/build/`.
- [ ] **Step 2: Write the four scenario files** with the values above.
- [ ] **Step 3: `topology.py`** — dataclasses `Node(name, kind, asn | None, mgmt, image, role)`, `Link(a, a_ip, b, b_ip, prefix)`, `Perspective(name, asn, ip, gateway, dev)`; the tables from design §2.7 as data.
- [ ] **Step 4: `frr.py`** — `render_frr(sc, build)`; one function per role, output text.
- [ ] **Step 5: `rpki.py`** — `render_rpki(sc, build)`: `rpki.json` (`{"metadata": {...}, "roas": [{"prefix", "maxLength", "asn": "AS65000", "ta": "lab"}]}`), the archive CSV with header `URI,ASN,IP Prefix,Max Length,Not Before,Not After` compressed with `lzma`, and `feed.json`.
- [ ] **Step 6: `render_all` + `labctl.py render [scenario]`** (default `lab/scenarios/baseline.yml`, `--build lab/build`).
- [ ] **Step 7: Verify** — `uv run lab/labctl.py render` then: `uv run python -c "from hijackscan.collect.rpki import RoaIndex; print(RoaIndex(Path('lab/build/data/rpki/lab')).covering('203.0.113.0/24'))"` → one ROA, max_length 28; `grep -c "neighbor" lab/build/transit1/frr.conf` ≥ 3; `yaml.safe_load` of `lab.clab.yml` succeeds; `uv run lab/labctl.py render lab/scenarios/tight-maxlength.yml` yields maxLength 24 in `rpki.json`.
- [ ] **Step 8: Commit (review gate).**

### Task 3: DNS rendering (zones, signing, Unbound, NSD)

**Files:**
- Create: `lab/render/dns.py`

**Interfaces:**
- `render_dns(sc: dict, build: Path) -> None` writes:
  - `build/resolver/unbound.conf` (listen all, `access-control` for 172.31.40.0/24 and 192.0.2.0/24 and 203.0.113.0/24, `trust-anchor-file: /etc/unbound/root.key`, `auth-zone` for `.`, `rs`, `org`, `rnids.rs`, `dnssec-failed.org` with `for-upstream: yes`, `for-downstream: no`, `zonefile`), `build/resolver/root.key`, `build/resolver/zones/*.zone` (signed).
  - `build/victim/nsd.conf` + `victim.rs.zone` (signed iff `dns.signed`; CAA records from `dns.caa`; A `victim.rs`/`www` → web, NS `ns1.victim.rs` → ns ip).
  - `build/attacker/nsd.conf` + `victim.rs.zone` (unsigned, no CAA, same A/NS; this is the forged zone).
  - `build/dns/ds.txt` (DS of `victim.rs`, present only when signed) consumed by the `rs` zone.
- Keys: `ldns-keygen -a ECDSAP256SHA256 -k -r /dev/urandom <name>` in `build/dns/keys/`; signing `ldns-signzone -o <zone> -e <now+30d as YYYYMMDDHHMMSS> <zonefile> <keybase>`; the root trust anchor is the root KSK's `.key` DNSKEY line. `dnssec-failed.org` is signed correctly but `org` carries a DS whose digest has its first hex digit changed.
- Zone contents: root → NS `ns.root.lab.` 192.0.2.2 with DS for `rs` and `org`; `rs` → DS for `rnids.rs` (always) and `victim.rs` (if signed), glue `ns1.victim.rs A 203.0.113.100`; `rnids.rs` → A 192.0.2.2; `org` → delegation + wrong DS; `dnssec-failed.org` → A 192.0.2.2.

- [ ] **Step 1: Implement `render_dns`** and hook it into `render_all`.
- [ ] **Step 2: Verify signing** — `ldns-verify-zone lab/build/resolver/zones/rs.zone` (and root, org, rnids.rs) print "Zone is verified and complete"; `named-checkzone victim.rs lab/build/victim/victim.rs.zone` OK; rendering `caa-signed.yml` yields a DS line for `victim.rs` in `rs.zone` and RRSIGs in `victim.rs.zone`; rendering `baseline.yml` yields neither.
- [ ] **Step 3: Commit (review gate).**

### Task 4: Lab image and host services

**Files:**
- Create: `lab/image/Dockerfile`, `lab/image/web.py`, `lab/image/entry-host.sh`, `lab/image/entry-resolver.sh`, `lab/image/entry-ca.sh`
- Modify: `lab/render/topology.py` (clab node definitions for resolver, ca, victim, attacker: binds `build/<node>/:/lab/`, `cmd` = the entry script, `exec` for addresses and the default route) — rendered by `lab/render/hosts.py` (create) which also writes `build/ca/ca.yml` and `build/<host>/web.json`.

**Interfaces:**
- `web.py --host-label victim|attacker --config /lab/web.json` serves `GET /.well-known/acme-challenge/<token>` → `"<token>.<account>"` for the tokens in `web.json` (`{"tokens": {"legit-token": "https://ca.lab/acct/legit"}}`), 404 otherwise; response header `X-Lab-Host: <label>`; listens on 0.0.0.0:80.
- `entry-host.sh`: starts `nsd -c /lab/nsd.conf` and `python3 /lab/web.py ...`, waits.
- `entry-resolver.sh`: `unbound -d -c /lab/unbound.conf`.
- `entry-ca.sh`: for each perspective in `/lab/ca.yml` with `table != main`: `ip rule add from <ip> table <n>`, `ip route add default via <gw> dev <dev> table <n>`; then `sleep infinity`. Addresses themselves come from clab `exec`.
- `ca.yml`: `{id, resolver: 192.0.2.2, accounts, perspectives: [{name, asn, ip, dev, gateway, table}], quorum: {min_remote: 4, max_fail: 1}}`.

- [ ] **Step 1: Dockerfile** — `FROM alpine:3.22`, `apk add --no-cache unbound nsd python3 py3-dnspython bind-tools curl iproute2`, copies `web.py` and the entry scripts to `/usr/local/bin/`. Build: `docker build -t hijackscan-lab:latest lab/image` (via `newgrp docker`).
- [ ] **Step 2: `web.py`** — `http.server` subclass; verify locally: `python3 lab/image/web.py --host-label victim --config <tmp web.json> --port 8089 &` then `curl -i localhost:8089/.well-known/acme-challenge/legit-token` → body `legit-token.https://ca.lab/acct/legit`, header `X-Lab-Host: victim`; unknown token → 404.
- [ ] **Step 3: `hosts.py`** — node definitions and `web.json`/`ca.yml`; `labctl.py render` now emits the full topology.
- [ ] **Step 4: Verify** — `docker run --rm hijackscan-lab:latest sh -c 'unbound -V | head -1; nsd -v; python3 -c "import dns"'` succeeds; rendered `lab.clab.yml` lists ten nodes and 14 links (7 inter-AS, 5 service, victim, attacker).
- [ ] **Step 5: Commit (review gate).**

### Task 5: The CA validator

**Files:**
- Create: `lab/ca.py` (copied into `build/ca/` by the renderer; run with `docker exec clab-hijackscan-ca python3 /lab/ca.py ...`)

**Interfaces:**
- `python3 /lab/ca.py --config /lab/ca.yml --domain victim.rs --account legit|attacker` → exit 0 "ISSUED", 1 "REFUSED"; every step logged as one line `[step] detail`.
- Steps, in order, each with its log line:
  1. `resolve(name, rtype)` through `resolver` with DO + AD requested (dnspython `dns.query.udp`), log rcode and AD. `SERVFAIL` anywhere → `REFUSED: DNSSEC validation failed (fail closed)`.
  2. CAA walk per RFC 8659: `victim.rs`, `rs`, `.` until a non-empty RRset; log where it came from and the AD flag. Parse `issue` tags: if any `issue` names a CA other than `ca.id` and none names it → refused; if an `issue` for `ca.id` carries `accounturi=` and it differs from the requested account → `REFUSED: CAA accounturi pins <uri>`; `validationmethods=` without `http-01` → refused.
  3. A lookup of the domain (AD logged); HTTP-01 fetch of `http://<ip>/.well-known/acme-challenge/<token>` with `Host: victim.rs` from the primary and every remote (`socket` bound to the perspective's source ip, 3 s timeout); log `X-Lab-Host` and body match per perspective.
  4. Quorum: primary must corroborate; remote failures ≤ `max_fail` and remotes ≥ `min_remote`; log `quorum 4/4 remote corroborations (max 1 failure)`.
  5. Decision line.
- Pure functions `parse_caa(records: list[str]) -> list[tuple[int, str, str]]` and `caa_allows(records, ca_id, account) -> tuple[bool, str]` at module level so they can be checked without the lab.

- [ ] **Step 1: Write `ca.py`** (stdlib + dnspython only).
- [ ] **Step 2: Offline check** — `uv run python -c "import importlib.util,sys; ... caa_allows(['0 issue \"lab-ca; accounturi=https://ca.lab/acct/legit\"'], 'lab-ca', 'https://ca.lab/acct/attacker')"` → `(False, 'accounturi pins https://ca.lab/acct/legit')`; same with the legit account → `(True, ...)`; `['0 issue "other-ca"']` → False; `[]` → True.
- [ ] **Step 3: Commit (review gate).**

### Task 6: The RIPEstat-shaped feed

**Files:**
- Create: `lab/feed.py` (bind-mounted into the collector at `/lab/feed.py`, started by clab `exec` as `python3 /lab/feed.py --port 8080 --config /lab/feed.json`)
- Modify: `lab/render/topology.py` (collector binds + exec)

**Interfaces:**
- GET `/data/<call>/data.json?resource=...[&prefix=...]` → `{"data": {...}}`:
  - `network-info`: most specific prefix in `vtysh -c "show bgp ipv4 unicast json"` covering `resource`, `{"prefix": p, "asns": [origin]}` (origin = last AS of the best path; empty path means the collector's own prefix).
  - `rpki-validation`: `{"status": "valid"|"invalid"|"unknown"}` against `feed.json` ROAs (covering ROA with matching ASN and length ≤ maxLength → valid; covering ROA exists otherwise → invalid; none → unknown).
  - `routing-status`: `{"more_specifics": [{"prefix", "origin"}], "visibility": {"v4": {"ris_peers_seeing": n, "total_ris_peers": N}}}` where `n` = number of the collector's peers whose path carries the exact prefix (from the per-prefix `paths` list) and `N` = number of configured peers.
  - `as-overview`: `{"holder": as_names[asn], "announced": true}`.
- Unknown call → 404. Uses `http.server` + `subprocess.run(["vtysh", "-c", ...])`.

- [ ] **Step 1: Write `feed.py`**; `topology.py`: collector gets `binds: [lab/feed.py:/lab/feed.py:ro, build/feed.json:/lab/feed.json:ro]` and `exec: ["sh -c 'nohup python3 /lab/feed.py --port 8080 --config /lab/feed.json >/tmp/feed.log 2>&1 &'"]`.
- [ ] **Step 2: Offline check** — `rpki_status(roas, '203.0.113.0/28', 65000)` → `valid` with maxLength 28, `invalid` with 24; `rpki_status(roas, '203.0.113.0/28', 65010)` → `invalid`; `rpki_status(roas, '192.0.2.0/30', 65002)` → `unknown`. The live endpoints are checked in Task 7 step 5.
- [ ] **Step 3: Commit (review gate).**

### Task 7: Lab control: deploy, check, attack, scan, ca; baseline bring-up

**Files:**
- Create: `lab/check.py` (containment), `lab/labctl.py` subcommands `apply`, `deploy`, `destroy`, `check`, `attack`, `scan`, `ca`

**Interfaces:**
- `labctl.py apply <scenario>` = render + `containerlab deploy --reconfigure -t lab/build/lab.clab.yml` + wait until `vtysh -c "show bgp summary json"` on transit1 reports every peer `Established` (60 s cap) + `attack off`.
- `labctl.py attack off|web|web+ns` → `docker exec clab-hijackscan-origin2 vtysh -c "conf t" -c "router bgp 65010" -c "address-family ipv4 unicast" -c "[no ]network 203.0.113.0/28" ...` then prints `show bgp ipv4 unicast 203.0.113.0/28` from the collector.
- `labctl.py scan` → clears `lab/build/data/{cache,collected}` and runs `uv run hijackscan victim.rs --data-dir lab/build/data --resolver 172.31.40.12:53 --rpki-date lab --ripestat-url http://172.31.40.15:8080/data/{call}/data.json --routable-cap-v4 28 --force`; prints the summary and returns its exit code; `--details` passes through.
- `labctl.py ca legit|attacker` → `docker exec clab-hijackscan-ca python3 /lab/ca.py --config /lab/ca.yml --domain victim.rs --account <a>`; returns its exit code.
- `check.py` implements design §2.9; `labctl.py check` runs it; exit 1 on any violation with one line per violation.

- [ ] **Step 1: Implement the subcommands** (subprocess wrappers; container names `clab-hijackscan-<node>`).
- [ ] **Step 2: Deploy baseline** — `labctl.py apply lab/scenarios/baseline.yml`; expected: all sessions Established on transit1, `show bgp ipv4 unicast` on the collector lists 203.0.113.0/24 from four paths and no /28.
- [ ] **Step 3: RTR check** — `docker exec clab-hijackscan-transit1 vtysh -c "show rpki prefix-table"` lists `203.0.113.0/24-28 AS65000`.
- [ ] **Step 4: Resolver check** — `dig @172.31.40.12 rnids.rs A +dnssec` has `ad` flag; `dig @172.31.40.12 dnssec-failed.org A` → SERVFAIL; `dig @172.31.40.12 victim.rs CAA` → NOERROR, empty; `uv run scripts/check_resolver.py --resolver 172.31.40.12:53` exits 0.
- [ ] **Step 5: Feed check** — `curl 'http://172.31.40.15:8080/data/network-info/data.json?resource=203.0.113.10'` → `{"data": {"prefix": "203.0.113.0/24", "asns": [65000]}}`; `rpki-validation` for AS65000 → valid; `as-overview` → holder `LAB-VICTIM-HOSTING`.
- [ ] **Step 6: Containment** — `labctl.py check` exits 0 and prints the five checks; then a negative run: `docker exec clab-hijackscan-victim ip route add default via 172.31.40.1` → `labctl.py check` exits 1 naming `victim`; remove the route again.
- [ ] **Step 7: Scanner baseline** — `labctl.py scan` prints `victim.rs` with label `open-web` (exposure class `open`), evidence naming the ROA `203.0.113.0/24→28 AS65000`.
- [ ] **Step 8: Attack and CA** — `labctl.py attack web`; the collector shows `203.0.113.0/28` with path `65010 65000` (via 65003) and `show bgp ipv4 unicast 203.0.113.0/28` on transit1 says `validation state: valid`; `labctl.py ca attacker` → ISSUED with all five perspectives reporting `X-Lab-Host: attacker`; `labctl.py ca legit` → REFUSED (its token is on the victim host, now unreachable) — note this in demo.md as the hijack's collateral; `labctl.py attack off`; `ca legit` → ISSUED.
- [ ] **Step 9: Commit (review gate).**

### Task 8: The matrix, demo.md, README

**Files:**
- Create: `lab/demo.md`
- Modify: `lab/labctl.py` (`matrix`), `README.md` (a "Validation lab" section pointing at `lab/demo.md` and `design/lab.md`)

**Interfaces:**
- `labctl.py matrix [--rows all]` runs, for each row of design §2.4: `apply`, `scan` (captures the risk label and exposure class from `hijackscan ... --json`? — the domain command has no `--json`; capture the first summary line), `attack <mode>`, `ca attacker`, `ca legit` (with attack off), `attack off`; prints a Markdown table `| scenario | attack | scanner | CA attacker | CA legit |` and exits 1 if any cell differs from the expected table embedded in `labctl.py`.

- [ ] **Step 1: Implement `matrix`.**
- [ ] **Step 2: Run it** — expected output per design §2.4; paste the actual table and the five CA logs (attacker runs) into `lab/demo.md`.
- [ ] **Step 3: Write `lab/demo.md`** — prerequisites (containerlab install line, docker + clab_admins groups, `docker build`), the per-row walk-through with the exact commands and the observed output, what each log line means, and the containment proof (`labctl.py check` output).
- [ ] **Step 4: README section**; `uv run ruff check lab src`.
- [ ] **Step 5: `labctl.py destroy`**; commit (review gate).
