# hijackscan

How exposed are the domains of a TLD (`.ee` from its zone file, `.rs` from a list) to certificate theft through
BGP hijacks below DNS, and how much of it does DNSSEC + CAA close? (team dogma, DNS SEC Hackathon 2026)

## Usage

Four commands, in this order, plus `list` to filter the results. Every step is cached, so re-running is cheap.

```bash
uv sync                                                  # once

# 0. make sure the resolver validates DNSSEC (the collector refuses to start otherwise)
uv run scripts/check_resolver.py                         # exit 0 = Quad9 over DoT validates

# 1. draw a reproducible sample from the zone file (2 s; same seed = same 100 names)
uv run hijackscan sample data/samples/zone.ee.part-* --n 100 --seed 1 --out data/samples/ee100.txt

# 2. collect raw facts, one JSON per domain (about 2 min cold for 100, 0 s when cached)
uv run hijackscan collect data/samples/ee100.txt

# 3. aggregate report: report.json + report.html (no domain names), domains.jsonl (per domain, names included)
uv run hijackscan zone data/samples/ee100.txt --out data/out/ee/
firefox data/out/ee/report.html

# 4. drill into one domain: risk summary and the fix that helps most; --details for the calculation and raw facts
uv run hijackscan rnids.rs
uv run hijackscan <name>.ee --details --html out.html

# 5. filter and sort collected domains by risk (reads data/collected, no network)
uv run hijackscan list data/samples/ee100.txt --severity High,Critical
uv run hijackscan list --label ns-partial --details
uv run hijackscan list --finding NO_CAA,UNSIGNED --min-score 4 --json
```

## Validation lab (containerlab, offline)

`lab/` holds a sealed containerlab fabric (private ASNs, RFC 5737 addresses, local RPKI/DNS/CA) that runs the
real scanner against one domain under four scenario states and checks that a minimal CA's issuance decision
matches the scanner's verdict. Walk-through and results: [lab/demo.md](lab/demo.md); decisions:
[design/lab.md](design/lab.md).

```bash
uv run lab/labctl.py matrix        # every row: render, deploy, scan, attack, CA (about 4 min)
uv run lab/labctl.py check         # containment: no route off the box, private ASNs, RFC 5737 only
uv run lab/labctl.py destroy
```

Every domain gets a risk score 0–10 with the CVSS severity scale (None / Low / Medium / High / Critical, plus
Unknown when the record is incomplete). Formula, parameters and references: [design/formula.md](design/formula.md).
Exit codes of `hijackscan <domain>`: 0 None, 1 Low / Medium, 2 High / Critical, 3 Unknown.

Step 2 is optional: `zone` and the drill-down collect what is missing. Step 1 is optional too: any plain list of
domains (one per line, `#` comments) works, e.g. the 100 `.rs` names in `data/samples/dev100.txt`:

```bash
uv run hijackscan zone data/samples/dev100.txt --out data/out/rs/
```

Useful variants:

```bash
uv run hijackscan sample data/samples/zone.ee.part-* --n 500 --seed 2 --out data/samples/ee500.txt   # bigger / different draw
uv run hijackscan --rpki-date 2026-08-28 zone data/samples/ee100.txt --out data/out/ee-aug28/        # ROAs of the Hetzner incident day
uv run hijackscan collect data/samples/ee100.txt --force                                             # ignore cached records
uv run hijackscan --resolver 127.0.0.1:53 zone ...                                                   # our own Unbound
head -30 data/samples/ee100.txt                                                                      # the population header
python -m json.tool data/collected/<domain>.json | less                                              # one raw record
firefox --headless --window-size=1100,2400 --screenshot zone.png file://$PWD/data/out/ee/report.html

uv run python -c "                                       # scoring and a what-if override, no network
import json; from hijackscan.score import score
r = json.load(open('data/collected/rnids.rs.json'))
print(score(r).exposure, score(r, {'signed': True, 'has_caa': True, 'pinned': True}).exposure)"
```

Global flags go before the subcommand: `--resolver host[:port]` (853 = DoT, 53 = plain), `--rpki-date YYYY-MM-DD`
(default: newest archive day), `--max-age HOURS` (default 168), `--workers N`, `--data-dir DIR`, `-v`.

## Layering

| layer | code | rule |
|---|---|---|
| sample | `hijackscan/collect/zonefile.py` | reads a TLD zone (dig axfr text, split parts in order), draws `random.Random(seed).sample(sorted(delegations), n)`, writes a domain list whose `#` header carries the population facts. |
| collect | `hijackscan/collect/` | observes only: DNS answers with AD flag and rcode, prefixes, ROAs, AS names. No judgement, no derived field. |
| score | `hijackscan/score.py` | pure functions over one collected record; every boolean and the exposure class are derived here. `score(record, overrides)` is the what-if mechanism. |
| risk | `hijackscan/risk.py` | pure: the 0–10 risk score and CVSS severity from a scored record (design/formula.md); paths, findings, re-scored fixes, summary / details JSON. |
| report | `hijackscan/report/` | renders: terminal + HTML per domain, aggregate JSON + HTML per zone. Self-contained HTML, inline CSS, no CDN. |

## Zone file and sample (`data/samples/ee100.txt`)

`data/samples/zone.ee.part-aa` + `part-ab` is the full `.ee` AXFR (`dig @zone.internet.ee ee. axfr`, SOA serial
1793464230, 2026-10-31; CC-BY 4.0, Estonian Internet Foundation), split for GitHub's file limit. 204,698
delegations, 52,785 with a DS at the parent. The sampler only reads NS and DS records: the names, which have a DS, and
the nameserver operator (registered domain of each NS host, same function as the scorer) per name. Everything the
verdict depends on (addresses, CAA, DNSKEY, the AD bit) is not in a zone file and is collected live.

The header (`# key=value`, top 20 `# ns_operator=... delegations=... ds=...`) is ignored by `collect` and read by
`zone`, which adds a "whole zone" section and per-operator "share of zone" and "DS at parent" columns. **DS at
parent is an upper bound on DNSSEC that validates**: zones signed without a DS are not counted, and a DS with a
broken chain makes the zone bogus, not secure; only the live sample splits secure from bogus. The sample's DS share
against the zone's is the representativeness check.

## Collector (`data/collected/<domain>.json`)

- Resolver: `Config.resolver`, default **Quad9 over DNS-over-TLS** (`9.9.9.9:853`). Our local Unbound would be
  `--resolver 127.0.0.1:53`; the default is DoT because plain port 53 to public resolvers is blocked on the
  hackathon network and the systemd stub does not validate. `scripts/check_resolver.py` asserts AD on a
  signed zone (`rnids.rs`) and SERVFAIL on `dnssec-failed.org`; the collector refuses to start otherwise and
  stores the result in every record (`resolver_check`).
- Every query sets the DO bit; the AD flag and rcode are recorded per answer, never interpreted here.
- Resolves A/AAAA for the apex, `www.`, and every NS host; DS and DNSKEY; CAA at every label up to and
  including the TLD (`caa_chain`).
- Per distinct address: announced prefix + origin ASNs (RIPEstat `network-info`), RIPEstat's RPKI verdict
  (`rpki-validation`), and **every covering ROA from the local RPKI archive** (`data/rpki/<date>/<ta>/roas.csv.xz`,
  five trust anchors, ~1M ROAs, downloaded once with sha256 check; `--rpki-date`, default `latest` = the newest
  archive day; `2026-08-28` replays the Hetzner incident day). AS names from `as-overview`. RIPEstat ≤ 8 concurrent, `sourceapp=hijackscan`, every
  response cached under `data/cache/ripestat/`.
- Per-domain failures land in `errors[]`; the batch never aborts. Records younger than `--max-age` (7 days) are
  reused. 8 domains in parallel, DNS capped at 50 qps.

## Scoring (`score.py`)

Per address: `limit = 24 (v4) | 48 (v6)`; no covering ROA → `forgeable_more_specific = true`,
`rpki_derived = not-found`; else `announced_len < min(max(maxLength), limit)`. `roa_too_permissive` =
any ROA maxLength > announced length (RFC 9319 hygiene). Exact-prefix contest is always possible absent ASPA.

Per domain: `dnssec` = unsigned (no DS) | secure (DS and A/AAAA with AD) | bogus (DS but SERVFAIL or no AD);
`web_forgeable` (any web address), `ns_forgeable` (**every** nameserver address — a CA's resolver and each MPIC
perspective may ask any of them; `ns_forgeable_hosts`/`ns_hosts` records partial capture); CAA parsed from the first label with records (`issue`, `issuewild`,
`accounturi`, `validationmethods`); `ns_operators` (registered domain of each NS host) and `hosting_asns`.

Exposure class, first match wins:

| class | condition |
|---|---|
| `closed` | pinned (`accounturi`) and signed |
| `caa-only` | CAA and signed, no account pin |
| `caa-erasable` | CAA, unsigned, every nameserver prefix forgeable → forge "no CAA" |
| `open` | no CAA and the web prefix or every nameserver prefix forgeable (the 28 Aug 2026 pattern) |
| `contested-only` | no win-everywhere hijack: exact-prefix contest or partial nameserver capture only, and no DNS-side defence |

Remediations are listed per owner (domain-owner, dns-host, hosting-provider, registrar), DNS-side fixes first.

## Results, 100 `.rs` domains (collected 2026-10-31, ROAs of 2026-10-31)

See `data/out/report.html`. Headline: no domain is `closed` or `caa-only`; nobody uses `accounturi`; CAA on 8,
DNSSEC validating on 4. Roughly a quarter are `open` — hosted behind loose-maxLength ROAs (Hetzner `/16 → 24`,
CloudFront `/16 → 24`, Yettel, Vultr) or in space with no ROA at all. What-if rows: signing alone and CAA alone
each move almost nothing (the attack erases unsigned CAA; DNSSEC without CAA restricts nobody); only both together
close, and that row is `closed` by definition.

What was checked after the first numbers looked too good: (1) re-scoring against a different archive day moves
only domains whose exposure hinged on one nameserver — so (2) `ns_forgeable` now requires **every** nameserver,
partial capture is reported as k of n and stays `contested-only`; (3) RIPEstat `routing-status` confirms no
more-specific is already announced inside each forgeable prefix (e.g. Amazon announces /24s elsewhere in
`18.172.0.0/16`, not inside the /21 in question); (4) "no ROA" is reported as *unknown origin, effectively
forgeable* rather than *valid*.


## Data

| path | what |
|---|---|
| `data/samples/zone.ee.part-*` | the `.ee` zone, dig axfr text, 2026-10-31 |
| `data/samples/ee100.txt` | 100 `.ee` delegations, seed 1, with the population header |
| `data/samples/dev100.txt` | the 100 `.rs` domains (top `.rs` names of Tranco list 746VX, 2026-10-30) |
| `data/collected/` | raw record per domain |
| `data/cache/ripestat/` | RIPEstat responses |
| `data/rpki/<date>/` | RPKI archive CSVs (~15 MB per day) |
| `data/out/` | zone report |
