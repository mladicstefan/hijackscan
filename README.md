# hijackscan

How exposed are the domains of a TLD (`.ee` from its zone file, `.rs` from a list) to certificate theft through
BGP hijacks below DNS, and how much of it does DNSSEC + CAA close? (team dogma, DNS SEC Hackathon 2026)

## Run the demo

Needs only [Docker Desktop](https://www.docker.com/products/docker-desktop/) (running). In this folder:

```bash
docker compose up
```

Then open **http://127.0.0.1:8000**. The first start builds the app (a few minutes); later starts take seconds.
It loads 200 scanned domains (`.rs` top 100 and a 100-domain `.ee` sample, collected 2026-10-31, in
`data/demo/`), so no scanning or internet access is needed. Stop with `Ctrl+C` or `docker compose down`;
`docker compose down -v` also deletes the database. The API and its documentation are at `/docs`.

To refresh the demo data after re-collecting (`uv run hijackscan collect data/samples/dev100.txt --force`, same
for `ee100.txt`), copy the records of both lists from `data/collected/` to `data/demo/collected/`, then
`docker compose down -v && docker compose up --build`.

Three parts, each documented end to end (the web page: [web/README.md](web/README.md)):

- **[docs/scanner.md](docs/scanner.md)**: the scanner. Sample a zone, collect DNS and routing facts, derive
  an exposure class and a 0–10 risk score, report per domain and per zone.
- **[docs/lab.md](docs/lab.md)**: the validation lab. A sealed containerlab fabric where the unmodified scanner
  scans one domain and a minimal CA then tries to issue to an attacker; every verdict is proven by the CA's
  decision and flipped by negative controls.

Design and results: [design/formula.md](design/formula.md) (the risk formula), [design/lab.md](design/lab.md)
(lab decisions), [lab/demo.md](lab/demo.md) (the last lab run, generated from its logs).

## Quick start

```bash
uv sync                                                  # once

# scanner
uv run scripts/check_resolver.py                         # the resolver must validate DNSSEC
uv run hijackscan sample data/samples/zone.ee.part-* --n 100 --seed 1 --out data/samples/ee100.txt
uv run hijackscan collect data/samples/ee100.txt

# 3. aggregate report: report.json + report.html (no domain names),
#    domains.jsonl + domains.html (per domain, names included; the page filters, rows expand to details)
uv run hijackscan zone data/samples/ee100.txt --out data/out/ee/
firefox data/out/ee/report.html

# 4. drill into one domain: risk summary and the fix that helps most; --details for the calculation and raw facts
uv run hijackscan rnids.rs
uv run hijackscan <name>.ee --details --html out.html

# 5. filter and sort collected domains by risk (reads data/collected, no network)
uv run hijackscan list data/samples/ee100.txt --severity High,Critical
uv run hijackscan list --label ns-partial --details
uv run hijackscan list --finding NO_CAA,UNSIGNED --min-score 4 --json
uv run hijackscan browse data/out/ee/domains.jsonl      # (re)build domains.html from a domains.jsonl
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

uv run python -c "                                       # risk score and a what-if fix, no network
import json; from hijackscan.score import score; from hijackscan.risk import assess
r = json.load(open('data/collected/rnids.rs.json')); s = score(r)
print(assess(r, s).summary()['severity'], assess(r, s, ov={'signed': True, 'pinned': True}).score)"
```

Global flags go before the subcommand: `--resolver host[:port]` (853 = DoT, 53 = plain), `--rpki-date YYYY-MM-DD`
(default: newest archive day), `--max-age HOURS` (default 168), `--workers N`, `--data-dir DIR`, `-v`.

## Layering

| layer | code | rule |
|---|---|---|
| sample | `hijackscan/collect/zonefile.py` | reads a TLD zone (dig axfr text, split parts in order), draws `random.Random(seed).sample(sorted(delegations), n)`, writes a domain list whose `#` header carries the population facts. |
| collect | `hijackscan/collect/` | observes only: DNS answers with AD flag and rcode, prefixes, ROAs, AS names. No judgement, no derived field. |
| score | `hijackscan/score.py` | pure functions over one collected record; every fact the risk model needs (DNSSEC state, CAA, forgeable addresses, operators) is derived here. |
| risk | `hijackscan/risk.py` | pure: the 0–10 risk score and CVSS severity from a scored record (design/formula.md); paths, findings, re-scored fixes, summary / details JSON. `assess(record, scored, ov=...)` is the what-if mechanism. |
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
  reused unless they have errors: an incomplete record is always collected again. 8 domains in parallel, DNS capped
  at 50 qps.

## Facts (`score.py`)

Per address: `limit = 24 (v4) | 48 (v6)`; no covering ROA → `forgeable_more_specific = true`,
`rpki_derived = not-found`; else `announced_len < min(max(maxLength), limit)`. `roa_too_permissive` =
any ROA maxLength > announced length (RFC 9319 hygiene). Exact-prefix contest is always possible absent ASPA.

Per domain: `dnssec` = unsigned (no DS) | secure (DS and A/AAAA with AD) | bogus (DS but SERVFAIL or no AD);
`web_forgeable`, `ns_forgeable_hosts` / `ns_hosts`; CAA parsed from the first label with records (`issue`,
`issuewild`, `accounturi`, `validationmethods`); `ns_operators` (registered domain of each NS host) and `hosting_asns`.

## Risk (`risk.py`, [design/formula.md](design/formula.md))

Three attack paths per domain, each scored 0–10; the domain's score is the highest open path:

| path | how | blocked by |
|---|---|---|
| `web` | forged RPKI-valid more-specific of the web prefix, pass HTTP-01 | CAA `accounturi`, CAA `issue ";"`, `validationmethods` without http-01 |
| `ns` | capture nameserver prefixes (all or some), forge DNS-01 / "no CAA" | DNSSEC |
| `contest` | exact-prefix origin contest | both of the above |

`Score = 10 × I × max(open × K × L)`, with `L = 1 − (1 − P)^N` (N = 5 attempts), `P` = the chance that the CA's
primary and at least r − f of its r remote perspectives (CA/B Forum BR 3.2.2.9) reach the attacker, and
`K = 0.87^h` per high-complexity step (the CVSS 3.1 AC:H / AC:L ratio). Severity is the CVSS rating scale:
None 0.0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0, Unknown when the record is incomplete.
Partial nameserver capture counts: 2 of 3 nameserver addresses captured scores 8.0 High.

Labels name what drives the score: `open-web`, `caa-bypassable`, `open-dns`, `caa-erasable`, `ns-partial`,
`contested`, `closed`, `unknown`. Every domain also lists its findings with evidence, the single fix that lowers its
score most and the fewest actions that bring it to 0.0.

## Results (collected 2026-10-31, ROAs of 2026-10-31)

| sample | Critical | High | Medium | Low | None | Unknown |
|---|---|---|---|---|---|---|
| 100 `.rs` (`data/out/rs/`) | 16 | 5 | 0 | 60 | 0 | 19 |
| 100 `.ee` (`data/out/ee/`) | 36 | 1 | 0 | 52 | 0 | 11 |

Nobody uses `accounturi`, so no domain is None. Critical and High are hosted behind loose-maxLength ROAs (Hetzner
`/16 → 24`, CloudFront `/16 → 24`, Yettel, Vultr) or in space with no ROA at all. What-if rows: DNSSEC alone and CAA
alone move almost nothing; CAA + accounturi closes the web path but unsigned zones stay open through their
nameservers; only both together reach None. Most Unknown `.rs` records are a fixed Windows cache bug; the next
`collect` or `zone` run re-collects them (records with errors are never reused).

What was checked after the first numbers looked too good: (1) re-scoring against a different archive day moves
only domains whose result hinged on one nameserver — so (2) partial nameserver capture is scored by its MPIC
success chance instead of counting as full capture; (3) RIPEstat `routing-status` confirms no more-specific is
already announced inside each forgeable prefix (e.g. Amazon announces /24s elsewhere in `18.172.0.0/16`, not inside
the /21 in question); (4) "no ROA" is reported as *unknown origin, effectively forgeable* rather than *valid*.


## Layout

| path | what |
|---|---|
| `src/hijackscan/collect/` | observes: zone file sampler, DNS, RIPEstat, the ROA archive |
| `src/hijackscan/score.py`, `risk.py` | pure: exposure class, risk score, fixes |
| `src/hijackscan/report/` | terminal, HTML and zone reports, the `list` view |
| `lab/` | the containerlab lab: `labctl.py`, scenario files, renderers, the CA, the feed, the matrix and controls |
| `design/` | formula and lab decisions |
| `data/samples/` | the `.ee` zone file and the two 100-domain samples (everything else under `data/` is generated) |
