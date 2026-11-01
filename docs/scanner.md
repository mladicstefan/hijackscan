# The scanner, end to end

`hijackscan` measures how exposed the domains of a TLD are to certificate theft through BGP hijacks below
DNS, and how much of that exposure DNSSEC plus CAA closes. This page is the whole process, from a zone file
to a risk score: what each stage reads, what it writes, and the rule it applies. The risk formula itself is in
[design/formula.md](../design/formula.md); the lab that validates the verdicts is in [lab.md](lab.md).

## 1. The threat in one paragraph

A CA that issues a domain-validated certificate checks control of the domain over the network: it resolves
the name, fetches a token over HTTP (HTTP-01) or reads a TXT record (DNS-01), from several vantage points.
Those checks ride on BGP. An attacker who announces a **more-specific** of the prefix that holds the domain's
web server or nameservers, with the legitimate origin AS prepended so the route is RPKI-valid, becomes the
longest match everywhere and answers the CA's checks from every vantage point (the Hetzner/Virtualizor
incident of 28 August 2026). Two DNS-side facts stop it: a CAA record that pins issuance to one account
(`accounturi`, RFC 8657), and DNSSEC so that the attacker cannot answer "no CAA here" from a forged
nameserver. The scanner reads exactly these facts for every domain and derives a class and a score.

## 2. Pipeline

```
zone file ──sample──> domain list ──collect──> one JSON per domain ──score──> class ──risk──> 0–10 + fixes
                                                     │                                        │
                                              RIPEstat + ROA archive                    report (text, HTML, zone)
```

| stage | code | rule |
|---|---|---|
| sample | `collect/zonefile.py` | reads a TLD zone (dig axfr text, split parts in order), draws `random.Random(seed).sample(sorted(delegations), n)`, writes a domain list whose `#` header carries the population facts. |
| collect | `collect/` | observes only: DNS answers with AD flag and rcode, prefixes, ROAs, AS names. No judgement, no derived field. |
| score | `score.py` | pure functions over one collected record; every boolean and the exposure class are derived here. `score(record, overrides)` is the what-if mechanism. |
| risk | `risk.py` | pure: the 0–10 risk score and CVSS severity from a scored record; attack paths, findings, re-scored fixes, summary and details JSON. |
| report | `report/` | renders: terminal and HTML per domain, aggregate JSON and HTML per zone, the `list` view. Self-contained HTML, inline CSS, no CDN. |

Every stage is cached, so re-running is cheap, and every stage is reproducible: the sample from its seed,
the ROAs from a dated archive, the scores from the records alone (no network).

## 3. Commands

```bash
uv sync                                                  # once

# 0. the resolver must validate DNSSEC (the collector refuses to start otherwise)
uv run scripts/check_resolver.py                         # exit 0 = Quad9 over DoT validates

# 1. a reproducible sample from the zone file (same seed = same 100 names)
uv run hijackscan sample data/samples/zone.ee.part-* --n 100 --seed 1 --out data/samples/ee100.txt

# 2. raw facts, one JSON per domain (about 2 min cold for 100, 0 s when cached)
uv run hijackscan collect data/samples/ee100.txt

# 3. the zone report: report.json + report.html (no domain names), domains.jsonl (per domain)
uv run hijackscan zone data/samples/ee100.txt --out data/out/ee/

# 4. one domain: risk summary and the fix that helps most; --details for the calculation and raw facts
uv run hijackscan rnids.rs
uv run hijackscan <name>.ee --details --html out.html

# 5. filter and sort collected domains by risk (reads data/collected, no network)
uv run hijackscan list data/samples/ee100.txt --severity High,Critical
uv run hijackscan list --label ns-partial --details
uv run hijackscan list --finding NO_CAA,UNSIGNED --min-score 4 --json
```

Steps 1 and 2 are optional: any plain list of domains works (one per line, `#` comments), and `zone` and the
drill-down collect what is missing. Global flags go before the subcommand: `--resolver host[:port]` (853 =
DoT, 53 = plain), `--rpki-date YYYY-MM-DD` (default `latest`: the newest complete day under `data/rpki/` when
it is at most `--rpki-max-age` days old, default 3, else the newest day the RIPE archive has published), `--ripestat-url` (a
RIPEstat-shaped feed, used by the lab), `--routable-cap-v4/-v6` (default 24/48), `--max-age HOURS` (default
168), `--workers N`, `--data-dir DIR`, `-v`. Exit codes of `hijackscan <domain>`: 0 None, 1 Low / Medium,
2 High / Critical, 3 Unknown.

Useful variants:

```bash
uv run hijackscan sample data/samples/zone.ee.part-* --n 500 --seed 2 --out data/samples/ee500.txt   # bigger / different draw
uv run hijackscan --rpki-date 2026-08-28 zone data/samples/ee100.txt --out data/out/ee-aug28/        # ROAs of the Hetzner incident day
uv run hijackscan collect data/samples/ee100.txt --force                                             # ignore cached records
uv run hijackscan --resolver 127.0.0.1:53 zone ...                                                   # our own Unbound
python -m json.tool data/collected/<domain>.json | less                                              # one raw record

uv run python -c "                                       # scoring and a what-if override, no network
import json; from hijackscan.score import score
r = json.load(open('data/collected/rnids.rs.json'))
print(score(r).exposure, score(r, {'signed': True, 'has_caa': True, 'pinned': True}).exposure)"
```

## 4. Sample: the zone file and the population header

`data/samples/zone.ee.part-aa` + `part-ab` is the full `.ee` AXFR (`dig @zone.internet.ee ee. axfr`, SOA
serial 1793464230, 2026-10-31; CC-BY 4.0, Estonian Internet Foundation), split for GitHub's file limit:
204,698 delegations, 52,785 with a DS at the parent. The sampler reads only NS and DS records: the names,
which have a DS, and the nameserver operator (registered domain of each NS host, the same function the scorer
uses). Everything the verdict depends on (addresses, CAA, DNSKEY, the AD bit) is not in a zone file and is
collected live.

The header (`# key=value`, the top 20 `# ns_operator=... delegations=... ds=...`) is ignored by `collect` and
read by `zone`, which adds a "whole zone" section and per-operator "share of zone" and "DS at parent"
columns. **DS at parent is an upper bound on DNSSEC that validates**: zones signed without a DS are not
counted, and a DS with a broken chain makes the zone bogus, not secure; only the live sample splits secure
from bogus. The sample's DS share against the zone's is the representativeness check.

## 5. Collect: one record per domain (`data/collected/<domain>.json`)

- **Resolver.** `Config.resolver`, default Quad9 over DNS-over-TLS (`9.9.9.9:853`). `scripts/check_resolver.py`
  asserts AD on a signed zone (`rnids.rs`) and SERVFAIL on `dnssec-failed.org`; the collector refuses to
  start otherwise and stores the result in every record (`resolver_check`). Every query sets the DO bit; the
  AD flag and rcode are recorded per answer, never interpreted here.
- **Names.** A/AAAA for the apex, `www.`, and every NS host; DS and DNSKEY; CAA at every label up to and
  including the TLD (`caa_chain`).
- **Routing, per distinct address.** The announced prefix and origin ASNs (RIPEstat `network-info`),
  RIPEstat's RPKI verdict (`rpki-validation`), whether anything more specific is already announced inside the
  prefix (`routing-status`), AS names (`as-overview`). RIPEstat is called with at most 8 in flight,
  `sourceapp=hijackscan`, every response cached under `data/cache/ripestat/`.
- **ROAs, per distinct address, from the local archive** (`data/rpki/<date>/<ta>/roas.csv.xz`, five trust
  anchors, about one million ROAs, downloaded once with a sha256 check, parsed once into
  `data/rpki/<date>/index.marshal`, which is rebuilt whenever the CSVs' sha256 changes). Two lookups: `roas`, every ROA
  covering the announced prefix (the prefix and its supernets), and `roas_within`, every ROA for a strict
  subnet of it. The second one matters: a tight covering ROA does not protect an address when a ROA for a
  routable subnet that holds it exists, because a forged announcement of that subnet is RPKI-valid
  (Cloudflare's `23.227.38.0/23` with `/24` ROAs inside it; Yettel's `/20` with a `/24` inside).
- **Provenance.** Each record names its resolver, routing source, ROA archive directory and the routable
  caps in force (`resolver`, `routing_source`, `rpki_source`, `routable_caps`, `rpki_date`), and every report
  prints them in its footer.
- Per-domain failures land in `errors[]`; the batch never aborts. Records younger than `--max-age` (7 days)
  are reused. 8 domains in parallel, DNS capped at 50 qps.

## 6. Score: from facts to a class (`score.py`)

Per address, with `limit` = the routable cap (24 for IPv4, 48 for IPv6):

- no covering ROA → `forgeable_more_specific`, `rpki_derived = not-found` (unknown origin: nothing is ever
  RPKI-invalid there);
- else `forgeable_more_specific` when `announced_len < min(max(maxLength), limit)`, **or** when a ROA in
  `roas_within` holds the address with a prefix length no longer than `limit`;
- `roa_too_permissive` when any covering ROA's maxLength exceeds the announced length (RFC 9319 hygiene);
- an exact-prefix origin contest is always possible absent ASPA (`exact_prefix_contestable`).

Per domain:

- `dnssec` = `unsigned` (no DS) | `secure` (DS and A/AAAA answered with AD) | `bogus` (DS but SERVFAIL or
  no AD);
- `web_forgeable` when any web address is forgeable; `ns_forgeable` only when **every** nameserver address
  is (a CA's resolver and each MPIC perspective may ask any of them; `ns_forgeable_hosts`/`ns_hosts` record
  partial capture);
- CAA parsed from the first label with records: `issue`, `issuewild`, `accounturi`, `validationmethods`, and
  `issue_pins`, one flag per `issue` value. `pinned` holds only when there is at least one `issue` record
  and **every** one of them carries `accounturi`: one unpinned `issue` beside a pinned one lets any account
  at that CA issue. `issuewild` records govern wildcard names only (RFC 8659 §4.3) and do not count;
- `ns_operators` (registered domain of each NS host) and `hosting_asns`.

Exposure class, first match wins:

| class | condition |
|---|---|
| `closed` | pinned and signed |
| `caa-only` | CAA and signed, no account pin |
| `caa-erasable` | CAA, unsigned, every nameserver prefix forgeable → forge "no CAA" |
| `open` | no CAA and the web prefix or every nameserver prefix forgeable (the 28 August 2026 pattern) |
| `contested-only` | no win-everywhere hijack: exact-prefix contest or partial nameserver capture only, and no DNS-side defence |

`score(record, overrides)` recomputes the class with any boolean forced (`signed`, `has_caa`, `pinned`,
`web_forgeable`, …); that is how the what-if rows and the "which fix helps most" ranking are made.

## 7. Risk: from a class to 0–10 and a fix (`risk.py`)

The score is the success probability of the best attack path (HTTP-01 on the web prefix, DNS-01 or
"no CAA" on the nameservers, exact-prefix contest) against the CA checks in force on the date
(`RiskParams.for_date`: number of remote perspectives and tolerated dissents under CA/B BR 3.2.2.9), mapped
to the CVSS severity scale: None / Low / Medium / High / Critical, plus Unknown when the record is
incomplete. Each domain gets the labels the reports use (`open-web`, `open-dns`, `caa-bypassable`, `caa-erasable`,
`ns-partial`, `contested`, `closed`, `unknown`), a list of findings, the re-scored result of every fix, and
remediations per owner (domain owner, DNS host, hosting provider, registrar), DNS-side fixes first.
Formula, parameters, derivations and references: [design/formula.md](../design/formula.md).

## 8. Report

- `hijackscan <domain>`: the risk summary and the fix that helps most; `--details` adds the calculation,
  every path, and the raw facts per address: the announced prefix and origin, RIPEstat's verdict, announced
  more-specifics, every covering ROA and every ROA inside the prefix that holds the address, and the verdict
  sentence that explains why the address is or is not forgeable. `--html` writes the same as one page.
- `hijackscan zone <list> --out DIR`: `report.json` and `report.html` (counts, what-if rows, per-operator
  table, no domain names) and `domains.jsonl` (one line per domain).
- `hijackscan list`: filter by sample, label, severity, finding or minimum score; `--json` for machines.
- Every footer names the resolver, the routing source and the ROA archive the record came from.

## 9. Results and what was checked

The first 100 `.rs` domains (collected 2026-10-31, ROAs of 2026-10-31): no domain was `closed` or
`caa-only`; nobody used `accounturi`; CAA on 8, DNSSEC validating on 4. Roughly a quarter were `open`,
hosted behind loose-maxLength ROAs (Hetzner `/16 → 24`, CloudFront `/16 → 24`, Vultr) or in space with no
ROA at all; the child-ROA rule then moved two more (Yettel, Pepco on Cloudflare) from `contested` to
`open-web` Critical. What-if rows: signing alone and CAA alone each move almost nothing (the attack erases
unsigned CAA; DNSSEC without CAA restricts nobody); only both together close, and that row is `closed` by
definition.

A fresh collection of the 100 `.ee` sample (2026-10-31): `open-web` 41, `contested` 43, `ns-partial` 4,
`unknown` 12 (records with collection errors); severity Critical 37, High 1, Medium 2, Low 48.

What was checked after the first numbers looked too good: (1) re-scoring against a different archive day
moves only domains whose exposure hinged on one nameserver, so (2) `ns_forgeable` requires **every**
nameserver and partial capture is reported as k of n and stays `contested-only`; (3) RIPEstat
`routing-status` confirms no more-specific is already announced inside each forgeable prefix; (4) "no ROA" is
reported as *unknown origin, effectively forgeable* rather than *valid*; (5) ROAs inside the announced prefix
are looked at, not only the ones covering it; (6) a mixed CAA set (one pinned CA, one unpinned) is not
`closed`. The last two are also proven in the lab ([lab.md](lab.md)).

## 10. Data

| path | what |
|---|---|
| `data/samples/zone.ee.part-*` | the `.ee` zone, dig axfr text, 2026-10-31 |
| `data/samples/ee100.txt` | 100 `.ee` delegations, seed 1, with the population header |
| `data/samples/dev100.txt` | the 100 `.rs` domains (top `.rs` names of Tranco list 746VX, 2026-10-30) |
| `data/collected/` | raw record per domain (git-ignored) |
| `data/cache/ripestat/` | RIPEstat responses (git-ignored) |
| `data/rpki/<date>/` | RPKI archive CSVs, about 15 MB per day, plus the parsed `index.marshal`, about 60 MB (git-ignored) |
| `data/out/` | zone reports (git-ignored) |
