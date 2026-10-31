# hijackscan

How exposed are `.rs` domains to certificate theft through BGP hijacks below DNS, and how much
of it does DNSSEC + CAA close? (team dogma, DNS SEC Hackathon 2026)

```bash
uv sync
uv run scripts/check_resolver.py                       # does the configured resolver validate DNSSEC?
uv run hijackscan collect data/samples/dev100.txt      # raw facts -> data/collected/<domain>.json
uv run hijackscan blic.rs [--html blic.html]           # one domain: facts, class, attack path, fixes
uv run hijackscan zone data/samples/dev100.txt --out data/out/   # report.json + report.html (no domain names)
```

Exit codes of `hijackscan <domain>`: 0 closed, 1 caa-only / contested-only, 2 open / caa-erasable.

## Trying it

```bash
uv run scripts/check_resolver.py                        # exit 0: the resolver validates (AD on rnids.rs, SERVFAIL on dnssec-failed.org)
uv run scripts/check_resolver.py --resolver 127.0.0.53:53   # the systemd stub: must FAIL

uv run hijackscan collect blic.rs --force               # one raw record
python -m json.tool data/collected/blic.rs.json | less
uv run hijackscan collect data/samples/dev100.txt       # batch; records younger than --max-age (7 d) are reused

uv run hijackscan blic.rs; echo "exit=$?"               # drill-down, exit 2 = open
uv run hijackscan rnids.rs                              # a signed zone
uv run hijackscan google.rs --html google.html

uv run hijackscan zone data/samples/dev100.txt --out data/out/
firefox data/out/report.html
firefox --headless --window-size=1100,1900 --screenshot zone.png file://$PWD/data/out/report.html

uv run python -c "                                      # scoring and a what-if override, no network
import json; from hijackscan.score import score
r = json.load(open('data/collected/blic.rs.json'))
print(score(r).exposure, score(r, {'signed': True, 'has_caa': True, 'pinned': True}).exposure)"
```

Flags on every command: `--resolver host[:port]` (853 = DoT, 53 = plain; e.g. `127.0.0.1:53` for our Unbound),
`--rpki-date YYYY-MM-DD` (fetches that archive day), `--max-age HOURS`, `--workers N`, `-v`.

## Layering

| layer | code | rule |
|---|---|---|
| collect | `hijackscan/collect/` | observes only: DNS answers with AD flag and rcode, prefixes, ROAs, AS names. No judgement, no derived field. |
| score | `hijackscan/score.py` | pure functions over one collected record; every boolean and the exposure class are derived here. `score(record, overrides)` is the what-if mechanism. |
| report | `hijackscan/report/` | renders: terminal + HTML per domain, aggregate JSON + HTML per zone. Self-contained HTML, inline CSS, no CDN. |

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
| `data/samples/dev100.txt` | the 100 `.rs` domains (top `.rs` names of Tranco list 746VX, 2026-10-30) |
| `data/collected/` | raw record per domain |
| `data/cache/ripestat/` | RIPEstat responses |
| `data/rpki/<date>/` | RPKI archive CSVs (~15 MB per day) |
| `data/out/` | zone report |
