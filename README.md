# hijackscan

Measures how exposed the `.rs` / `.срб` namespace is to certificate theft through BGP hijacks
below DNS, and how much CAA (`accounturi`) plus DNSSEC closes. This repository currently holds
the **fetch stage**: it gets public datasets onto disk, verified, with a manifest. No analysis yet.

```bash
uv sync --all-groups
uv run hijackscan fetch all                 # or: make fetch-all
uv run hijackscan fetch caida tranco        # or: make fetch-caida
uv run hijackscan fetch rpki --dates 2026-08-28
uv run hijackscan fetch ris --rrcs 00 --window 2026-08-28T10:00Z/2026-08-28T10:30Z
uv run hijackscan fetch crtsh --months 1    # test on the most recent month first
uv run hijackscan fetch crtsh --finalize    # names.txt / registered_domains.txt, no network
uv run pytest                               # unit tests (no network); -m integration for network tests
```

Behaviour common to every target:

- Config lives in `config/fetch.yaml` (dates, RRC list, TLDs, contact email); CLI flags override it.
- Downloads stream to `<path>.part` and are renamed atomically; a partial `.part` is resumed with a
  `Range` request. Existing files are skipped when their size matches the manifest or `Content-Length`;
  `--force` re-downloads.
- Retries: 5 attempts, exponential backoff with jitter, on network errors and 5xx only. 4xx is final.
- `data/MANIFEST.jsonl`: one line per local file (target, URL, path, bytes, sha256, fetched_at, params),
  rewritten atomically and keyed by path so re-runs update rather than duplicate.
- `User-Agent: hijackscan/0.1 (DNS SEC Hackathon 2026; <contact email>)`; at most 4 concurrent
  downloads per host; exactly one connection to crt.sh.
- Logs go to stderr with timestamps (`--quiet`, `--verbose`).

## Datasets

### `caida` — CAIDA AS Relationships (serial-2)

- URL: `https://publicdata.caida.org/datasets/as-relationships/serial-2/{YYYYMM}01.as-rel2.txt.bz2`
  plus `README.txt`. Default month 2026-08 (`caida.date`, `--caida-date`).
- Saved as `data/caida/20260801.as-rel2.txt.bz2` (~2.0 MB, not decompressed).
- Licence: CAIDA Acceptable Use Agreement. Publications must cite
  "The CAIDA AS Relationships Dataset, 2026-08-01, https://www.caida.org/catalog/datasets/as-relationships/"
  and be reported to CAIDA.
- Known gaps: inferred relationships only; IXP route servers and sibling ASes are not modelled.

### `rpki` — RIPE NCC RPKI archive

- URL: `https://ftp.ripe.net/rpki/{ta}.tal/{YYYY}/{MM}/{DD}/` for `afrinic apnic arin lacnic ripencc`;
  files `roas.csv.xz`, `output.json.xz` (validated payloads incl. ASPA), `routinator.log`, each with a
  `.sha256` sibling that is downloaded and verified (a mismatch renames the file to `.corrupt`).
  `repo.tar.xz` (100+ MB per TA/day) is deliberately not fetched.
- The directory listing is fetched first; a missing TA/day is recorded in `data/rpki/STATUS.json` and
  skipped. If the primary tree 404s, `https://ftp.ripe.net/ripe/rpki/…` is tried.
- Default days (`rpki.dates`, `--dates`): 2026-08-27/28/29 (the Hetzner incident) and today.
- Saved under `data/rpki/{YYYY-MM-DD}/{ta}/`. 2026-08-28 is ~24 MB across all five TAs.
- Licence: RIPE NCC terms for public data; research results should be shared with RIPE NCC.
- Known gaps: the archive has missing days; `routinator.log` is large for ripencc; ASPA objects only
  appear in `output.json.xz` for days after each TA started publishing them.

### `ris` — RIPE RIS BGP updates around 28 Aug 2026

- URL: `https://data.ris.ripe.net/rrc{NN}/{YYYY}.{MM}/updates.{YYYYMMDD}.{HHmm}.gz` (every 5 min) and
  `bview.{YYYYMMDD}.{HHmm}.gz` (00:00, 08:00, 16:00). **Confirmed on the 2026.08 index: the prefix is
  `updates` (plural).**
- Config: `ris.rrcs` (default: the 23 collectors with 2026-08 data; `rrc02/08/09/17` 404),
  `window_start`/`window_end` (default 2026-08-27T20:00Z → 2026-08-30T12:00Z), or `--rrcs 00,01` and
  `--window START/END`. The last bview before `window_start` is fetched for each collector.
- The month index is parsed per collector; files missing from the index and inactive collectors are
  recorded in `data/ris/STATUS.json`. The planned file count and an estimated size (one HEAD per
  collector) are printed; above 2 GB the run stops unless `--yes` is given.
- Measured: rrc00 updates ≈ 5–8 MB per 5 min, bview ≈ 427 MB. The default window over 23 collectors is
  roughly 23 × (768 × ~6 MB + 427 MB) ≈ **115 GB** — pick collectors deliberately.
- Saved to `data/ris/rrc{NN}/<file>`; MRT is not parsed here.
- Licence: RIPE NCC RIS terms (free for research; cite RIPE RIS).

### `ris-parquet` (stub)

RIPE NCC also publishes RIS in indexed Parquet form (see the RIPE Labs articles on "RIS data in
Parquet" / the `ris-live`/BigQuery-style exports). TODO: confirm the documented bucket/URL layout and
implement a target that fetches only the hours and prefixes we replay. The MRT path above works
today; Parquet would let us filter on `162.55.0.0/16` without downloading full update files.

### `tranco` — Tranco top list

- Via the official `tranco` package: `Tranco(cache=True, cache_dir="data/tranco").list()`; the list ID
  and page URL (`https://tranco-list.eu/list/{ID}/`) go into the manifest.
- Fallback: `https://tranco-list.eu/top-1m.csv.zip` (307 → `/download/daily/top-1m.csv.zip`; the final
  URL carries **no** ID, so the ID is read from `https://tranco-list.eu/top-1m-id`).
- Saved as `data/tranco/{ID}.csv` (package) or `{ID}.csv.zip` (fallback) with a `latest` symlink.
  ~22 MB uncompressed; the package download takes 4–5 minutes.
- Licence: free to use; cite the list ID (the list page gives a citation).

### `bgpy-smoke` — BGPy 13.0.13 install and timing

- Unpacks the fetched CAIDA file into BGPy's cache name
  (`data/bgpy_cache/CAIDAASGraphCollector_2026.08.01.txt`) so BGPy does not download it again, then runs
  `Simulation(percent_adoptions=(0.5,), SubprefixHijack + ROV, num_trials=20, parse_cpus=<cores>)`.
- `scripts/bgpy_smoke.py` prints wall-clock, trials, cores; `data/bgpy_smoke/smoke.json` keeps the same.
- API notes (checked against 13.0.13): `CAIDAASGraphConstructor(tsv_path=...)` is an **output** path
  (the constructor writes a TSV there), not an input — the graph is read from the collector cache file
  above. `ScenarioConfig` supports `override_victim_asns`, `override_attacker_asns`, `override_roas` and
  `hardcoded_asn_cls_dict`; `ROV`, `PeerROV`, `ASPA` (and `*Full` variants) live in
  `bgpy.simulation_engine`. The real runs will use those. Importing `bgpy.simulation_framework` parses
  `sys.argv`, so the import is lazy.
- Measured on this machine: 20 trials in 57 s wall on 14 cores (expected RAM 12.6 GB).

### `crtsh` — Certificate Transparency sample of `.rs` and `.срб`

- Source: crt.sh public PostgreSQL (`crt.sh:5432`, user `guest`, db `certwatch`, no password, no TLS).
  **Shared courtesy service: run once, keep the cache, never parallelize.**
- One calendar month per query, fresh connection per query, `statement_timeout = 30min`. A month that
  hits the timeout is split into halves (down to 7 days); a chunk slower than 10 min makes later months
  use half-length chunks. Failed months are retried 3× with backoff, then recorded as failed in
  `data/crtsh/STATUS.json`; the run never aborts.
- Query shape (uses the full-text index on `identities(CERTIFICATE)`):
  `plainto_tsquery('certwatch', '<tld>') @@ identities(cai.CERTIFICATE) AND NAME_VALUE ILIKE '%.<tld>'
  AND NAME_TYPE IN ('dNSName','commonName') AND x509_notBefore(...) in [month)`; second pass with
  `xn--90a3ac`.
- Server quirks found on 2026-10-31: pgbouncer *statement pooling* — no transactions
  (`autocommit=True`), no `options=` startup parameter, and a `SET` only applies to the statement it is
  sent with, so the timeout is prepended to the query in one simple-query message (psycopg
  `ClientCursor`). The default timeout is 1 min. IPv6 to crt.sh times out from here; the A record is
  pinned via `hostaddr`. The server often answers `no more connections allowed (max_client_conn)`.
- Range: `crtsh.start`/`crtsh.end` (`--crtsh-start/--crtsh-end`). **Default is the last two months
  (2026-09-01 → today)**, decided 2026-10-31 instead of the two-year range first planned.
- Output: `data/crtsh/raw/{tld}/{YYYY-MM}.csv` (`name_value,not_before,issuer_ca_id,cert_id`),
  written atomically; complete months are skipped on re-run. `--finalize` writes `data/crtsh/names.txt`
  (distinct, lowercase, `*.` stripped), `registered_domains.txt` (via `publicsuffix2`) and
  `registered_domains.counts.csv` — no network.
- **Status 2026-10-31: deferred.** The one-month test showed `guest` statements are cancelled at ~60 s
  whatever `statement_timeout` says, planning alone took 30 s under load, and the plan scans all 26
  notAfter partitions, so `.rs` October timed out even at 7-day chunks (`.срб` returned 0 rows in 40 s —
  before the `san:dNSName` fix below). The server also refused connections (`max_client_conn`) several
  times. Options: retry off-peak with 1–3-day chunks, restrict `ISSUER_CA_ID` to the big CAs (Let's
  Encrypt R10–R14/E5–E9 are `ca.ID` 295809–295819), or switch the sample to an openly published zone file.
- Fixed from the task spec: SAN names are typed `san:dNSName` in `certificate_and_identities`; the spec's
  `NAME_TYPE IN ('dNSName','commonName')` only matched commonName.
- Known gaps: `commonName` entries can be non-DNS strings (dropped at finalize if they contain spaces);
  pre-certificates and leaf certificates both appear (dedupe by `cert_id` is not attempted here).

## Layout

```
config/fetch.yaml          all dates, hosts, TLDs, contact email
src/hijackscan/cli.py      hijackscan fetch ...
src/hijackscan/fetch/      common.py (HTTP, manifest, atomic writes) + one module per target
scripts/bgpy_smoke.py      standalone timing script
tests/                     URL construction and date iteration; integration tests need -m integration
data/                      downloads (git-ignored); data/MANIFEST.jsonl
```
