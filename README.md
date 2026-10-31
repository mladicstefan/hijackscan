# hijackscan

How exposed is the `.rs` namespace to certificate theft through BGP hijacks below DNS, and how much
of it does DNSSEC + CAA close? (team dogma, DNS SEC Hackathon 2026)

```bash
uv sync
uv run hijackscan collect                      # data/domains.txt -> data/facts.jsonl
uv run hijackscan collect --limit 5 -v         # try a few first
uv run hijackscan collect --resolver 127.0.0.1 # use our own validating resolver
```

## Data

| File | What | Size |
|---|---|---|
| `data/domains.txt` | the 100 `.rs` domains under study (one-off: top `.rs` names from Tranco list 746VX, 2026-10-30) | 2 KB |
| `data/facts.jsonl` | one JSON object per domain: web addresses, nameservers and their addresses, each with covering prefix, origin AS, RPKI status and ROAs (maxLength); CAA (after the RFC 8659 tree climb), DS, DNSKEY, AD bit | ~300 KB |
| `data/ripestat/` | raw RIPEstat responses (`network-info`, `rpki-validation`), one JSON per call, reused on re-run | ~1 MB |

Sources: DNS answers come from the resolver named in each record (`--resolver`; the AD bit is only
meaningful with a validating one — the systemd-resolved stub at 127.0.0.53 does not validate).
Routing facts come from the RIPEstat Data API (`sourceapp=hijackscan`, sequential, cached).
No scanning, no AXFR, read-only public APIs.

`forgeable_more_specific` is the key routing signal: a ROA whose `max_length` is longer than the
announced prefix lets an attacker announce an RPKI-*valid* more-specific with the victim's origin AS
(the 28 Aug 2026 Hetzner pattern), which wins by longest-prefix match everywhere.
