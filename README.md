# hijackscan

How exposed are the domains of a TLD (`.ee` from its zone file, `.rs` from a list) to certificate theft through
BGP hijacks below DNS, and how much of it does DNSSEC + CAA close? (team dogma, DNS SEC Hackathon 2026)

Two parts, each documented end to end:

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
uv run hijackscan zone data/samples/ee100.txt --out data/out/ee/
uv run hijackscan rnids.rs --details
uv run hijackscan list --severity High,Critical

# lab (containerlab, docker and clab_admins groups, the lab image: docs/lab.md §4)
uv run lab/labctl.py matrix        # every row: render, deploy, scan, attack, CA (about 4 min), evidence in lab/logs/
uv run lab/labctl.py controls      # negative controls: every verdict flips when its mechanism is removed
uv run lab/labctl.py check         # containment: no route off the box, private ASNs, RFC 5737 only
uv run lab/labctl.py destroy
```

Every domain gets a risk score 0–10 on the CVSS severity scale (None / Low / Medium / High / Critical, plus
Unknown when the record is incomplete). Exit codes of `hijackscan <domain>`: 0 None, 1 Low / Medium,
2 High / Critical, 3 Unknown.

## Layout

| path | what |
|---|---|
| `src/hijackscan/collect/` | observes: zone file sampler, DNS, RIPEstat, the ROA archive |
| `src/hijackscan/score.py`, `risk.py` | pure: exposure class, risk score, fixes |
| `src/hijackscan/report/` | terminal, HTML and zone reports, the `list` view |
| `lab/` | the containerlab lab: `labctl.py`, scenario files, renderers, the CA, the feed, the matrix and controls |
| `design/` | formula and lab decisions |
| `data/samples/` | the `.ee` zone file and the two 100-domain samples (everything else under `data/` is generated) |
