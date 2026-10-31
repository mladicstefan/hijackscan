"""RPKI ground truth in three shapes: StayRTR's rpki.json, the scanner's archive day, the feed's config."""

from __future__ import annotations

import csv
import io
import json
import lzma
from pathlib import Path

# Fixed timestamps (the same window as the DNSSEC signatures in dns.py), so a build is reproducible; StayRTR
# runs with -checktime=false (clab.py) and does not enforce `valid` anyway.
GENERATED = 1767225600  # 2026-01-01T00:00:00Z
VALID = 1830297599  # 2027-12-31T23:59:59Z


def render_rpki(sc: dict, build: Path) -> None:
    roas = sc["roas"]
    rpki_dir = build / "rpki"
    rpki_dir.mkdir(parents=True, exist_ok=True)
    (rpki_dir / "rpki.json").write_text(
        json.dumps(
            {
                "metadata": {"counts": len(roas), "generated": GENERATED, "valid": VALID},
                "roas": [
                    {"prefix": r["prefix"], "maxLength": r["max_length"], "asn": f"AS{r['asn']}", "ta": "lab"}
                    for r in roas
                ],
            },
            indent=1,
        )
        + "\n"
    )
    # The RIPE NCC archive format read by hijackscan.collect.rpki.RoaIndex: data/rpki/<day>/<ta>/roas.csv.xz
    day = build / "data" / "rpki" / "lab" / "lab"
    day.mkdir(parents=True, exist_ok=True)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["URI", "ASN", "IP Prefix", "Max Length", "Not Before", "Not After"])
    for r in roas:
        w.writerow(
            [
                f"rsync://rpki.lab/{r['prefix'].replace('/', '-')}.roa",
                f"AS{r['asn']}",
                r["prefix"],
                r["max_length"],
                "2026-01-01 00:00:00",
                "2027-01-01 00:00:00",
            ]
        )
    with lzma.open(day / "roas.csv.xz", "wt", encoding="utf-8") as f:
        f.write(buf.getvalue())
    (build / "feed.json").write_text(
        json.dumps({"as_names": {str(k): v for k, v in sc["as_names"].items()}, "roas": roas}, indent=1) + "\n"
    )
