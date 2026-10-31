"""Per-host service configs: web.json for the two HTTP-01 responders, ca.json for the validator."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from .topology import PERSPECTIVES, RESOLVER_IP

LAB_DIR = Path(__file__).resolve().parents[1]


def render_hosts(sc: dict, build: Path) -> None:
    acct, tok = sc["ca"]["accounts"], sc["ca"]["tokens"]
    for host, who in (("victim", "legit"), ("attacker", "attacker")):
        (build / host).mkdir(exist_ok=True)
        (build / host / "web.json").write_text(json.dumps({"label": host, "tokens": {tok[who]: acct[who]}}, indent=1))
    ca = build / "ca"
    ca.mkdir(exist_ok=True)
    (ca / "ca.json").write_text(
        json.dumps(
            {
                "id": sc["ca"]["id"],
                "domain": sc["domain"],
                "resolver": RESOLVER_IP,
                "accounts": acct,
                "tokens": tok,
                "perspectives": [p.__dict__ for p in PERSPECTIVES],
                "quorum": {"min_remote": 4, "max_fail": 1},  # CA/B SC-067: at most one non-corroborating remote
            },
            indent=1,
        )
    )
    shutil.copy(LAB_DIR / "ca.py", ca / "ca.py")
