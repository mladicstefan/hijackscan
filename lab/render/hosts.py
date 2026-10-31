"""Per-host service configs: web.json for the two HTTP-01 responders, ca.json for the validator."""

from __future__ import annotations

import json
import shutil
from datetime import date
from pathlib import Path

from hijackscan.risk import RiskParams

from .topology import PERSPECTIVES, RESOLVER_IP

LAB_DIR = Path(__file__).resolve().parents[1]


def quorum(today: date | None = None) -> dict[str, int]:
    """The MPIC quorum in force today (BR 3.2.2.9), from the scanner's own table so lab CA and scanner agree."""
    today = today or date.today()
    p = RiskParams.for_date(today)
    remotes = len(PERSPECTIVES) - 1
    if remotes < p.remote_perspectives:
        raise SystemExit(
            f"the CA has {remotes} remote perspectives but BR 3.2.2.9 requires {p.remote_perspectives} on {today}: "
            f"add a perspective r{remotes + 1} to lab/render/topology.py"
        )
    return {"min_remote": p.remote_perspectives, "max_fail": p.allowed_non_corroborations}


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
                "quorum": quorum(),  # CA/B SC-067: the primary plus at most max_fail non-corroborating remotes
            },
            indent=1,
        )
    )
    shutil.copy(LAB_DIR / "ca.py", ca / "ca.py")
