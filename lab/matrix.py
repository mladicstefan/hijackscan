"""The validation matrix (design/lab.md §2.4): every row applied, scanned, attacked and validated, then compared."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import labctl
from render import SCENARIOS

# scenario, attack mode, expected scanner label, expected CA decision for the attacker
ROWS = [
    ("baseline", "web", "open-web", "ISSUED"),
    ("tight-maxlength", "web", "contested", "REFUSED"),
    ("caa-unsigned", "web", "caa-erasable", "REFUSED"),
    ("caa-unsigned", "web+ns", "caa-erasable", "ISSUED"),
    ("caa-signed", "web+ns", "closed", "REFUSED"),
]


def scan_label(build: Path, sc: dict) -> str:
    """The risk label from the scanner's summary line `victim.rs  CRITICAL 10.0  open-web`."""
    out = labctl.scan(build, sc, False, capture=True).stdout
    m = re.search(rf"^{re.escape(sc['domain'])}\s+(\S+)\s+(\S+)\s+(\S+)", out, re.M)
    return f"{m.group(3)} ({m.group(1)} {m.group(2)})" if m else "?"


def decision(account: str, log_to: Path | None = None) -> str:
    r = subprocess.run(
        [
            "docker",
            "exec",
            f"clab-{labctl.LAB}-ca",
            "python3",
            "/lab/ca.py",
            "--config",
            "/lab/ca.json",
            "--account",
            account,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if log_to:
        log_to.write_text(r.stdout)
    m = re.search(r"\[decision \] (ISSUED|REFUSED)", r.stdout)
    return m.group(1) if m else "?"


def run_matrix(build: Path) -> int:
    results = []
    applied = None
    for scenario, mode, want_label, want_ca in ROWS:
        print(f"\n=== {scenario} / attack {mode}", flush=True)
        if scenario != applied:
            sc = labctl.render(SCENARIOS / f"{scenario}.yml", build)
            labctl.deploy(build)
            labctl.attack("off", sc)
            applied = scenario
        label = scan_label(build, sc)
        labctl.attack(mode, sc)
        logs = build.parent / "logs"  # outside build/, which every render wipes
        logs.mkdir(exist_ok=True)
        ca_attacker = decision("attacker", logs / f"{scenario}-{mode}-attacker.log")
        labctl.attack("off", sc)
        ca_legit = decision("legit", logs / f"{scenario}-{mode}-legit.log")
        ok = label.startswith(want_label) and ca_attacker == want_ca and ca_legit == "ISSUED"
        results.append((scenario, mode, label, ca_attacker, ca_legit, want_label, want_ca, ok))
        print(f"scanner {label}; CA attacker {ca_attacker} (expected {want_ca}); CA legit {ca_legit}", flush=True)
        if not ok:
            print((logs / f"{scenario}-{mode}-attacker.log").read_text())
    print("\n| scenario | attack | scanner | CA → attacker | CA → legit (attack off) | expected | ok |")
    print("|---|---|---|---|---|---|---|")
    for scenario, mode, label, ca_a, ca_l, want_label, want_ca, ok in results:
        verdict = "yes" if ok else "NO"
        print(f"| {scenario} | {mode} | {label} | {ca_a} | {ca_l} | {want_label} / {want_ca} | {verdict} |")
    return 0 if all(r[-1] for r in results) else 1
