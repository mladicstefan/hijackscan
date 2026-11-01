"""`uv run demo`: the README quick start and the validation lab, run for a judge who is alone with the repo.

Every step is the README command, run as a child process; an outer bar counts steps, an inner bar counts the
step's items; everything a child prints goes to data/out/demo-<UTC timestamp>.log; the terminal gets the
command, a one-line result, the few outputs worth reading in full, and a scoreboard. Design:
docs/superpowers/specs/2026-11-01-demo-entrypoint-design.md.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime

from .lab import LabSummary, recorded_lab, run_lab, show_recorded
from .preflight import preflight
from .runner import REPO, Runner
from .scanner import run_scanner
from .scoreboard import exit_code, scoreboard

EXIT_WORDS = {
    0: "everything ran and passed",
    1: "a scanner step failed",
    2: "the lab ran and some of its checks failed",
    3: "the lab could not run on this machine; the recorded run above stands in for it",
}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="demo", description=__doc__.splitlines()[0])
    p.add_argument("--skip-lab", action="store_true", help="do not run the lab, show the newest recorded run instead")
    p.add_argument("-v", "--verbose", action="store_true", help="also mirror every child line to the terminal")
    return p


def main() -> int:
    a = parser().parse_args()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    log = REPO / "data" / "out" / f"demo-{stamp}.log"
    for i in range(2, 100):  # two runs in one second must not share a log
        if not log.exists():
            break
        log = log.with_name(f"demo-{stamp}-{i}.log")
    runner = Runner(log, verbose=a.verbose)
    code = 1
    try:
        code = _run(runner, skip_lab=a.skip_lab)
    except KeyboardInterrupt:
        runner.note("interrupted")
        code = 130
    finally:
        runner.finish()
    if code in EXIT_WORDS:
        runner.console.print(f"\n[bold]exit {code}: {EXIT_WORDS[code]}[/]")
    return code


SCANNER_STEPS = 6  # resolver, sample, collect, zone, domain, list
LAB_STEPS = 4  # matrix, controls, check, destroy (one step, the recorded run, when the lab cannot run here)


def _run(runner: Runner, skip_lab: bool) -> int:
    runner.begin()  # the outer total is settled after preflight: the lab steps drop out when the lab cannot run here
    runner.step("preflight", inner_total=7)
    checks, lab_available = preflight(runner)
    missing = [c for c in checks if not c.ok and not c.lab]
    if missing:
        runner.result(False, "scanner prerequisites missing: " + ", ".join(c.name for c in missing))
        return 1
    if skip_lab:
        lab_available = False
        runner.note("--skip-lab: the lab is not run; the newest recorded run is shown instead")
    elif not lab_available:
        runner.note(
            "lab: not runnable on this machine (see the table); the scanner runs, the newest recorded lab run is shown"
        )
    runner.retotal(1 + SCANNER_STEPS + (LAB_STEPS if lab_available else 1) + 1)
    runner.result(True, "prerequisites checked" + ("" if lab_available else ", lab unavailable"))

    scanner = run_scanner(runner)
    lab: LabSummary | None = None
    if scanner is not None and lab_available:
        lab = run_lab(runner)
    elif scanner is not None:
        lab = recorded_lab()
        runner.step("lab: recorded run")
        if lab is None:
            runner.result(False, "no complete lab run found under lab/logs/ and the lab cannot run here")
        else:
            show_recorded(runner, lab)
            runner.result(True, f"recorded run from {lab.timestamp}: matrix {lab.matrix_ok}/{lab.matrix_total}")
    runner.step("scoreboard")
    scoreboard(runner, scanner, lab, runner.log_path)
    return exit_code(scanner is not None, lab, lab_available)


if __name__ == "__main__":
    sys.exit(main())
