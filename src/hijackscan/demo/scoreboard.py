"""The last screen: one table a judge can quote, the four paths, and the exit code in words."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from rich.table import Table

from ..console import sev
from .runner import REPO, Runner

if TYPE_CHECKING:
    from .lab import LabSummary
    from .scanner import ScannerSummary

SEVERITIES = ("Critical", "High", "Medium", "Low", "None", "Unknown")


def _rel(p: Path | None) -> str:
    if p is None:
        return "-"
    try:
        return str(p.relative_to(REPO))
    except ValueError:
        return str(p)


def scoreboard(runner: Runner, scanner: ScannerSummary | None, lab: LabSummary | None, log_path: Path) -> None:
    t = Table(show_header=False, box=None, pad_edge=False, title="[bold]scoreboard", title_justify="left")
    t.add_column("section", style="bold cyan")
    t.add_column("key")
    t.add_column("value")
    if scanner is None:
        t.add_row("scanner", "", "[fail]did not complete[/]")
    else:
        counts = "  ".join(sev(s, f"{s} {scanner.severity.get(s, 0)}") for s in SEVERITIES)
        t.add_row("scanner", "domains", f"{scanner.sampled} sampled from the .ee zone (seed 1)")
        t.add_row("", "severity", counts)
        t.add_row(
            "", "collected", f"{scanner.collected} live, {scanner.cached} from cache, {scanner.errors} with errors"
        )
        t.add_row(
            "drill-down",
            "domain",
            f"{scanner.top_domain}  {scanner.top_label}  {sev(scanner.top_severity)} {scanner.top_score}",
        )
        t.add_row("", "best fix", scanner.top_fix or "-")
    if lab is None:
        t.add_row("lab", "", "[fail]no recorded run found and not reproduced here[/]")
    else:
        how = (
            "reproduced on this machine"
            if lab.reproduced
            else f"[note]not reproduced here: recorded run from {lab.timestamp}[/]"
        )
        t.add_row("lab", "", how)
        m_ok = lab.matrix_ok == lab.matrix_total and lab.matrix_total > 0
        c_ok = lab.controls_ok == lab.controls_total and lab.controls_total > 0
        t.add_row(
            "",
            "matrix",
            f"[{'ok' if m_ok else 'fail'}]{lab.matrix_ok}/{lab.matrix_total} rows[/]  scanner verdict = CA decision",
        )
        t.add_row(
            "",
            "controls",
            f"[{'ok' if c_ok else 'fail'}]{lab.controls_ok}/{lab.controls_total} flips[/]  "
            "each verdict flips when its mechanism is removed",
        )
        t.add_row("", "containment", lab.containment)
    runner.show(t)
    runner.show("")
    paths = [
        ("zone report", scanner.report_html if scanner else None),
        ("per-domain page", scanner.domains_html if scanner else None),
        ("demo log", log_path),
        ("lab evidence", lab.run_dir if lab else None),
    ]
    for name, p in paths:
        runner.console.print(f"  [dim]{name:<16}[/] {_rel(p)}")


def exit_code(scanner_ok: bool, lab: LabSummary | None, lab_available: bool) -> int:
    """0 all passed, 1 scanner failed, 2 lab ran and failed, 3 lab not runnable here."""
    if not scanner_ok:
        return 1
    if not lab_available:
        return 3
    if lab is None or not lab.reproduced:
        return 3
    ok = lab.matrix_ok == lab.matrix_total and lab.controls_ok == lab.controls_total and lab.containment == "OK"
    return 0 if ok else 2
