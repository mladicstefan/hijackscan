"""Steps 7-10: the validation lab as the README runs it, and the recorded run shown when the lab cannot run here.

`run_lab` runs `labctl.py matrix`, `controls`, `check` and `destroy` as children; destroy runs once the matrix
step has started, also after a failure or a Ctrl-C. `recorded_lab` finds the newest complete run under lab/logs/
by directory name (the `latest-matrix` link is not trusted: it has pointed at an empty root-owned directory) and
`show_recorded` prints it under a heading that says it was not reproduced on this machine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from rich.table import Table
from rich.text import Text

from .runner import REPO, Runner, StepResult

LOGS = REPO / "lab" / "logs"
LABCTL = ["uv", "run", "lab/labctl.py"]
# `len(matrix.selected(None))` is not importable from here (lab/ is scripts, not a package):
MATRIX_ROWS = 5  # lab/matrix.py ROWS
CONTROLS = 4  # lab/controls.py control_a .. control_d

# The children run without a TTY: console.stage() prints the Rule title at column 0 followed by box characters,
# and every logged line carries RichHandler's `HH:MM:SS ` prefix and is padded with spaces to the console width.
TIME = r"^(?:\d\d:\d\d:\d\d )?"
ROW_BANNER = re.compile(r"^row: ")
RESULTS_BANNER = re.compile(r"^matrix: results\b")
MATRIX_OK = re.compile(r"matrix: (\d+)/(\d+) rows ok")
LOGS_DIR = re.compile(r"logs: (\S+)")
CONTROL_BANNER = re.compile(r"^#+ [ABCD]\. |^[ABCD]\. ")
VERDICT = re.compile(TIME + r"[✔✘] ")
CONTROLS_ALL = re.compile(r"controls: all expected flips")
CONTROLS_MISSING = re.compile(r"controls: MISSING (\d+)")
CONTAINMENT_FAILED = re.compile(r"containment FAILED \((\d+) violations?\)")
STAMP = re.compile(r"^(\d{8}T\d{6}Z)-")


@dataclass
class LabSummary:
    reproduced: bool  # False in the fallback
    run_dir: Path | None  # lab/logs/<ts>-matrix/
    matrix_ok: int
    matrix_total: int
    controls_ok: int
    controls_total: int  # 0 in the fallback when no complete controls run is recorded
    containment: str  # "OK" | "<n> violations" | "not checked"
    timestamp: str  # from the run directory name

    @property
    def passed(self) -> bool:
        return (
            self.matrix_total > 0
            and self.matrix_ok == self.matrix_total
            and self.controls_ok == self.controls_total
            and self.containment == "OK"
        )


def _stamp(name: str) -> str:
    """`20261101T000834Z-matrix` -> `2026-11-01 00:08:34 UTC`; the raw prefix when it does not parse."""
    m = STAMP.match(name)
    raw = m.group(1) if m else name
    try:
        return datetime.strptime(raw, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return raw


# ----------------------------------------------------------------------------------------------- live run


class _Matrix:
    """Line filter for `labctl matrix`: a tick per row banner, the results block kept for after the exit."""

    def __init__(self, lab: LabSummary) -> None:
        self.lab = lab
        self.results: list[str] = []
        self.in_results = False

    def __call__(self, line: str, runner: Runner) -> None:
        if ROW_BANNER.match(line):
            runner.tick()
            return
        if RESULTS_BANNER.match(line):
            self.in_results = True
        if m := LOGS_DIR.search(line):
            self.lab.run_dir = Path(m.group(1))
            self.lab.timestamp = _stamp(self.lab.run_dir.name)
        if m := MATRIX_OK.search(line):
            self.lab.matrix_ok, self.lab.matrix_total = int(m.group(1)), int(m.group(2))
        if self.in_results:
            self.results.append(line.rstrip())


class _Controls:
    """Line filter for `labctl controls`: a tick per control banner, verdict lines straight to the terminal."""

    def __init__(self, lab: LabSummary) -> None:
        self.lab = lab
        self.verdict_seen = False  # the final `controls:` line arrived

    def __call__(self, line: str, runner: Runner) -> None:
        if CONTROL_BANNER.match(line):
            runner.tick()
            return
        if VERDICT.match(line):
            runner.show(line.rstrip())
        if CONTROLS_ALL.search(line):
            self.lab.controls_ok, self.verdict_seen = self.lab.controls_total, True
        elif m := CONTROLS_MISSING.search(line):
            self.lab.controls_ok, self.verdict_seen = max(0, self.lab.controls_total - int(m.group(1))), True


def _check_lines(res: StepResult) -> str:
    """`OK`, or the count of violations the check printed (its FAILED line, else its VIOLATION lines)."""
    if res.ok:
        return "OK"
    for line in reversed(res.lines):
        if m := CONTAINMENT_FAILED.search(line):
            return f"{m.group(1)} violations"
    n = sum(1 for line in res.lines if "VIOLATION" in line)
    return f"{n} violations" if n else f"check exited {res.returncode}"


def run_lab(runner: Runner) -> LabSummary:
    """Matrix, controls, check, destroy. A failing step stops the rest but never the destroy; so does Ctrl-C."""
    lab = LabSummary(
        reproduced=True,
        run_dir=None,
        matrix_ok=0,
        matrix_total=MATRIX_ROWS,
        controls_ok=0,
        controls_total=CONTROLS,
        containment="not checked",
        timestamp="",
    )
    runner.step("lab matrix", inner_total=MATRIX_ROWS, expect="about 4 min")
    try:
        matrix = _Matrix(lab)
        res = runner.run("matrix", [*LABCTL, "matrix"], matrix)
        for line in matrix.results:
            runner.show(line)
        if not res.ok and not matrix.results:
            runner.tail(res)
        where = f"  ({lab.run_dir})" if lab.run_dir else ""
        runner.result(res.ok, f"matrix {lab.matrix_ok}/{lab.matrix_total} rows ok{where}")
        if not res.ok:
            return lab

        runner.step("lab controls", inner_total=CONTROLS)
        controls = _Controls(lab)
        res = runner.run("controls", [*LABCTL, "controls"], controls)
        if not res.ok and not controls.verdict_seen:  # died before its verdict line
            runner.tail(res)
        runner.result(res.ok, f"controls {lab.controls_ok}/{lab.controls_total} expected flips observed")
        if not res.ok:
            return lab

        runner.step("lab check")
        res = runner.run("check", [*LABCTL, "check"])
        lab.containment = _check_lines(res)
        for line in res.lines:
            if "VIOLATION" in line:
                runner.show(line.rstrip())
        runner.result(res.ok, f"containment {lab.containment}")
    finally:
        runner.step("lab destroy")
        res = runner.run("destroy", [*LABCTL, "destroy"])
        if not res.ok:
            runner.tail(res, n=10)
        runner.result(res.ok, "lab destroyed" if res.ok else "destroy failed: check `docker ps` for clab-hijackscan-*")
    return lab


# ----------------------------------------------------------------------------------------------- fallback


def _read(path: Path) -> str | None:
    """The file's text, or None when it is missing or unreadable (several lab/logs directories are root-owned)."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:  # FileNotFoundError, PermissionError, NotADirectoryError
        return None


def _table_cells(matrix_md: str) -> list[list[str]]:
    """The cells of every data row of matrix.md (header and rule skipped)."""
    rows = []
    for line in matrix_md.splitlines():
        if not line.startswith("|") or line.startswith("|---") or line.startswith("| scenario |"):
            continue
        parts = [c.strip() for c in line.strip().strip("|").split("|")]
        if parts:
            rows.append(parts)
    return rows


def _table_rows(matrix_md: str) -> list[str]:
    """The last cell (`ok` column) of every data row of matrix.md."""
    return [r[-1] for r in _table_cells(matrix_md)]


def _compact(matrix_md: str) -> Table:
    """Six of matrix.md's ten columns, enough to read the claim; the full table stays in matrix.md."""
    t = Table(box=None, pad_edge=False, header_style="bold")
    for col in ("scenario", "attack", "scanner", "CA -> attacker", "expected", "ok"):
        t.add_column(col)
    for cells in _table_cells(matrix_md):
        if len(cells) < 10:
            continue
        scenario, mode, _plane, label, _ev, ca_a, _hosts, _ca_l, expected, ok = cells[:10]
        verdict = ca_a.split(":")[0]
        t.add_row(scenario, mode, label, verdict, expected, f"[{'ok' if ok == 'yes' else 'fail'}]{ok}[/]")
    return t


def _recorded_containment(run_dir: Path, matrix_md: str) -> str:
    if "Containment violations:" in matrix_md:
        n = sum(1 for ln in matrix_md.splitlines() if ln.startswith("- "))
        return f"{n} violations"
    checks = [_read(p) for p in sorted(run_dir.glob("*-check.log"))]
    if checks and all(c is not None and c.strip() == "containment: OK" for c in checks):
        return "OK"
    return "not checked"


def _recorded_controls() -> tuple[int, int, Path | None]:
    """(ok, total, log) from the newest *-controls/controls.log that reached its final `controls:` line."""
    for d in sorted(LOGS.glob("*-controls"))[::-1]:
        text = _read(d / "controls.log")
        if text is None:
            continue
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines or not lines[-1].startswith("controls: "):
            continue
        last = lines[-1]
        if CONTROLS_ALL.search(last):
            return CONTROLS, CONTROLS, d / "controls.log"
        if m := CONTROLS_MISSING.search(last):
            return max(0, CONTROLS - int(m.group(1))), CONTROLS, d / "controls.log"
    return 0, 0, None


def recorded_lab() -> LabSummary | None:
    """The newest complete matrix run by directory name, with the newest complete controls run; None if none."""
    try:
        dirs = sorted(LOGS.glob("*-matrix"))[::-1]
    except OSError:
        return None
    for d in dirs:
        text = _read(d / "matrix.md")
        if text is None or "| baseline |" not in text:
            continue
        verdicts = _table_rows(text)
        controls_ok, controls_total, _ = _recorded_controls()
        return LabSummary(
            reproduced=False,
            run_dir=d,
            matrix_ok=sum(v == "yes" for v in verdicts),
            matrix_total=len(verdicts),
            controls_ok=controls_ok,
            controls_total=controls_total,
            containment=_recorded_containment(d, text),
            timestamp=_stamp(d.name),
        )
    return None


def show_recorded(runner: Runner, lab: LabSummary) -> None:
    """The fallback: the recorded matrix.md rendered, then the controls line."""
    runner.show(Text(f"lab run from {lab.timestamp}, not reproduced on this machine", style="bold"))
    text = _read(lab.run_dir / "matrix.md") if lab.run_dir else None
    if text is None:
        runner.note(f"matrix.md unreadable in {lab.run_dir}")
    else:
        runner.show(_compact(text))
        runner.show("")
    runner.show(f"matrix: {lab.matrix_ok}/{lab.matrix_total} rows ok, containment {lab.containment}")
    runner.show(f"  full table and per-row transcripts: {lab.run_dir}")
    _, _, controls_log = _recorded_controls()
    if controls_log is None:
        runner.show("controls: no complete recorded run (no controls.log reached its final `controls:` line)")
    else:
        runner.show(f"controls: {lab.controls_ok}/{lab.controls_total} expected flips observed")
        runner.show(f"  transcript: {controls_log}")
