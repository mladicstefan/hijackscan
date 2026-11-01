# `uv run demo` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One command, `uv run demo`, that runs the README quick start and the validation lab as child processes, with an outer and an inner progress bar, a one log file, the few outputs worth reading, and a scoreboard.

**Architecture:** A small package `src/hijackscan/demo/` with a `Runner` (Rich two-bar progress, log file, line-streaming subprocess), a preflight, step definitions whose line filters drive the inner bar and pick what reaches the terminal, a lab-run locator for the fallback, and a scoreboard. Nothing in the scanner or `lab/` changes.

**Tech Stack:** Python ≥ 3.11, Rich (already a dependency), `subprocess`, `threading` (two reader threads per child so stdout and stderr both stream).

**Spec:** `docs/superpowers/specs/2026-11-01-demo-entrypoint-design.md`

## Global Constraints

- Registered as `demo = "hijackscan.demo:main"` in `pyproject.toml`; no new dependency.
- Every step runs the README command verbatim as a child process; the printed command is the executed command.
- The demo never calls sudo and never checks group membership; preflight tests `docker info` and `containerlab version` as the current user.
- All child output, uncoloured, goes to `data/out/demo-<UTC timestamp>.log` (`%Y%m%dT%H%M%SZ`).
- Exit codes: 0 all passed, 1 scanner step failed, 2 lab ran and failed, 3 lab not runnable (fallback shown). Last terminal line states the meaning in words.
- Flags: `--skip-lab`, `-v` only.
- No tests (project preference); each task ends with a manual verification command.
- No commits by the implementer: the project owner reviews and commits (git-review-gate).

## Review Focus

1. stdout not a TTY (`uv run demo | tee x`): bars off, same lines printed plainly, no escape codes in the log. Pinned in Task 1.
2. A child that prints a line not matching any pattern (future format change): inner bar stays a spinner, nothing crashes. Pinned in Task 3.
3. `data/out/ee/domains.jsonl` missing or empty after step 4: the domain step fails with a clear message, no `IndexError`. Pinned in Task 3.
4. Ctrl-C during the matrix: `lab destroy` still runs, log path printed, exit non-zero. Pinned in Task 4.
5. `lab/logs/` has only empty or aborted directories: the fallback says "no complete lab run found" rather than printing an empty table. Pinned in Task 4.

---

### Task 1: Runner, entrypoint, progress, log

**Files:**
- Create: `src/hijackscan/demo/__init__.py` (argparse, `main() -> int`, wiring of later tasks, initially runs one trivial step)
- Create: `src/hijackscan/demo/runner.py`
- Modify: `pyproject.toml` `[project.scripts]`: add `demo = "hijackscan.demo:main"`

**Interfaces (produces):**
```python
@dataclass
class StepResult:
    name: str
    command: list[str] | None
    returncode: int
    seconds: float
    lines: list[str]          # every stdout+stderr line, in arrival order, ANSI stripped
    facts: dict[str, str]     # whatever the step's line filter extracted

class Runner:
    def __init__(self, log_path: Path, verbose: bool = False) -> None
    def begin(self, total_steps: int) -> None                       # starts the Progress; outer task
    def step(self, title: str, inner_total: int | None = None, expect: str = "") -> None
        # advances the outer bar to this step, resets the inner (None = spinner); expect e.g. "about 4 min"
    def run(self, name: str, command: list[str], on_line: Callable[[str, Runner], None] | None = None,
            cwd: Path = REPO) -> StepResult
        # prints "$ <command>" (shlex.join), streams both pipes line by line to the log and to on_line,
        # mirrors to the terminal when verbose; returns when the child exits
    def tick(self, n: int = 1) -> None                               # inner bar advance
    def show(self, renderable) -> None                               # print above the bars (console.print)
    def result(self, ok: bool, text: str) -> None                    # the one-line result, ✔/✘, with seconds
    def tail(self, res: StepResult, n: int = 30) -> None             # last n lines, for failures
    def finish(self) -> None                                         # stops the Progress
    log_path: Path
```
Two reader threads per child push `(stream, line)` into a `queue.Queue`; the main thread drains it, strips ANSI with a regex, writes to the log, calls `on_line`. Rich `Progress(disable=not sys.stdout.isatty())` with two tasks; the outer uses `TextColumn("[bold]step {task.completed}/{task.total}: {task.description}")`, the inner shows description, bar, `n/total` or a spinner when total is None. Child env: inherit, add `TERM=dumb`, `NO_COLOR=1`, `PYTHONUNBUFFERED=1`, `COLUMNS=120`.

- [x] **Step 1:** Add the script entry to `pyproject.toml` and create `demo/__init__.py` with `main()` parsing `--skip-lab` and `-v`, creating `data/out/demo-<ts>.log`, and running one step `runner.run("echo", ["uv", "--version"])` then `runner.result(True, "uv ok")`.
- [x] **Step 2:** Implement `runner.py` per the interface.
- [x] **Step 3:** Verify: `uv run demo` prints the command, the result line, and leaves a log with the uv version line in it. Then `uv run demo | cat` prints the same without bars and `grep -c $'\x1b' data/out/demo-*.log` is 0 for the newest log (Review Focus 1).

### Task 2: Preflight

**Files:**
- Create: `src/hijackscan/demo/preflight.py`
- Modify: `src/hijackscan/demo/__init__.py` (call preflight before the steps)

**Interfaces (produces):**
```python
@dataclass
class Check:
    name: str
    ok: bool
    detail: str          # version or error text, one line
    remedy: str          # README install line, "" when ok
    lab: bool            # True: a lab prerequisite; False: a scanner prerequisite
    warn_only: bool = False

def preflight(runner: Runner) -> tuple[list[Check], bool]   # (checks, lab_available)
```
Checks, in this order, each one `runner.tick()`:
`python >= 3.11` (sys.version_info); `uv` (`uv --version`); zone parts (`data/samples/zone.ee.part-*` glob non-empty, remedy: "the zone parts are in the repository; run from a full clone"); `docker info` (lab, remedy: README Docker line); `containerlab version` (lab, remedy: the `curl -sL https://containerlab.dev/setup | sudo -E bash -s "install-containerlab"` line); `ldns-signzone -v` (lab, remedy: `sudo apt install ldnsutils` / `pacman -S ldns`); `docker image inspect hijackscan-lab:latest` (lab, `warn_only=True`, detail when missing: "labctl deploy builds it; the first matrix row takes several extra minutes"). `lab_available` is true when every `lab and not warn_only` check passed. Show the checks as a Rich table (name, ✔/✘/!, detail, remedy). A failed scanner check exits 1 immediately. When `lab_available` is false (or `--skip-lab`), print "lab: not runnable on this machine, the scanner runs and the newest recorded lab run is shown" and compute `total_steps` without the lab steps.

- [x] **Step 1:** Implement `preflight.py` and wire it in as step 0 (`runner.step("preflight", inner_total=7)`).
- [x] **Step 2:** Verify: `uv run demo` shows the table with every row green on the lab machine; `PATH=/usr/bin uv run demo` (or an equivalent that hides containerlab) shows the red row with the install line and the "not runnable" sentence.

### Task 3: Scanner steps

**Files:**
- Create: `src/hijackscan/demo/scanner.py`
- Modify: `src/hijackscan/demo/__init__.py` (run the six steps, stop on first failure with `runner.tail`)

**Interfaces (produces):**
```python
@dataclass
class ScannerSummary:
    sampled: int; collected: int; cached: int; errors: int
    severity: dict[str, int]            # Critical, High, Medium, Low, None, Unknown
    top_domain: str; top_label: str; top_severity: str; top_score: float; top_fix: str
    report_html: Path; domains_html: Path

def run_scanner(runner: Runner) -> ScannerSummary | None    # None after a failed step (already reported via runner.tail)
def top_domain(jsonl: Path) -> dict | None                   # first row of domains.jsonl, None when missing/empty
```
Commands and the lines each step keys on (regexes on ANSI-stripped lines, every one optional: a miss leaves the fact empty, never raises):

| step | command | keyed lines |
|---|---|---|
| resolver | `uv run scripts/check_resolver.py` | `resolver validates` → ok; exit code decides |
| sample | `uv run hijackscan sample data/samples/zone.ee.part-aa data/samples/zone.ee.part-ab --n 100 --seed 1 --out data/samples/ee100.txt` (the glob expanded in Python with `sorted(glob)`) | `zone ee  serial \d+: ([\d,]+) delegations, ([\d,]+) with DS`; `wrote (\d+) domains` |
| collect | `uv run hijackscan collect data/samples/ee100.txt` | `collect  (\d+) of (\d+) domains` → inner total = first group, cached = second minus first; `\[(\d+)/(\d+)\] ` → `runner.tick()`; `(\d+) collected in`; `(\d+) with errors` |
| zone | `uv run hijackscan zone data/samples/ee100.txt --out data/out/ee/` | the six histogram lines `^\s+(Critical|High|Medium|Low|None|Unknown)\s+(\d+)` are both parsed and shown in full; `wrote` line gives the paths |
| domain | `uv run hijackscan <top> --details` | every line shown in full; exit code 0–3 is the severity, not a failure (fail only on exit > 3 or a traceback) |
| list | `uv run hijackscan list data/samples/ee100.txt --severity High,Critical` | every line shown in full |

`<top>`: first line of `data/out/ee/domains.jsonl` → `domain`, `label`, `severity`, `score`, `fix.action`. If the file is missing or empty, `runner.result(False, "no domains.jsonl after the zone step")` and return None (Review Focus 3). The inner bar for collect is created with `inner_total=None` and given its total when the `collect N of M` line arrives; if that line never comes the spinner stays (Review Focus 2). One-line results: resolver "`<address>` validates DNSSEC"; sample "`<delegations>` delegations, `<ds>` with DS, 100 drawn"; collect "`<n>` collected live, `<cached>` from cache, `<errors>` with errors"; zone "report.html, domains.html written to data/out/ee/".

- [x] **Step 1:** Implement `scanner.py` and wire it in.
- [x] **Step 2:** Verify: `uv run demo --skip-lab` runs all six steps on cached data in under two minutes, the collect inner bar reaches 100/100 (or the `N of M` count), the drill-down and the list appear in full, and the log holds every `[n/100]` line. Expose `top_domain(jsonl: Path) -> dict | None` and confirm `uv run python -c "from pathlib import Path; from hijackscan.demo.scanner import top_domain; print(top_domain(Path('nope')))"` prints `None` (Review Focus 3).

### Task 4: Lab steps and fallback

**Files:**
- Create: `src/hijackscan/demo/lab.py`
- Modify: `src/hijackscan/demo/__init__.py`

**Interfaces (produces):**
```python
@dataclass
class LabSummary:
    reproduced: bool                 # False in the fallback
    run_dir: Path | None             # lab/logs/<ts>-matrix/
    matrix_ok: int; matrix_total: int
    controls_ok: int; controls_total: int
    containment: str                 # "OK" | "<n> violations" | "not checked"
    timestamp: str                   # from the run directory name

def run_lab(runner: Runner) -> LabSummary
def recorded_lab() -> LabSummary | None     # newest complete run, or None
```
`run_lab` steps: matrix `uv run lab/labctl.py matrix` (`runner.step("lab matrix", inner_total=5, expect="about 4 min")`; `^.*row: ` → tick; from the `matrix: results` banner onward every line is collected and shown in full after the child exits; `matrix: (\d+)/(\d+) rows ok`; `logs: (\S+)` gives `run_dir`); controls `uv run lab/labctl.py controls` (`inner_total=4`; `^#+ [ABCD]\. |^[ABCD]\. ` → tick; shown: lines starting with ✔/✘ and the final `controls:` line; `controls: all expected flips` → 4/4, `MISSING (\d+)` → 4−n); check `uv run lab/labctl.py check` (exit 0 → "OK", else count of lines); destroy `uv run lab/labctl.py destroy` always runs once matrix started, also from a `finally:` on `KeyboardInterrupt` (Review Focus 4). Matrix rows: 5 (`len(selected(None))` is not importable; hardcode 5 and 4 with a comment naming `lab/matrix.py ROWS` and `controls.py`).

`recorded_lab()`: `sorted(lab/logs.glob("*-matrix"))[::-1]`, first whose `matrix.md` exists and contains a `| baseline |` row; parse `| ... | yes |` / `| no |` cells for ok/total, timestamp from the name; controls likewise from the newest `*-controls/controls.log` whose last `controls:` line exists. None when nothing qualifies (Review Focus 5). The fallback prints the heading "lab run from <timestamp>, not reproduced on this machine", renders `matrix.md` through `rich.markdown.Markdown`, and the controls line.

- [x] **Step 1:** Implement `lab.py` and wire it: after the scanner, `run_lab` when the lab is available, else `recorded_lab()` and the fallback print.
- [x] **Step 2:** Verify fallback: `uv run demo --skip-lab` shows the 5/5 run from `lab/logs/20261101T000834Z-matrix` (the newest complete one today) and not the empty newer directories. Temporarily rename `lab/logs` to confirm the "no complete lab run found" message, restore.
- [ ] **Step 3:** Verify live: `uv run demo` on the lab machine, matrix inner bar 5/5, controls 4/4, lab destroyed afterwards (`docker ps` shows no `clab-hijackscan-*`). Press Ctrl-C during the second matrix row in one run and confirm destroy runs and the log path is printed.

### Task 5: Scoreboard, exit codes, README

**Files:**
- Create: `src/hijackscan/demo/scoreboard.py`
- Modify: `src/hijackscan/demo/__init__.py`, `README.md` (Quick start, first lines)

**Interfaces:**
```python
def scoreboard(runner: Runner, scanner: ScannerSummary, lab: LabSummary | None, log_path: Path) -> None
def exit_code(scanner_ok: bool, lab: LabSummary | None, lab_available: bool) -> int   # 0/1/2/3 per spec
```
One Rich table with sections scanner / drill-down / lab exactly as the spec lists them, then the four paths one per line, then the last line in words: "everything ran and passed" / "a scanner step failed, see <log>" / "the lab ran and <n> checks failed" / "the lab could not run here; the recorded run above is from <timestamp>".

- [x] **Step 1:** Implement `scoreboard.py`, call it, `return exit_code(...)` from `main`.
- [x] **Step 2:** README: under Quick start, before the scanner block, add `uv run demo    # the whole thing: README steps below plus the lab, two progress bars, one log, a scoreboard (lab: containerlab, Docker, ldns; ~10 min)` and one sentence that `sudo uv run demo` is the form on a machine where the user cannot reach Docker.
- [ ] **Step 3:** Verify: `uv run demo --skip-lab; echo $?` prints 3 with the fallback (done); `uv run demo; echo $?` prints 0 on the lab machine (open); `uv run demo | tee /tmp/demo.txt` shows no bars and the scoreboard intact.
