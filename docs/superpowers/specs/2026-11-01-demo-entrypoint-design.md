# `uv run demo`: one entrypoint for a judge running hijackscan alone

Date: 2026-11-01. Branch: `start-script`.

## Intent

The pitch is five minutes and shows the tidied results and the SPA; the lab is only mentioned. Judges who
want to verify the claims will run the project at home, alone, probably once, on a machine we have never
seen. `uv run demo` is the one command for that person. It must work first try or say exactly why not, it
must narrate itself because nobody is talking over it, and it must end with a short verdict they can quote
rather than minutes of scrolling transcripts.

## Goals

- One command, `uv run demo`, that runs the README quick start for the scanner (`.ee` zone, 100 names, seed 1)
  and then the validation lab (containment check, matrix, negative controls), in that order.
- Two progress bars: an outer "step k of N: name" bar across the whole run, and an inner bar for the
  items of the step that is running (domains collected, matrix rows, controls).
- Terminal output limited to: the exact README command about to run, a one-line result per step, the
  few outputs worth reading in full, and a final scoreboard.
- Everything every step prints, verbatim and uncoloured, in one log file for the run.
- A preflight that names every missing prerequisite with the install line from the README before
  anything else runs.
- Exit 0 only when every step ran and passed.

## Non-goals

- The zone report's web UI: the zone component becomes a React SPA fed from MongoDB by a separate
  `hijackscan load` on another branch. The demo neither builds nor serves it and must not depend on it.
  It may leave an obvious place for a later "load" step but adds no code for it.
- Making the scanner or the lab faster, quieter or different. Nothing in `src/hijackscan/` (except the new
  module) or `lab/` changes for this. The README commands are run as they are.
- Narrating the pitch. The script is for the judge at home, not for the stage.

## Anti-goals (a failure even if it technically works)

- The demo prints a different verdict, label or score than the README commands would. It runs them, it
  does not reimplement them.
- A judge sees a Python traceback from a missing tool three minutes into the run.
- Output is silently lost: anything hidden from the terminal must be in the log file.
- The lab is left deployed on the judge's machine after a successful run.
- The bars corrupt the output when stdout is not a terminal (a judge piping into `tee`).

## Constraints

- Python, registered as `demo = "hijackscan.demo:main"` under `[project.scripts]` in `pyproject.toml`, module
  `src/hijackscan/demo.py`. Rich is already a dependency; no new dependency.
- The lab is mandatory. When preflight finds it cannot run, the scanner half still runs, then the demo
  prints the newest committed lab run (`lab/logs/<timestamp>-matrix/matrix.md`, these logs are untracked
  today and will be tracked) under the heading "lab run from <timestamp>, not reproduced on this machine",
  and exits non-zero. If no such run exists it says so.
- Dates and paths in the terminal are absolute or repo-relative; the judge must be able to open every
  file the scoreboard names.
- Data stays where the README puts it: `data/samples/ee100.txt`, `data/collected/`, `data/out/ee/`,
  `lab/logs/`. The demo's own log goes to `data/out/demo-<UTC timestamp>.log`.
- RFC 5737 / private-ASN discipline, provenance footers and the lab's reproducibility manifest are
  untouched because the lab code is untouched.

## Decided: how it is built

**Subprocesses, not in-process calls.** Each step is the README command run as a child process
(`uv run hijackscan …`, `uv run scripts/check_resolver.py`, `uv run lab/labctl.py …`). Reasons: the
command printed is then literally the command run, so a judge can copy any line; the scanner and lab
each install their own Rich logging handlers and `basicConfig`, which would fight a Rich `Live` display
in the same process; the lab modules are scripts with `sys.path` imports, not a package. The child's
stdout and stderr are read line by line as they arrive, appended to the log file, and fed to a per-step
line filter that drives the inner bar and decides what reaches the terminal. Children see no TTY, so Rich
in the child emits plain text, which is what the log wants.

**Steps** (the outer bar's N is this list, minus the lab steps when the lab is skipped):

| # | step | command | inner bar | shown in full |
|---|---|---|---|---|
| 0 | preflight | (checks below) | one tick per check | the table of checks, green/red |
| 1 | resolver | `uv run scripts/check_resolver.py` | none | one line: resolver and whether AD was set |
| 2 | sample | `uv run hijackscan sample data/samples/zone.ee.part-* --n 100 --seed 1 --out data/samples/ee100.txt` | none | one line: delegations, DS share, 100 drawn |
| 3 | collect | `uv run hijackscan collect data/samples/ee100.txt` | 100, advanced on each `[n/100] domain` line | one line: collected, from cache, with errors |
| 4 | zone | `uv run hijackscan zone data/samples/ee100.txt --out data/out/ee/` | none | the severity histogram the command prints, plus the two output paths |
| 5 | domain | `uv run hijackscan <top> --details` | none | everything the command prints |
| 6 | list | `uv run hijackscan list data/samples/ee100.txt --severity High,Critical` | none | everything the command prints |
| 7 | lab matrix | `uv run lab/labctl.py matrix` | 5 rows, advanced on each `row:` banner | the results block (from the `matrix: results` banner on) rendered as a table, and the `matrix: n/5 rows ok` line |
| 8 | lab controls | `uv run lab/labctl.py controls` | 4, advanced on each `A.`/`B.`/`C.`/`D.` banner | the four verdict lines and the final `controls:` line |
| 9 | lab check | `uv run lab/labctl.py check` | none | one line: OK or the violations. Runs after controls because `check` needs a deployed lab (README order); the matrix also checks containment per scenario and records it in the run directory |
| 10 | lab destroy | `uv run lab/labctl.py destroy` | none | one line |
| 11 | scoreboard | (no command) | | the scoreboard |

`<top>` in step 5 is the highest-scoring domain of the sample: read `data/out/ee/domains.jsonl` written
by step 4, take the first row by score (ties: first in file). It is not hardcoded so the demo stays honest
when the data changes.

**Preflight checks**, each with its README remedy printed on failure: Python ≥ 3.11 and `uv` (trivially
true if we are running, still listed); the zone parts and `data/samples/` present; Docker daemon reachable
(`docker info`); `containerlab version`; both as the current user, no sudo and no group check (see "Root
for the lab"); `ldns-signzone` on PATH; image `hijackscan-lab:latest` present (`docker image inspect`): its absence is a
warning, not a stop, because `labctl deploy` builds the image itself (commit d1beb5f); the warning says the
first matrix row will take several extra minutes. FRR image pullable is not checked (the matrix pulls it). Scanner prerequisites failing (zone parts missing, resolver not validating in step 1)
stop the run. Lab prerequisites failing switch the run to the fallback described under Constraints and
the outer bar's N shrinks accordingly; the judge is told this before step 1 starts.

**Progress display.** One Rich `Progress` with two tasks, outer and inner, rendered with `transient=False`
for the outer and the inner reset per step. Tables and shown-in-full output are printed through the
progress' console so they land above the bars. When stdout is not a TTY the bars are disabled and the
same lines are printed plainly. Elapsed time per step is printed in the one-line result; the README's
"about 4 min" for the matrix is the expectation to show next to its bar.

**Scoreboard** (step 11), a single Rich table followed by the paths:

- scanner: domains in sample, severity counts (Critical/High/Medium/Low/None/Unknown), collected from
  cache vs live, errors
- drill-down: the domain, its label, severity and score, and the one-line best fix the `domain` command printed
- lab: matrix n/5, controls n/4, containment OK/violations, or "not reproduced, showing run <timestamp>"
- paths: `data/out/ee/report.html`, `data/out/ee/domains.html`, the demo log, the lab run directory
  (`lab/logs/<timestamp>-matrix/`)

**Exit codes.** 0 all ran and passed; 1 a scanner step failed; 2 the lab ran and a row, control or the
containment check failed; 3 the lab could not run on this machine (fallback shown). The last line of the
terminal states the code's meaning in words.

**Flags**, for our own use, not advertised to judges: `--skip-lab` (behave as if preflight found no lab),
`--rows`/none. Keep it to `--skip-lab` and `-v` (also mirror the children's output to the terminal).

**Root for the lab.** The demo never calls sudo and never checks group membership. Every command runs as
the user who typed `uv run demo`; on a machine where that user cannot reach Docker, the whole demo is run as
root by that user's choice (`sudo uv run demo`), exactly as the lab is run there today. Preflight therefore
tests capability, not identity: `docker info` and `containerlab version` must succeed as the current user,
otherwise the lab cannot run and the fallback applies, with the README's group line printed as the remedy.

**Failure mid-run.** A failing step prints its last 30 log lines to the terminal, the log path, and stops;
later steps are not attempted except `lab destroy`, which always runs if any lab step started.

## Left to the builder

- Exact line patterns for the inner bars (take them from `collect/__init__.py`, `matrix.py`, `controls.py`
  as they are today; a pattern that stops matching must degrade to an indeterminate spinner, not a crash).
- How the matrix results are turned into a Rich table (parsing the `summary()` lines or reading the run
  directory's `matrix.md` after the child exits are both acceptable; `matrix.md` is simpler and already
  the canonical table).
- Locating the fallback run: the newest `lab/logs/*-matrix` directory by name that holds a complete
  `matrix.md` (the `latest-matrix` symlink is not trusted: it has pointed at an empty root-owned directory).
  The verdict is shown as the file states it, failed rows included. Controls come the same way from the
  newest `*-controls` directory with a `controls.log` that has a final `controls:` line. Dead directories
  in `lab/logs/` are pruned by hand before the logs are tracked; that is not the demo's job.
- README: add `uv run demo` as the first line of Quick start with one sentence saying what it does; do
  not remove the step-by-step commands.
- No tests (project preference). Verify by running `uv run demo --skip-lab`, then the full run on the lab
  machine, and by piping the full run into `tee` to confirm the non-TTY path.
