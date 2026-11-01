"""The demo's engine: two progress bars, one log file, children streamed line by line.

Every step is a README command run as a child process. Both of its pipes are read by threads and drained
here, line by line: each line is stripped of colour codes, appended to the log, and handed to the step's
`on_line` filter, which advances the inner bar and decides what reaches the terminal. The terminal itself
only gets what goes through `show()` and `result()`, printed above the bars. When stdout is not a terminal
the bars are disabled and the same lines print plainly.
"""

from __future__ import annotations

import os
import queue
import re
import shlex
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console, RenderableType
from rich.markup import escape
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.theme import Theme

from ..config import project_root
from ..console import THEME as REPORT_THEME
from ..console import paint

REPO = project_root()
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
CHILD_ENV = {"TERM": "dumb", "NO_COLOR": "1", "PYTHONUNBUFFERED": "1", "COLUMNS": "120", "PYTHONIOENCODING": "utf-8"}
# The children print plain text (NO_COLOR); every line shown here goes through the scanner's `paint`, which
# needs the scanner's theme (severity colours, keys, verdicts) next to the demo's own styles.
THEME = Theme({**REPORT_THEME.styles, "cmd": "dim"})

OnLine = Callable[[str, "Runner"], None]


@dataclass
class StepResult:
    name: str
    command: list[str] | None
    returncode: int
    seconds: float
    lines: list[str] = field(default_factory=list)  # stdout + stderr in arrival order, colour codes stripped
    facts: dict[str, str] = field(default_factory=dict)  # whatever the step's filter extracted

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Runner:
    def __init__(self, log_path: Path, verbose: bool = False) -> None:
        self.log_path = log_path
        self.verbose = verbose
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log = log_path.open("w", encoding="utf-8")
        tty = sys.stdout.isatty()
        self.console = Console(theme=THEME, highlight=False, width=None if tty else 120)
        self.progress = Progress(
            TextColumn("{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("{task.fields[count]}"),
            TimeElapsedColumn(),
            SpinnerColumn(finished_text=" "),
            console=self.console,
            disable=not tty,
            transient=False,
        )
        self._outer: TaskID | None = None
        self._inner: TaskID | None = None
        self._step_started = 0.0
        self._step_no = 0
        self._total = 0

    # ------------------------------------------------------------------ lifecycle

    def begin(self, total_steps: int | None = None) -> None:
        """Start the bars; the outer total may wait for preflight (`retotal`), the banner then omits it."""
        self._total = total_steps or 0
        self.progress.start()
        self._outer = self.progress.add_task("[bold]demo", total=total_steps, count="")
        self._inner = self.progress.add_task("", total=None, count="", visible=False)
        self.note(f"log: {self.log_path}")

    def step(self, title: str, inner_total: int | None = None, expect: str = "") -> None:
        """Advance the outer bar to this step and reset the inner one (None = spinner)."""
        self._step_no += 1
        self._step_started = time.monotonic()
        suffix = f"  [dim]({escape(expect)})[/]" if expect else ""
        label = f"step {self._step_no}/{self._total}" if self._total else f"step {self._step_no}"
        self.console.print()
        self.console.print(Rule(f"[stage]{label}: {escape(title)}[/]{suffix}", align="left", style="cyan"))
        self._write(f"\n==== {label}: {title}\n")
        assert self._outer is not None and self._inner is not None
        self.progress.update(
            self._outer,
            completed=self._step_no - 1,
            description=f"[bold]{label}: {escape(title)}",
        )
        self.progress.reset(self._inner, total=inner_total, description=f"  {escape(title)}", visible=True)
        self.progress.update(self._inner, count=self._count(0, inner_total))

    def retotal(self, total_steps: int) -> None:
        """Settle the outer total once preflight knows whether the lab steps run."""
        self._total = total_steps
        assert self._outer is not None
        self.progress.update(self._outer, total=total_steps)

    def inner_total(self, total: int) -> None:
        """Give the inner bar its total once the step reveals it (collect prints `N of M` first)."""
        assert self._inner is not None
        done = int(self.progress.tasks[self._inner].completed)
        self.progress.update(self._inner, total=total, count=self._count(done, total))

    def tick(self, n: int = 1) -> None:
        assert self._inner is not None
        t = self.progress.tasks[self._inner]
        done = int(t.completed) + n
        self.progress.update(self._inner, completed=done, count=self._count(done, t.total))

    def finish(self) -> None:
        if self._outer is not None:
            self.progress.update(self._outer, completed=self._total, description="[bold]demo")
        if self._inner is not None:
            self.progress.update(self._inner, visible=False)
        self.progress.stop()
        self._log.close()

    # ------------------------------------------------------------------ children

    def run(self, name: str, command: list[str], on_line: OnLine | None = None, cwd: Path = REPO) -> StepResult:
        """Run one README command, streaming both pipes to the log and to `on_line`; mirror when verbose."""
        self.cmd(shlex.join(command))
        t0 = time.monotonic()
        res = StepResult(name=name, command=command, returncode=-1, seconds=0.0)
        env = {**os.environ, **CHILD_ENV}
        try:
            proc = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except OSError as e:
            res.lines.append(f"cannot start: {e}")
            self._write(res.lines[-1] + "\n")
            res.returncode = 127
            return res
        q: queue.Queue[tuple[str, str | None]] = queue.Queue()

        def pump(stream, tag: str) -> None:
            for line in iter(stream.readline, ""):
                q.put((tag, line.rstrip("\n")))
            q.put((tag, None))

        threads = [
            threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True),
            threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True),
        ]
        for t in threads:
            t.start()
        open_streams = 2
        try:
            while open_streams:
                tag, line = q.get()
                if line is None:
                    open_streams -= 1
                    continue
                clean = ANSI.sub("", line)
                res.lines.append(clean)
                self._write(clean + "\n")
                if self.verbose:
                    self.console.print(escape(clean), style="dim")
                if on_line is not None:
                    try:
                        on_line(clean, self)
                    except Exception as e:  # a filter must never kill the demo
                        self._write(f"[demo] filter error on line {clean!r}: {e}\n")
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
            raise
        res.returncode = proc.returncode
        res.seconds = time.monotonic() - t0
        self._write(f"[demo] exit {res.returncode} after {res.seconds:.0f}s\n")
        return res

    # ------------------------------------------------------------------ terminal

    def show(self, renderable: RenderableType | str) -> None:
        """Print above the bars: a table, or a verbatim line from a child (coloured by its shape, text unchanged)."""
        if isinstance(renderable, str):
            self.console.print(paint(renderable), soft_wrap=True)
        else:
            self.console.print(renderable)

    def explain(self, text: str) -> None:
        """One sentence, before a block of child output, saying what it shows and what to look at."""
        self.console.print(f"[explain]{escape(text)}[/]", soft_wrap=True)
        self._write(f"[demo] {text}\n")

    def cmd(self, command: str) -> None:
        self.console.print(f"[cmd]$ {escape(command)}[/]")
        self._write(f"$ {command}\n")

    def note(self, text: str) -> None:
        self.console.print(f"[note]{escape(text)}[/]")
        self._write(f"[demo] {text}\n")

    def result(self, ok: bool, text: str) -> None:
        """The one-line result of a step, with its wall time."""
        took = time.monotonic() - self._step_started
        mark = "[ok]✔[/]" if ok else "[fail]✘[/]"
        self.console.print(f"{mark} {escape(text)}  [dim]{took:.0f}s[/]")
        self._write(f"[demo] {'OK' if ok else 'FAIL'}: {text} ({took:.0f}s)\n")

    def tail(self, res: StepResult, n: int = 30) -> None:
        """A failed step: its last lines, then where the whole transcript is."""
        self.console.print(f"[fail]last {min(n, len(res.lines))} lines of {res.name}:[/]")
        for line in res.lines[-n:]:
            self.console.print("  " + escape(line), style="dim")
        self.note(f"full transcript: {self.log_path}")

    # ------------------------------------------------------------------ internals

    def _write(self, text: str) -> None:
        self._log.write(text)
        self._log.flush()

    @staticmethod
    def _count(done: int, total: float | None) -> str:
        return f"{done}/{int(total)}" if total else ""
