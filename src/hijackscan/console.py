"""Terminal output for the scanner: logging through a Rich handler, stage banners, verdict lines, severity colours.

Same idea as lab/console.py. Progress and diagnostics go to stderr through `log`; results (tables, summaries) go to
stdout through `out`, so `hijackscan list --json | jq` and `> file` stay clean. Rich drops every colour code when
the stream is not a terminal, so redirected output is plain text. Records are plain unless sent through
ok()/fail()/note()/cmd(), which mark them for markup, so a domain or an error message is never parsed as markup.
"""

from __future__ import annotations

import logging
import re

from rich.console import Console
from rich.logging import RichHandler
from rich.markup import escape
from rich.rule import Rule
from rich.text import Text
from rich.theme import Theme

THEME = Theme(
    {
        "stage": "bold cyan",
        "ok": "bold green",
        "fail": "bold red",
        "note": "yellow",
        "dim": "dim",
        "label": "bold magenta",
        "sev.none": "bold green",
        "sev.low": "green",
        "sev.medium": "yellow",
        "sev.high": "bold red",
        "sev.critical": "bold white on red",
        "sev.unknown": "bold magenta",
        "heading": "bold cyan",
    }
)
console = Console(theme=THEME, highlight=False, stderr=True)  # logs and progress
out = Console(theme=THEME, highlight=False)  # results
log = logging.getLogger("hijackscan")
MARKUP = {"markup": True}


def setup(verbose: bool = False) -> None:
    """Root logging through Rich: `HH:MM:SS message`, markup only where a record asks for it."""
    handler = RichHandler(
        console=console,
        show_level=False,
        show_path=False,
        markup=False,
        rich_tracebacks=True,
        omit_repeated_times=False,
        log_time_format="%H:%M:%S",
    )
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format="%(message)s", handlers=[handler])
    logging.getLogger("httpx").setLevel(logging.WARNING)


def stage(title: str) -> None:
    """A full-width banner: one per pipeline step (sample, collect, report)."""
    console.print()
    console.print(Rule(f"[stage]{escape(title)}[/]", style="cyan", align="left"))


def ok(what: str, detail: str = "") -> None:
    log.info(f"[ok]✔ {escape(what)}[/]" + (f"  {escape(detail)}" if detail else ""), extra=MARKUP)


def fail(what: str, detail: str = "") -> None:
    log.error(f"[fail]✘ {escape(what)}[/]" + (f"  {escape(detail)}" if detail else ""), extra=MARKUP)


def note(text: str) -> None:
    log.info(f"[note]{escape(text)}[/]", extra=MARKUP)


def info(label: str, detail: str = "") -> None:
    """`label  detail`, label in magenta: a fact about the run (resolver, ROA day, counts)."""
    log.info(f"[label]{escape(label)}[/]  {escape(detail)}", extra=MARKUP)


def sev_style(severity: str) -> str:
    return f"sev.{severity.lower()}"


def sev(severity: str, text: str | None = None) -> str:
    """Markup for a severity word in its colour."""
    return f"[{sev_style(severity)}]{escape(text if text is not None else severity)}[/]"


_SEVERITY_WORDS = re.compile(r"\b(NONE|LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN|None|Low|Medium|High|Critical|Unknown)\b")
_HEADING = re.compile(r"^[A-Z][A-Z0-9 ()/.,&-]+?(\s{2,}\(.*\))?$")


def show(lines: list[str]) -> None:
    """Print report text: section headings cyan, severity words in their colour. Plain when not a terminal."""
    for line in lines:
        t = Text(line)
        if _HEADING.match(line) and not line.startswith(" "):
            t.stylize("heading")
        else:
            for m in _SEVERITY_WORDS.finditer(line):
                t.stylize(sev_style(m.group(1)), m.start(), m.end())
            if line.lstrip().startswith(("blocked by", "(--details")):
                t.stylize("dim")
        out.print(t, soft_wrap=True)
