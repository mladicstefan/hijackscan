"""Terminal output for the lab scripts: Python logging through a Rich handler, stage banners and verdict lines.

Every script logs through `log`; messages are plain text unless sent via ok()/fail()/note()/cmd(), which mark
the record for Rich markup. Plain records are never parsed as markup, so CA transcript lines such as
`[decision ] ...` print verbatim. Files under lab/logs/ get the plain text, never the colour codes.

transcript() shows a line of evidence (a CA step, an attack observation, a control expectation) through the
scanner's `paint`: the same colours the scanner uses, added to the text without changing it, so the terminal
and the log file carry the same line. explain() and legend() are the sentences that tell a judge what the next
lines show and what to look at; they are terminal only and never go to a log file.
"""

from __future__ import annotations

import logging

from rich.console import Console
from rich.highlighter import NullHighlighter
from rich.logging import RichHandler
from rich.markup import escape
from rich.rule import Rule
from rich.theme import Theme

from hijackscan.console import THEME as REPORT_THEME
from hijackscan.console import paint

THEME = Theme({**REPORT_THEME.styles, "cmd": "dim"})
console = Console(theme=THEME, highlight=False)
log = logging.getLogger("lab")
MARKUP = {"markup": True}


def setup(verbose: bool = False) -> None:
    """Root logging through Rich: `HH:MM:SS message`, levels coloured, markup only where a record asks for it."""
    handler = RichHandler(
        console=console,
        show_level=False,
        show_path=False,
        markup=False,
        rich_tracebacks=True,
        highlighter=NullHighlighter(),  # only paint() colours a line; no repr highlighting of quotes and numbers
        omit_repeated_times=False,
        log_time_format="%H:%M:%S",
    )
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format="%(message)s", handlers=[handler])
    logging.getLogger("httpx").setLevel(logging.WARNING)


def stage(title: str) -> None:
    """A full-width banner: one per matrix row, control, or lifecycle step."""
    console.print()
    console.print(Rule(f"[stage]{escape(title)}[/]", style="cyan", align="left"))


def cmd(command: str) -> None:
    log.info(f"[cmd]$ {escape(command)}[/]", extra=MARKUP)


def ok(what: str, detail: str = "") -> None:
    log.info(f"[ok]✔ {escape(what)}[/]" + (f"  {escape(detail)}" if detail else ""), extra=MARKUP)


def fail(what: str, detail: str = "") -> None:
    log.error(f"[fail]✘ {escape(what)}[/]" + (f"  {escape(detail)}" if detail else ""), extra=MARKUP)


def note(text: str) -> None:
    log.info(f"[note]{escape(text)}[/]", extra=MARKUP)


def kv(pairs: list[tuple[str, str]], indent: int = 2) -> None:
    """Aligned `key  value` lines, keys in the scanner's key colour, values painted by their shape."""
    width = max(len(k) for k, _ in pairs)
    for k, v in pairs:
        log.info(paint(f"{' ' * indent}{k.ljust(width)}  {v}").markup, extra=MARKUP)


def transcript(line: str, indent: str = "  ") -> None:
    """One line of evidence, coloured by its shape (host 'attacker' red, 'victim' green, SERVFAIL yellow, the
    CA's step tag cyan); the text itself is untouched."""
    log.info(paint(indent + line).markup, extra=MARKUP)


def explain(text: str) -> None:
    """One sentence for the reader before a block of evidence: what it shows and what to look at. Not logged."""
    console.print(f"  [explain]{escape(text)}[/]", soft_wrap=True)


def legend(title: str, rows: list[tuple[str, str]]) -> None:
    """A short key to the lines that follow: `tag  what it means`, under a one-line title. Not logged."""
    console.print(f"[heading]{escape(title)}[/]")
    width = max(len(k) for k, _ in rows)
    for k, v in rows:
        console.print(f"  [tag]{escape(k.ljust(width))}[/]  {escape(v)}", soft_wrap=True)
    console.print()
