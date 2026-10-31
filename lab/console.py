"""Terminal output for the lab scripts: Python logging through a Rich handler, stage banners and verdict lines.

Every script logs through `log`; messages are plain text unless sent via ok()/fail()/note()/cmd(), which mark
the record for Rich markup. Plain records are never parsed as markup, so CA transcript lines such as
`[decision ] ...` print verbatim. Files under lab/logs/ get the plain text, never the colour codes.
"""

from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler
from rich.markup import escape
from rich.rule import Rule
from rich.theme import Theme

THEME = Theme(
    {
        "stage": "bold cyan",
        "ok": "bold green",
        "fail": "bold red",
        "note": "yellow",
        "cmd": "dim",
        "label": "bold magenta",
    }
)
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
    """Aligned `key  value` lines, keys dim: the borderless table used for row summaries."""
    width = max(len(k) for k, _ in pairs)
    for k, v in pairs:
        log.info(f"{' ' * indent}[cmd]{escape(k.ljust(width))}[/]  {escape(v)}", extra=MARKUP)
