"""Terminal output for the scanner: logging through a Rich handler, stage banners, verdict lines, severity colours.

Same idea as lab/console.py. Progress and diagnostics go to stderr through `log`; results (tables, summaries) go to
stdout through `out`, so `hijackscan list --json | jq` and `> file` stay clean. Rich drops every colour code when
the stream is not a terminal, so redirected output is plain text. Records are plain unless sent through
ok()/fail()/note()/cmd(), which mark them for markup, so a domain or an error message is never parsed as markup.

`paint` is the one colouriser for report text: it knows the shape of the lines the scanner prints (summary line,
section headings, key/value facts, per-address verdicts, ROA rows, findings) and of the lab's transcripts (the CA's
`[http-01  ]` lines, `✔`/`✘` verdicts, `[ok  ]` control expectations), so the scanner, the lab scripts and
`uv run demo` (which re-prints its children's plain lines) all colour the same line the same way. It only adds
styles; the text is never changed, so a painted line reads the same as the plain one in a log file.
"""

from __future__ import annotations

import logging
import re

from rich.console import Console
from rich.highlighter import NullHighlighter
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
        # report text (paint)
        "key": "cyan",  # the name of a fact: `announced as`, `DNSSEC`, `driving path`
        "name": "bold",  # a domain, nameserver host or address that a block is about
        "class": "magenta",  # the risk label: open-web, caa-erasable, contested, closed ...
        "finding": "bold yellow",  # a finding id: WEB_MORE_SPECIFIC, NO_CAA ...
        "bad": "bold red",  # forgeable, attacker, ISSUED to the attacker, a violation
        "good": "green",  # not forgeable, victim, blocked path, a tightly fitting ROA
        "warn": "yellow",  # unknown origin, no CAA, a loose ROA, SERVFAIL, a manipulation in a control
        "tag": "cyan",  # the `[http-01  ]` step tag of a CA transcript line
        "explain": "italic",  # a sentence that tells the reader what to look at
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
        highlighter=NullHighlighter(),  # only paint() colours a line; no repr highlighting of quotes and numbers
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


# --------------------------------------------------------------------------- paint: colour for report text

_SEV = r"NONE|LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN|None|Low|Medium|High|Critical|Unknown"
# `10.0 Critical`, `CRITICAL 10.0`, `Low`: the severity word with the score next to it, if any
_SEVERITY = re.compile(rf"(?<![\w/])(?:\d{{1,2}}\.\d\s+)?(?:{_SEV})(?:\s+\d{{1,2}}\.\d)?(?![\w-])")
# `blic.rs  LOW  1.1  contested`: the summary line of one domain
_SUMMARY = re.compile(rf"^(\S+)(\s{{2}})({_SEV})(\s+)([\d.]+|-)(\s{{2}})(\S+)$")
# `RISK CALCULATION   (design/formula.md)`, `WEB ADDRESSES   — none forgeable`, `ALL PATHS`
_HEADING = re.compile(r"^([A-Z][A-Z0-9 &]*[A-Z0-9])(\s+(?:\(|—).*)?$")
# `  announced as   99.83.128.0/20 ...`, `  DNSSEC        unsigned ...`: a fact with its name on the left
_KEY_VALUE = re.compile(r"^(\s{2,})([A-Za-z](?:[A-Za-z0-9 ()>-]*?[A-Za-z0-9)])?)(\s{2,})(\S.*)$")
# `  WEB_MORE_SPECIFIC     [Critical] ...`: a finding (ids are UPPER_SNAKE; UNSIGNED is the one without a `_`)
_FINDING = re.compile(r"^(\s{2})([A-Z0-9]+_[A-Z0-9_]+|UNSIGNED)(\s)")
_DOMAIN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$")
# `        99.84.0.0/16         maxLength 24  origin AS16509   TA arin     allows /16–/24`
_ROA_ROW = re.compile(r"^\s+\S+/\d+\s+maxLength\s")
_IP = re.compile(r"^(\s{2,})(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)$")
_HOST = re.compile(r"^(\s{2})([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,})$")
_PATH_STATE = re.compile(r"^(\s{2})(web|ns|contest)(\s+)(blocked)\b")
_TECHNIQUE = re.compile(r"^(\s{2})(T\d{4}(?:\.\d{3})?)(\s)")  # a MITRE ATT&CK technique id
# lab transcripts
_TIME = r"(?:\d\d:\d\d:\d\d )?"
_VERDICT = re.compile(rf"^(\s*{_TIME})([✔✘])( .*)$")
_CA_TAG = re.compile(r"^(\s*)(\[(?:request|dns|caa|http-01|quorum|decision)\s*\])")
_CONTROL = re.compile(r"^(\s*)(\[(?:ok  |MISS)\])")
_LAB_HOST = re.compile(r"(?:host |by |=)'?(attacker|victim)\b'?")  # host 'attacker', r3=victim, by 'victim'
_LAB_WORDS = re.compile(
    r"\b(ISSUED|REFUSED|SERVFAIL|UNEXPECTED|VIOLATION|FAILED|MISSING|NOT met|does NOT corroborate|withdrawn|"
    r"ad=1|ad=0|RPKI-valid|rpki validation-state: invalid|DNSSEC-bogus|reachable but bogus)\b"
)


def paint(line: str) -> Text:
    """The line as a Rich Text with the colours above; the plain line when it has no shape paint knows.
    Never raises: a line that trips a rule comes back plain."""
    try:
        return _paint(line)
    except Exception:  # a colour rule must never break a report
        return Text(line)


def _paint(line: str) -> Text:  # noqa: C901 - one rule per line shape, in order of precedence
    t = Text(line)
    s = line.lstrip()
    # --- lab transcripts: verdict lines, CA steps, control expectations, attack lines
    if m := _VERDICT.match(line):
        t.stylize("ok" if m.group(2) == "✔" else "fail", m.start(2), m.end(3))
        _lab_words(t, line)
        return t
    if m := _CONTROL.match(line):
        t.stylize("ok" if m.group(2) == "[ok  ]" else "fail", m.start(2), m.end(2))
        _lab_words(t, line)
        _severities(t, line, m.end())
        return t
    if m := _CA_TAG.match(line):
        t.stylize("tag", m.start(2), m.end(2))
        if "[decision" in m.group(2):
            t.stylize("bold", m.end(2))
        _lab_words(t, line)
        return t
    if s.startswith("######## "):
        t.stylize("heading")
        return t
    if s.startswith("-- "):
        t.stylize("warn")
        return t
    if s.startswith("attack ") and ":" in s:
        _lab_words(t, line)
        return t
    # --- the scanner's report
    if m := _SUMMARY.match(line):
        t.stylize("name", m.start(1), m.end(1))
        t.stylize(sev_style(m.group(3)), m.start(3), m.end(5))
        t.stylize("class", m.start(7), m.end(7))
        return t
    if line.startswith("ERRORS"):
        t.stylize("fail")
        return t
    if not line.startswith(" ") and (m := _HEADING.match(line)):
        t.stylize("heading", m.start(1), m.end(1))
        if m.group(2):
            tail = m.group(2)
            style = "good" if "none forgeable" in tail else "bad" if "forgeable" in tail.lower() else "dim"
            t.stylize(style, m.start(2), m.end(2))
        return t
    if s.startswith("→ "):
        if s.startswith(("→ FORGEABLE", "→ UNKNOWN ORIGIN, effectively forgeable")):
            t.stylize("bad")
        elif s.startswith("→ not forgeable"):
            t.stylize("good")
        elif s.startswith("→ UNKNOWN ORIGIN"):
            t.stylize("warn")
        else:
            t.stylize("dim")
        return t
    if s.startswith("! "):
        t.stylize("warn")
        return t
    if s.startswith(("blocked by", "(--details", "(no address)", "(apex and www do not resolve)", "- …")):
        t.stylize("dim")
        return t
    if _ROA_ROW.match(line):
        if "allows /" in line:
            t.stylize("warn", line.index("allows /"))
        elif "exact length only" in line:
            t.stylize("good", line.index("exact length only"))
        elif "inside:" in line:
            t.stylize("bad", line.index("inside:"))
        return t
    if m := _IP.match(line):
        t.stylize("name", m.start(2), m.end(2))
        return t
    if m := _HOST.match(line):
        t.stylize("name", m.start(2), m.end(2))
        return t
    if m := _PATH_STATE.match(line):
        t.stylize("key", m.start(2), m.end(2))
        t.stylize("good", m.start(4), m.end(4))
        return t
    if m := _FINDING.match(line):
        t.stylize("finding", m.start(2), m.end(2))
        _severities(t, line, m.end())
        return t
    if m := _TECHNIQUE.match(line):
        t.stylize("key", m.start(2), m.end(2))
        return t
    if m := _KEY_VALUE.match(line):
        key, value, at = m.group(2), m.group(4), m.start(4)
        t.stylize("key", m.start(2), m.end(2))
        _value(t, key, value, at)
        _severities(t, line, 0)  # from 0: the zone histogram's keys are the severities themselves
        return t
    if _DOMAIN.match(line):
        t.stylize("name")
        return t
    _severities(t, line, 0)
    return t


def _value(t: Text, key: str, value: str, at: int) -> None:
    """The first word of a few facts says whether the domain is defended: colour it."""
    word = value.split()[0]
    end = at + len(word)
    if key == "DNSSEC":
        t.stylize("good" if word == "secure" else "bad", at, end)
    elif key == "CAA":
        if value.startswith("none"):
            t.stylize("warn", at, end)
    elif key == "RIPEstat RPKI":
        t.stylize("good" if word == "valid" else "bad" if word == "invalid" else "warn", at, end)
    elif key == "ROAs" and value.startswith("none cover"):
        t.stylize("warn", at)
    elif key.startswith(("CA ", "HTTP-01", "data plane", "scanner")):  # a matrix row summary (lab/matrix.py)
        _lab_words(t, t.plain)


def _severities(t: Text, line: str, start: int) -> None:
    words = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")
    for m in _SEVERITY.finditer(line, start):
        word = next(w for w in m.group(0).split() if w.upper() in words)
        t.stylize(sev_style(word), m.start(), m.end())


def _lab_words(t: Text, line: str) -> None:
    for m in _LAB_HOST.finditer(line):
        t.stylize("bad" if m.group(1) == "attacker" else "good", m.start(1), m.end(1))
    for m in _LAB_WORDS.finditer(line):
        w = m.group(1)
        if w in ("ISSUED", "REFUSED"):
            t.stylize("bold", m.start(), m.end())
        elif w in ("ad=1", "RPKI-valid"):
            t.stylize("good", m.start(), m.end())
        elif w in ("withdrawn", "ad=0"):
            t.stylize("dim", m.start(), m.end())
        elif w in ("SERVFAIL", "UNEXPECTED", "DNSSEC-bogus", "reachable but bogus"):
            t.stylize("warn", m.start(), m.end())
        else:
            t.stylize("bad", m.start(), m.end())


def show(lines: list[str]) -> None:
    """Print report text through `paint`. Plain when stdout is not a terminal."""
    for line in lines:
        out.print(paint(line), soft_wrap=True)


def explain(text: str, stream: Console | None = None) -> None:
    """One sentence that tells the reader what the next lines show and what to look at."""
    (stream or out).print(Text(text, style="explain"), soft_wrap=True)
