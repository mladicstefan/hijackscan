"""Steps 1-6: the README quick start for the scanner, one child process per README command.

Each step keys on a few lines of the child's output (regexes over colour-stripped lines; a miss leaves the
fact empty and never raises), drives the inner bar from them, shows the lines worth reading in full, and ends
in a one-line result. The scanner writes its log lines to stderr and its results to stdout; the runner merges
both in arrival order, so everything here keys on content, never on the stream. The first failed step is
reported through `runner.tail` and stops the sequence.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .runner import REPO, Runner, StepResult

SAMPLE = Path("data/samples/ee100.txt")
OUT = Path("data/out/ee")
SEVERITIES = ("Critical", "High", "Medium", "Low", "None", "Unknown")
DOMAIN_EXIT_MAX = 3  # `hijackscan <domain>` exits with the severity: 0 None, 1 Low/Medium, 2 High/Critical, 3 Unknown

RESOLVER_OK = re.compile(r"resolver validates\s+(\S+)")
ZONE_FACTS = re.compile(r"zone ee\s+serial \d+: ([\d,]+) delegations, ([\d,]+) with DS")
SAMPLE_WROTE = re.compile(r"wrote (\d+) domains")
COLLECT_PLAN = re.compile(r"collect\s+(\d+) of (\d+) domains")
COLLECT_ITEM = re.compile(r"\[(\d+)/(\d+)\] ")
COLLECTED_IN = re.compile(r"(\d+) collected in")
WITH_ERRORS = re.compile(r"(\d+) with errors")
HISTOGRAM = re.compile(r"^\s+(Critical|High|Medium|Low|None|Unknown)\s+(\d+)")
PREAMBLE = re.compile(r"^\d\d:\d\d:\d\d ")
TRACEBACK = re.compile(r"^Traceback \(most recent call last\)")


@dataclass
class ScannerSummary:
    sampled: int
    collected: int
    cached: int
    errors: int
    severity: dict[str, int] = field(default_factory=dict)  # Critical, High, Medium, Low, None, Unknown
    top_domain: str = ""
    top_label: str = ""
    top_severity: str = ""
    top_score: float = 0.0
    top_fix: str = ""
    report_html: Path = REPO / OUT / "report.html"
    domains_html: Path = REPO / OUT / "domains.html"


def top_domain(jsonl: Path) -> dict | None:
    """First row of a domains.jsonl (worst first); None when the file is missing, empty or not JSON."""
    try:
        with jsonl.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    row = json.loads(line)
                    return row if isinstance(row, dict) else None
    except (OSError, ValueError):
        return None
    return None


def _int(text: str, default: int = 0) -> int:
    try:
        return int(text.replace(",", ""))
    except ValueError:
        return default


def _failed(runner: Runner, res: StepResult, text: str) -> None:
    runner.result(False, text)
    runner.tail(res)


# --------------------------------------------------------------------------- the six steps


def _resolver(runner: Runner) -> bool:
    runner.step("resolver", expect="a few seconds")
    facts: dict[str, str] = {}

    def on_line(line: str, _: Runner) -> None:
        if m := RESOLVER_OK.search(line):
            facts["address"] = m.group(1)

    res = runner.run("resolver", ["uv", "run", "scripts/check_resolver.py"], on_line)
    res.facts = facts
    if not res.ok:
        _failed(runner, res, "the configured resolver does not validate DNSSEC")
        return False
    runner.result(True, f"{facts.get('address', 'resolver')} validates DNSSEC")
    return True


def _sample(runner: Runner) -> int | None:
    runner.step("sample")
    parts = sorted(str(p.relative_to(REPO)) for p in (REPO / "data" / "samples").glob("zone.ee.part-*"))
    facts: dict[str, str] = {}

    def on_line(line: str, _: Runner) -> None:
        if m := ZONE_FACTS.search(line):
            facts["delegations"], facts["ds"] = m.group(1), m.group(2)
        if m := SAMPLE_WROTE.search(line):
            facts["wrote"] = m.group(1)

    command = ["uv", "run", "hijackscan", "sample", *parts, "--n", "100", "--seed", "1", "--out", str(SAMPLE)]
    res = runner.run("sample", command, on_line)
    res.facts = facts
    if not res.ok:
        _failed(runner, res, "sample failed")
        return None
    drawn = _int(facts.get("wrote", "100"), 100)
    runner.result(
        True,
        f"{facts.get('delegations', '?')} delegations, {facts.get('ds', '?')} with DS, {drawn} drawn",
    )
    return drawn


def _collect(runner: Runner) -> tuple[int, int, int] | None:
    """(collected live, from cache, with errors), or None after a failure."""
    runner.step("collect", inner_total=None, expect="about 40 s even from cache: the ROA set loads first")
    facts: dict[str, str] = {}

    def on_line(line: str, r: Runner) -> None:
        if m := COLLECT_PLAN.search(line):
            todo, total = int(m.group(1)), int(m.group(2))
            facts["todo"], facts["cached"] = str(todo), str(total - todo)
            if todo:
                r.inner_total(todo)
        elif COLLECT_ITEM.search(line):
            r.tick()
        if m := COLLECTED_IN.search(line):
            facts["collected"] = m.group(1)
        if m := WITH_ERRORS.search(line):
            facts["errors"] = m.group(1)

    res = runner.run("collect", ["uv", "run", "hijackscan", "collect", str(SAMPLE)], on_line)
    res.facts = facts
    if not res.ok:
        _failed(runner, res, "collect failed")
        return None
    collected = _int(facts.get("collected", facts.get("todo", "0")))
    cached, errors = _int(facts.get("cached", "0")), _int(facts.get("errors", "0"))
    runner.result(True, f"{collected} collected live, {cached} from cache, {errors} with errors")
    return collected, cached, errors


def _zone(runner: Runner) -> dict[str, int] | None:
    runner.step("zone report")
    severity: dict[str, int] = {}

    def on_line(line: str, r: Runner) -> None:
        if m := HISTOGRAM.match(line):
            severity[m.group(1)] = int(m.group(2))
            r.show(line)

    command = ["uv", "run", "hijackscan", "zone", str(SAMPLE), "--out", f"{OUT}/"]
    res = runner.run("zone", command, on_line)
    if not res.ok:
        _failed(runner, res, "zone report failed")
        return None
    runner.result(True, f"report.html, domains.html written to {OUT}/")
    return {s: severity.get(s, 0) for s in SEVERITIES}


def _domain(runner: Runner, name: str) -> bool:
    runner.step(f"drill-down: {name}")
    seen_traceback = False

    def on_line(line: str, r: Runner) -> None:
        nonlocal seen_traceback
        if TRACEBACK.match(line):
            seen_traceback = True
        # The scanner's stderr preamble (timestamped resolver/rpki/collect lines) is in the log; show the report.
        if PREAMBLE.match(line) or line.startswith("collect  "):
            return
        r.show(line.rstrip())

    res = runner.run("domain", ["uv", "run", "hijackscan", name, "--details"], on_line)
    if res.returncode > DOMAIN_EXIT_MAX or res.returncode < 0 or seen_traceback:
        _failed(runner, res, f"hijackscan {name} failed (exit {res.returncode})")
        return False
    runner.result(True, f"{name} reported in full (exit {res.returncode} = its severity)")
    return True


def _list(runner: Runner) -> bool:
    runner.step("list High and Critical")
    command = ["uv", "run", "hijackscan", "list", str(SAMPLE), "--severity", "High,Critical"]
    res = runner.run("list", command, lambda line, r: r.show(line))
    if not res.ok:
        _failed(runner, res, "list failed")
        return False
    runner.result(True, "every High and Critical domain of the sample listed")
    return True


# --------------------------------------------------------------------------- sequence


def run_scanner(runner: Runner) -> ScannerSummary | None:
    """Run the six README steps in order; None after the first failed step (already reported via tail)."""
    if not _resolver(runner):
        return None
    sampled = _sample(runner)
    if sampled is None:
        return None
    counts = _collect(runner)
    if counts is None:
        return None
    collected, cached, errors = counts
    severity = _zone(runner)
    if severity is None:
        return None
    top = top_domain(REPO / OUT / "domains.jsonl")
    if top is None or not top.get("domain"):
        runner.step("drill-down")
        runner.result(False, f"no domains.jsonl after the zone step ({OUT / 'domains.jsonl'} missing or empty)")
        return None
    name = str(top["domain"])
    if not _domain(runner, name):
        return None
    if not _list(runner):
        return None
    fix = top.get("fix") or {}
    return ScannerSummary(
        sampled=sampled,
        collected=collected,
        cached=cached,
        errors=errors,
        severity=severity,
        top_domain=name,
        top_label=str(top.get("label", "")),
        top_severity=str(top.get("severity", "")),
        top_score=float(top.get("score") or 0.0),
        top_fix=str(fix.get("action", "")) if isinstance(fix, dict) else "",
        report_html=REPO / OUT / "report.html",
        domains_html=REPO / OUT / "domains.html",
    )
