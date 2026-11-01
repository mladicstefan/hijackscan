"""Step 0: name every missing prerequisite with the README's install line before anything runs.

Capability, not identity: Docker and containerlab are tested as the current user (`docker info`,
`containerlab version`). The demo never calls sudo and never looks at group membership; on a machine where
the user cannot reach Docker, the user runs the whole demo as root (`sudo uv run demo`).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass

from rich.table import Table

from .runner import ANSI, CHILD_ENV, REPO, Runner

CONTAINERLAB_INSTALL = 'curl -sL https://containerlab.dev/setup | sudo -E bash -s "install-containerlab"'
LAB_IMAGE = "hijackscan-lab:latest"


@dataclass
class Check:
    name: str
    ok: bool
    detail: str  # version or error text, one line
    remedy: str  # README install line, "" when ok
    lab: bool  # a lab prerequisite (False: a scanner prerequisite)
    warn_only: bool = False


def _probe(*cmd: str, timeout: float = 30, want: str = "") -> tuple[bool, str]:
    """Run a version/info command; (ok, first useful line of output or the error)."""
    if shutil.which(cmd[0]) is None:
        return False, f"{cmd[0]} not found on PATH"
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env={**os.environ, **CHILD_ENV})
    except subprocess.TimeoutExpired:
        return False, f"{cmd[0]} did not answer in {timeout:.0f}s"
    lines = [ANSI.sub("", ln).strip() for ln in (p.stdout + "\n" + p.stderr).splitlines()]
    lines = [ln for ln in lines if ln and any(ch.isalnum() for ch in ln)]  # drops containerlab's banner art
    if want:
        lines = [ln for ln in lines if want in ln.lower()] or lines
    return p.returncode == 0, (lines[0] if lines else "")[:80]


def checks() -> list[Check]:
    out: list[Check] = []
    v = sys.version_info
    out.append(Check("python", v >= (3, 11), f"{v.major}.{v.minor}.{v.micro}", "Python >= 3.11 is required", lab=False))
    ok, d = _probe("uv", "--version")
    out.append(Check("uv", ok, d, "https://docs.astral.sh/uv/", lab=False))
    parts = sorted((REPO / "data" / "samples").glob("zone.ee.part-*"))
    out.append(
        Check(
            "zone parts",
            bool(parts),
            f"{len(parts)} files in data/samples/" if parts else "data/samples/zone.ee.part-* missing",
            "the .ee zone parts are in the repository; run from a full clone",
            lab=False,
        )
    )
    docker_ok, d = _probe("docker", "info", "--format", "{{.ServerVersion}}")
    ok = docker_ok
    out.append(
        Check(
            "docker",
            ok,
            f"server {d}" if ok else d,
            "install Docker and make it reachable for this user (docker group) or run `sudo uv run demo`",
            lab=True,
        )
    )
    ok, d = _probe("containerlab", "version", want="version:")
    out.append(Check("containerlab", ok, d, CONTAINERLAB_INSTALL, lab=True))
    ok, d = _probe("ldns-signzone", "-v")
    out.append(Check("ldns", ok, d, "Debian/Ubuntu: sudo apt install ldnsutils   Arch: pacman -S ldns", lab=True))
    ok, d = (
        _probe("docker", "image", "inspect", LAB_IMAGE, "--format", "{{.Id}}")
        if docker_ok
        else (False, "docker unreachable")
    )
    detail = (
        d[:19]
        if ok
        else ("not built yet: labctl builds it, the first matrix row takes several minutes more" if docker_ok else d)
    )
    out.append(Check("lab image", ok, detail, f"docker build -t {LAB_IMAGE} lab/image", lab=True, warn_only=True))
    return out


def preflight(runner: Runner) -> tuple[list[Check], bool]:
    """Run every check with a tick each, show the table; (checks, lab_available)."""
    results: list[Check] = []
    for c in checks():
        results.append(c)
        runner.tick()
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("check")
    table.add_column("")
    table.add_column("detail")
    table.add_column("if missing", style="dim")
    for c in results:
        mark = "[ok]✔[/]" if c.ok else ("[note]![/]" if c.warn_only else "[fail]✘[/]")
        table.add_row(c.name, mark, c.detail, "" if c.ok else c.remedy)
    runner.show(table)
    lab_available = all(c.ok for c in results if c.lab and not c.warn_only)
    return results, lab_available
