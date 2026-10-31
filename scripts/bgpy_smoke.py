"""Time a tiny BGPy 13.0.13 simulation on the pinned CAIDA month. Prints wall-clock, trials, cores."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hijackscan.fetch.bgpy_smoke import smoke  # noqa: E402
from hijackscan.fetch.common import load_config  # noqa: E402


def main() -> None:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    res = smoke(load_config())
    print(f"wall {res['wall_seconds']}s  trials {res['trials']}  cores {res['cores']}")


if __name__ == "__main__":
    main()
