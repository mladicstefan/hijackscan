"""Does the configured resolver validate DNSSEC? Exit 0 if yes.

uv run scripts/check_resolver.py [--resolver host[:port]]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hijackscan.collect.dns import Dns  # noqa: E402
from hijackscan.collect.resolver_check import check_resolver, passes  # noqa: E402
from hijackscan.config import Config  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--resolver", default=Config.resolver)
    a = p.parse_args()
    result = check_resolver(Dns(a.resolver, qps=10))
    print(json.dumps(result, indent=2))
    ok = passes(result)
    print("OK: resolver validates" if ok else "FAIL: resolver does not validate", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
