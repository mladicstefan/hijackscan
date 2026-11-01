"""Does the configured resolver validate DNSSEC? Exit 0 if yes.

uv run scripts/check_resolver.py [--resolver host[:port]]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hijackscan import console  # noqa: E402
from hijackscan.collect.dns import Dns  # noqa: E402
from hijackscan.collect.resolver_check import check_resolver, passes  # noqa: E402
from hijackscan.config import Config  # noqa: E402


def main() -> int:
    console.setup()
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--resolver", default=Config.resolver)
    a = p.parse_args()
    result = check_resolver(Dns(a.resolver, qps=10))
    print(json.dumps(result, indent=2))
    good = passes(result)
    if good:
        console.ok("resolver validates", result["resolver"])
    else:
        console.fail("resolver does not validate", result["resolver"])
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
