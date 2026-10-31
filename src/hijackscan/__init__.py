import sys


def main() -> None:
    from .cli import main as _main

    sys.exit(_main())
