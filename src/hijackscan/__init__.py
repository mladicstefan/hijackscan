"""hijackscan: how exposed is a namespace to certificate theft through BGP hijacks below DNS."""

import sys


def main() -> None:
    """`hijackscan <command> [args]` — commands: collect."""
    commands = {"collect": "hijackscan.scripts.collect"}
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd not in commands:
        print(f"usage: hijackscan {{{'|'.join(commands)}}} [options]", file=sys.stderr)
        sys.exit(2)
    import importlib

    sys.exit(importlib.import_module(commands[cmd]).main(sys.argv[2:]))
