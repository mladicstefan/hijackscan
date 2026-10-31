#!/usr/bin/env python3
"""The HTTP-01 responder of one host: serves the tokens it owns and names itself in X-Lab-Host.

web.json: {"label": "victim", "tokens": {"legit-token": "https://ca.lab/acct/legit"}}
Body of /.well-known/acme-challenge/<token> is "<token>.<account>", the lab's stand-in for the key authorization.
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PREFIX = "/.well-known/acme-challenge/"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--config", required=True)
    p.add_argument("--port", type=int, default=80)
    a = p.parse_args()
    cfg = json.load(open(a.config))
    label, tokens = cfg["label"], cfg["tokens"]

    class H(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            token = self.path[len(PREFIX) :] if self.path.startswith(PREFIX) else None
            body = f"{token}.{tokens[token]}".encode() if token in tokens else b"not found\n"
            self.send_response(200 if token in tokens else 404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Lab-Host", label)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            sys.stderr.write(f"web[{label}] {self.client_address[0]} {fmt % args}\n")

    HTTPServer(("0.0.0.0", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
