#!/usr/bin/env python3
"""A RIPEstat-shaped HTTP feed over the route-collector's BGP table (stdlib only; runs inside the FRR container).

GET /data/<call>/data.json?resource=...[&prefix=...] -> {"data": {...}} for the four calls hijackscan makes:
network-info, rpki-validation, routing-status, as-overview. The table comes from `vtysh -c "show bgp ipv4 unicast
json"`, the ROAs and AS names from feed.json (the same ROAs StayRTR serves).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


def vtysh(cmd: str) -> dict:
    out = subprocess.run(["vtysh", "-c", cmd], capture_output=True, text=True, check=True).stdout
    return json.loads(out) if out.strip() else {}


def table() -> dict[str, list[dict]]:
    """prefix -> [{"origin": int|None, "peer": str, "path": "65002 65000"}] from the collector's RIB."""
    routes = vtysh("show bgp ipv4 unicast json").get("routes", {})
    out: dict[str, list[dict]] = {}
    for prefix, paths in routes.items():
        for p in paths:
            path = p.get("path", "").split()
            origin = int(path[-1]) if path else None
            out.setdefault(prefix, []).append({"origin": origin, "peer": p.get("peerId", ""), "path": " ".join(path)})
    return out


def total_peers() -> int:
    s = vtysh("show bgp summary json")
    return int(s.get("ipv4Unicast", {}).get("totalPeers", 0))


def rpki_status(roas: list[dict], prefix: str, asn: int) -> str:
    """valid | invalid | unknown for (prefix, origin) against the lab ROAs (RFC 6811)."""
    net = ipaddress.ip_network(prefix, strict=False)
    covering = [r for r in roas if net.subnet_of(ipaddress.ip_network(r["prefix"], strict=False))]
    if not covering:
        return "unknown"
    ok = any(r["asn"] == asn and net.prefixlen <= r["max_length"] for r in covering)
    return "valid" if ok else "invalid"


def most_specific(tbl: dict[str, list[dict]], ip: str) -> tuple[str | None, list[int]]:
    addr = ipaddress.ip_address(ip)
    best = None
    for prefix in tbl:
        net = ipaddress.ip_network(prefix, strict=False)
        if addr in net and (best is None or net.prefixlen > best.prefixlen):
            best = net
    if best is None:
        return None, []
    origins = sorted({p["origin"] for p in tbl[str(best)] if p["origin"] is not None})
    return str(best), origins


def answer(call: str, q: dict[str, str], cfg: dict, local_as: int) -> dict | None:
    tbl = table()
    if call == "network-info":
        prefix, asns = most_specific(tbl, q["resource"])
        return {"prefix": prefix or "", "asns": [str(a) for a in asns]}
    if call == "rpki-validation":
        return {"status": rpki_status(cfg["roas"], q["prefix"], int(q["resource"].upper().removeprefix("AS")))}
    if call == "routing-status":
        net = ipaddress.ip_network(q["resource"], strict=False)
        more = [
            {"prefix": p, "origin": paths[0]["origin"] if paths[0]["origin"] is not None else local_as}
            for p, paths in tbl.items()
            if ipaddress.ip_network(p).subnet_of(net) and ipaddress.ip_network(p) != net
        ]
        seeing = len({p["peer"] for p in tbl.get(q["resource"], []) if p["peer"]})
        return {
            "more_specifics": more,
            "visibility": {"v4": {"ris_peers_seeing": seeing, "total_ris_peers": total_peers()}},
        }
    if call == "as-overview":
        asn = int(q["resource"].upper().removeprefix("AS"))
        announced = any(p["origin"] == asn for paths in tbl.values() for p in paths)
        return {"holder": cfg["as_names"].get(str(asn)), "announced": announced}
    return None


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--config", required=True)
    p.add_argument("--port", type=int, default=8080)
    a = p.parse_args()
    cfg = json.load(open(a.config))
    local_as = int(vtysh("show bgp summary json").get("ipv4Unicast", {}).get("as", 0))

    class H(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            u = urlparse(self.path)
            parts = u.path.strip("/").split("/")
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            data = None
            if len(parts) == 3 and parts[0] == "data" and parts[2] == "data.json":
                try:
                    data = answer(parts[1], q, cfg, local_as)
                except Exception as e:  # noqa: BLE001
                    sys.stderr.write(f"feed: {parts[1]} {q}: {e}\n")
            body = json.dumps({"data": data, "status": "ok"} if data is not None else {"error": "unknown call"})
            self.send_response(200 if data is not None else 404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, fmt: str, *args: object) -> None:
            sys.stderr.write(f"feed {self.client_address[0]} {fmt % args}\n")

    HTTPServer(("0.0.0.0", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
