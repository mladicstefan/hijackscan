"""Negative controls (design/lab.md §2.4): every matrix verdict must flip when the mechanism it rests on is removed.

A. caa-signed / web+ns   REFUSED (reachable but bogus) only while the resolver validates.
B. tight-maxlength / web REFUSED only while the transits run ROV on the RTR feed.
C. baseline / web        ISSUED only while the attacker serves the hijacked address; the feed reads the live table.
D. baseline              the scanner's verdict follows the ROA day it is given.

Each control: expected state, remove the mechanism, expected flip, restore, expected state again. Every step is
logged to lab/logs/<timestamp>-controls/controls.log (latest-controls links to the newest) with the CA transcript it
rests on. Exit 1 if any expected flip is missing.
"""

from __future__ import annotations

import csv
import io
import json
import lzma
import re
import time
import urllib.request
from pathlib import Path

import console
import labctl
from console import log
from render import SCENARIOS
from render.topology import EXTRA_ADDRESSES, FEED_PORT, LINKS, NODES

VALIDATING = 'module-config: "validator iterator"'
NOT_VALIDATING = 'module-config: "iterator"'


def link_ip(node: str, neighbour: str) -> str:
    """The neighbour's address on its link with `node` (the BGP peer address `node` configures)."""
    for link in LINKS:
        if (link.a, link.b) == (node, neighbour):
            return link.b_ip.split("/")[0]
        if (link.a, link.b) == (neighbour, node):
            return link.a_ip.split("/")[0]
    raise KeyError(f"no link {node}-{neighbour}")


def feed(call: str, resource: str) -> dict:
    url = f"http://{NODES['collector'].mgmt}:{FEED_PORT}/data/{call}/data.json?resource={resource}"
    with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 - lab management address
        return json.load(r)


class Controls:
    def __init__(self, build: Path, log: Path) -> None:
        self.build, self.log = build, log
        self.applied: str | None = None
        self.sc: dict = {}
        self.misses: list[str] = []
        log.parent.mkdir(exist_ok=True)
        log.write_text("")

    def say(self, line: str, show: bool = True) -> None:
        if show:
            log.info(line)
        with self.log.open("a") as f:
            f.write(line + "\n")

    def stage(self, title: str) -> None:
        console.stage(title)
        self.say(f"######## {title}", show=False)

    def expect(self, what: str, ok: bool, detail: str) -> None:
        (console.ok if ok else console.fail)(what, detail)
        self.say(f"  [{'ok  ' if ok else 'MISS'}] {what}: {detail}", show=False)
        if not ok:
            self.misses.append(what)

    def apply(self, scenario: str) -> dict:
        if self.applied != scenario:
            self.sc = labctl.render(SCENARIOS / f"{scenario}.yml", self.build)
            labctl.deploy(self.build)
            self.applied = scenario
        labctl.attack("off", self.sc)
        return self.sc

    def decision(self, account: str = "attacker") -> tuple[str, str]:
        """(the CA's decision line, its whole transcript); the transcript goes to the log."""
        out = labctl.dexec("ca", "python3", "/lab/ca.py", "--config", "/lab/ca.json", "--account", account)
        for ln in out.splitlines():
            self.say("    " + ln)
        m = re.search(r"^\[decision \] (.*)$", out, re.M)
        return (m.group(1) if m else "?"), out

    def scan_label(self) -> str:
        out = labctl.scan(self.build, self.sc, False, capture=True).stdout
        m = re.search(rf"^{re.escape(self.sc['domain'])}\s+(\S+)\s+(\S+)\s+(\S+)", out, re.M)
        return f"{m.group(3)} ({m.group(1)} {m.group(2)})" if m else "?"

    # --------------------------------------------------------------------- the controls

    def control_a(self) -> None:
        self.stage("A. caa-signed / web+ns: the REFUSED rests on the resolver validating")
        sc = self.apply("caa-signed")
        labctl.attack("web+ns", sc)
        d, _ = self.decision()
        self.expect(
            "A1 validating: REFUSED, reachable but bogus", d.startswith("REFUSED") and "reachable but bogus" in d, d
        )
        conf = self.build / "resolver" / "unbound.conf"
        text = conf.read_text()
        assert VALIDATING in text, f"{conf} has no {VALIDATING}"
        self.say(f"  -- {NOT_VALIDATING} in {conf.name}, kill -HUP unbound")
        conf.write_text(text.replace(VALIDATING, NOT_VALIDATING))
        self.reload_resolver()
        d, _ = self.decision()
        self.expect("A2 validation off: ISSUED", d.startswith("ISSUED"), d)
        self.say("  -- validator restored")
        conf.write_text(text)
        self.reload_resolver()
        d, _ = self.decision()
        self.expect("A3 validating again: REFUSED", d.startswith("REFUSED") and "reachable but bogus" in d, d)
        labctl.attack("off", sc)

    def reload_resolver(self) -> None:
        labctl.dexec("resolver", "kill", "-HUP", "1")
        time.sleep(3)

    def control_b(self) -> None:
        self.stage("B. tight-maxlength / web: the REFUSED rests on ROV at the transits")
        sc = self.apply("tight-maxlength")
        labctl.attack("web", sc)
        ms = sc["attacker"]["more_specifics"]["web"]
        t2 = labctl.vtysh("transit2", f"show bgp ipv4 unicast {ms}")
        self.expect(f"B1 transit2 drops {ms} (ROV)", "Network not in table" in t2, t2.strip().splitlines()[0])
        d, _ = self.decision()
        self.expect("B2 with ROV: REFUSED, domain control not demonstrated", "domain control not demonstrated" in d, d)
        self.say("  -- no route-map ROV in on transit2<-origin2 and transit1<-transit2, soft out from origin2")
        self.rov(False)
        t1 = labctl.vtysh("transit1", f"show bgp ipv4 unicast {ms}")
        self.expect(
            f"B3 transit1 carries {ms} as rpki invalid", "rpki validation-state: invalid" in t1, "shown" if t1 else "?"
        )
        d, _ = self.decision()
        self.expect("B4 ROV removed: ISSUED", d.startswith("ISSUED"), d)
        self.say("  -- route-map ROV restored")
        self.rov(True)
        d, _ = self.decision()
        self.expect("B5 ROV back: REFUSED", "domain control not demonstrated" in d, d)
        labctl.attack("off", sc)

    def rov(self, on: bool) -> None:
        for node, peer in (("transit2", "origin2"), ("transit1", "transit2")):
            labctl.vtysh(
                node,
                "conf t",
                f"router bgp {NODES[node].asn}",
                "address-family ipv4 unicast",
                f"{'' if on else 'no '}neighbor {link_ip(node, peer)} route-map ROV in",
            )
        labctl.vtysh("origin2", "clear bgp ipv4 unicast * soft out")
        time.sleep(8)

    def control_c(self) -> None:
        self.stage("C. baseline / web: the ISSUED rests on the attacker serving; the feed reads the live table")
        sc = self.apply("baseline")
        web, ms = sc["victim"]["web"], sc["attacker"]["more_specifics"]["web"]
        before = feed("network-info", web)["data"]
        self.say(f"  -- feed network-info {web} before the attack: {before}")
        labctl.attack("web", sc)
        during = feed("network-info", web)["data"]
        want = {"prefix": ms, "asns": [str(sc["victim"]["asn"])]}
        self.expect("C1 feed shows the forged more-specific with the victim's origin", during == want, str(during))
        d, _ = self.decision()
        self.expect("C2 attacker serving: ISSUED", d.startswith("ISSUED"), d)
        addr, dev = f"{web}/{ms.split('/')[1]}", EXTRA_ADDRESSES["attacker"][0][1]
        self.say(f"  -- ip addr del {addr} dev {dev} on the attacker (hijack still announced)")
        labctl.dexec("attacker", "ip", "addr", "del", addr, "dev", dev)
        d, out = self.decision()
        self.expect("C3 attacker silent: REFUSED, unreachable", d.startswith("REFUSED") and "unreachable" in out, d)
        labctl.dexec("attacker", "ip", "addr", "add", addr, "dev", dev)
        time.sleep(2)
        d, _ = self.decision()
        self.expect("C4 address restored: ISSUED", d.startswith("ISSUED"), d)
        labctl.attack("off", sc)

    def control_d(self) -> None:
        self.stage("D. baseline: the scanner's verdict follows the ROA day it is given")
        self.apply("baseline")
        label = self.scan_label()
        self.expect("D1 ROA day as rendered: open-web", label.startswith("open-web"), label)
        roas = self.build / "data" / "rpki" / "lab" / "lab" / "roas.csv.xz"
        original = roas.read_bytes()
        self.say("  -- rewrite the ROA day: every maxLength = the prefix length")
        roas.write_bytes(tightened(original))
        label = self.scan_label()
        self.expect("D2 tight ROA day: contested", label.startswith("contested"), label)
        roas.write_bytes(original)
        label = self.scan_label()
        self.expect("D3 ROA day restored: open-web", label.startswith("open-web"), label)


def tightened(roas_csv_xz: bytes) -> bytes:
    rows = list(csv.reader(io.StringIO(lzma.decompress(roas_csv_xz).decode())))
    for r in rows[1:]:
        r[3] = r[2].split("/")[1]
    buf = io.StringIO()
    csv.writer(buf).writerows(rows)
    return lzma.compress(buf.getvalue().encode())


def run_controls(build: Path) -> int:
    c = Controls(build, labctl.run_dir("controls") / "controls.log")
    c.say(f"negative controls, {time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
    for control in (c.control_a, c.control_b, c.control_c, c.control_d):
        control()
    if c.misses:
        console.fail(f"controls: MISSING {len(c.misses)} expected flips", ", ".join(c.misses))
    else:
        console.ok("controls: all expected flips observed")
    c.say(
        "controls: " + ("all expected flips observed" if not c.misses else f"MISSING {len(c.misses)}: {c.misses}"),
        show=False,
    )
    return 1 if c.misses else 0
