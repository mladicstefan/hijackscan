"""Read a TLD zone (dig axfr text form, possibly split into parts) and draw a reproducible sample of delegations.

The zone gives two population facts for free: which names are delegated (NS at the parent) and which of them have
a DS at the parent. Everything else (addresses, CAA, DNSKEY, validation) is still collected live per sampled domain.
"""

from __future__ import annotations

import random
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from publicsuffix2 import get_sld

from .. import console

TOP_OPERATORS = 20


@dataclass
class Zone:
    source: list[Path]
    apex: str = ""
    soa_serial: str = ""
    delegated: set[str] = field(default_factory=set)
    ds: set[str] = field(default_factory=set)
    operators: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))  # name -> NS operators

    def operator_counts(self) -> list[tuple[str, int, int]]:
        """(operator, delegations, delegations with DS), largest first; a name with two operators counts for both."""
        delegations: Counter[str] = Counter()
        with_ds: Counter[str] = Counter()
        for name, ops in self.operators.items():
            for op in ops:
                delegations[op] += 1
                if name in self.ds:
                    with_ds[op] += 1
        return [(op, n, with_ds[op]) for op, n in delegations.most_common()]


def operator_of(host: str) -> str:
    return get_sld(host, strict=False) or host


def read_zone(parts: list[Path]) -> Zone:
    """Parse the dig axfr output across `parts` in the given order. Only NS, DS and SOA records are looked at."""
    z = Zone(source=parts)
    for part in parts:
        console.info("reading", str(part))
        with part.open(errors="replace") as fh:
            for line in fh:
                if not line or line[0] == ";":
                    continue
                f = line.split()
                if len(f) < 5 or f[2] != "IN":
                    continue
                owner, rtype = f[0].lower().rstrip("."), f[3]
                if rtype == "SOA":
                    z.apex, z.soa_serial = owner, f[6]
                    continue
                if owner == z.apex:
                    continue
                if rtype == "NS":
                    z.delegated.add(owner)
                    z.operators[owner].add(operator_of(f[4].lower().rstrip(".")))
                elif rtype == "DS":
                    z.ds.add(owner)
    z.ds &= z.delegated
    console.ok(f"zone {z.apex}", f"serial {z.soa_serial}: {len(z.delegated):,} delegations, {len(z.ds):,} with DS")
    return z


def sample(z: Zone, n: int, seed: int) -> list[str]:
    """Same zone content + same seed = same names, on any machine."""
    population = sorted(z.delegated)
    if n > len(population):
        raise SystemExit(f"n={n} exceeds the {len(population)} delegations in the zone")
    return random.Random(seed).sample(population, n)


def write_sample(z: Zone, names: list[str], seed: int, out: Path) -> None:
    """A domains.txt that `collect` and `zone` read as before; the `#` header carries the population facts."""
    lines = [
        "# hijackscan-sample v1",
        f"# source={' '.join(p.name for p in z.source)}",
        f"# apex={z.apex}",
        f"# soa_serial={z.soa_serial}",
        f"# seed={seed}",
        f"# n={len(names)}",
        f"# population={len(z.delegated)}",
        f"# population_ds={len(z.ds)}",
        f"# sample_ds={sum(d in z.ds for d in names)}",
    ]
    lines += [f"# ns_operator={op} delegations={d} ds={s}" for op, d, s in z.operator_counts()[:TOP_OPERATORS]]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines + names) + "\n")
    console.ok(f"wrote {len(names)} domains", str(out))


def read_meta(path: Path) -> dict | None:
    """The population facts from a sample header, or None for a plain domain list."""
    with path.open() as fh:
        first = fh.readline()
        if not first.startswith("# hijackscan-sample"):
            return None
        meta: dict = {"ns_operators": []}
        for line in fh:
            if not line.startswith("#"):
                break
            kv = line[1:].strip()
            if kv.startswith("ns_operator="):
                op, d, s = kv.split()
                meta["ns_operators"].append(
                    {"operator": op.split("=", 1)[1], "delegations": int(d.split("=")[1]), "ds": int(s.split("=")[1])}
                )
            elif "=" in kv:
                k, v = kv.split("=", 1)
                meta[k] = int(v) if v.isdigit() and k != "soa_serial" else v
    return meta
