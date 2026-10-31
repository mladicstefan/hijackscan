"""Risk score (0-10) and CVSS severity for one domain. Pure: no network, no I/O.

Implements design/formula.md. Reference numbers [n] match that document and REFERENCES below.

    Score = 10 x I x max over paths ( open x K x L )
    P     = p x P(at least r-f of r remote perspectives fooled)     (MPIC quorum, primary fooled too)
    L     = 1 - (1 - P)^N                                          (N issuance attempts per hijack)
    K     = (CVSS 3.1 base with AC:H / with AC:L) ^ h              (h high-complexity conditions)

`summary` is the quick, actionable view (score, severity, one sentence, the fix that helps most);
`details` carries every input, path, finding, vector and reference behind it.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from datetime import date

from .score import AddressDerived, Scored

REFERENCES: dict[int, tuple[str, str]] = {
    1: ("FIRST, CVSS v3.1 Specification", "https://www.first.org/cvss/v3.1/specification-document"),
    2: ("FIRST, CVSS v4.0 Specification", "https://www.first.org/cvss/v4.0/specification-document"),
    3: ("NIST IR 7502, Common Configuration Scoring System", "https://csrc.nist.gov/pubs/ir/7502/final"),
    5: ("OWASP Risk Rating Methodology", "https://community.owasp.org/OWASP_Risk_Rating_Methodology"),
    6: (
        "CA/B Forum TLS Baseline Requirements 3.2.2.9 (MPIC)",
        "https://github.com/cabforum/servercert/blob/main/docs/BR.md",
    ),
    8: (
        "Birge-Lee et al., Bamboozling Certificate Authorities with BGP, USENIX Security 2018",
        "https://www.usenix.org/conference/usenixsecurity18/presentation/birge-lee",
    ),
    9: (
        "APNIC, Latest BGP hijack targets hosting software vendor (2026-09-22)",
        "https://blog.apnic.net/2026/09/22/latest-bgp-hijack-targets-hosting-software-vendor/",
    ),
    12: ("RFC 9319, The Use of maxLength in the RPKI", "https://www.rfc-editor.org/rfc/rfc9319"),
    13: ("MITRE ATT&CK T1588.004 Digital Certificates", "https://attack.mitre.org/techniques/T1588/004"),
    14: ("MITRE ATT&CK T1557 Adversary-in-the-Middle", "https://attack.mitre.org/techniques/T1557/"),
    18: ("RFC 8659, DNS Certification Authority Authorization (CAA)", "https://www.rfc-editor.org/rfc/rfc8659"),
    19: ("RFC 8657, CAA accounturi and validationmethods", "https://www.rfc-editor.org/rfc/rfc8657"),
}

# --------------------------------------------------------------------------- CVSS v3.1 [1]

_CVSS31 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def roundup(x: float) -> float:
    """CVSS v3.1 Roundup (Appendix A): smallest one-decimal number >= x, float-safe."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss31_base(vector: str) -> float:
    """Base score of a CVSS:3.1 vector string, per the specification's equations [1]."""
    m = dict(part.split(":") for part in vector.split("/")[1:])
    changed = m["S"] == "C"
    iss = 1 - (1 - _CVSS31["CIA"][m["C"]]) * (1 - _CVSS31["CIA"][m["I"]]) * (1 - _CVSS31["CIA"][m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    pr = _CVSS31["PR_C" if changed else "PR_U"][m["PR"]]
    expl = 8.22 * _CVSS31["AV"][m["AV"]] * _CVSS31["AC"][m["AC"]] * pr * _CVSS31["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    return roundup(min((1.08 if changed else 1) * (impact + expl), 10))


# The attack as CVSS sees it: network, no privileges or user interaction on the victim, scope changed
# (the misissued certificate hurts the domain's users), confidentiality and integrity lost.
CVSS31_TEMPLATE = "CVSS:3.1/AV:N/AC:{ac}/PR:N/UI:N/S:C/C:H/I:H/A:N"
CVSS40_TEMPLATE = "CVSS:4.0/AV:N/AC:{ac}/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N"  # AT:P = network injection [2]
COMPLEXITY_STEP = cvss31_base(CVSS31_TEMPLATE.format(ac="H")) / cvss31_base(CVSS31_TEMPLATE.format(ac="L"))  # 0.87

# --------------------------------------------------------------------------- severity [1, 2]

SEVERITIES = ("None", "Low", "Medium", "High", "Critical", "Unknown")


def severity(score: float | None) -> str:
    """CVSS qualitative rating scale: None 0.0, Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0."""
    if score is None:
        return "Unknown"
    if score == 0:
        return "None"
    return "Low" if score < 4 else "Medium" if score < 7 else "High" if score < 9 else "Critical"


# --------------------------------------------------------------------------- parameters


@dataclass(frozen=True)
class RiskParams:
    remote_perspectives: int = 4  # BR 3.2.2.9: >= 4 from 2026-06-15, >= 5 from 2026-12-15 [6]
    allowed_non_corroborations: int = 1  # BR 3.2.2.9 table: 2-5 remote -> 1, 6+ -> 2 [6]
    attempts: int = 5  # assumption: certificate requests during one hijack
    contest_share: float = 0.3  # assumption: share of CA perspectives won in an exact-prefix contest
    impact: float = 1.0  # environmental hook; 1 = full impact

    @classmethod
    def for_date(cls, day: date, **kw) -> RiskParams:
        """The MPIC minimum in force on `day` [6]."""
        r = 5 if day >= date(2026, 12, 15) else 4 if day >= date(2026, 6, 15) else 3 if day >= date(2026, 3, 15) else 2
        return cls(remote_perspectives=r, allowed_non_corroborations=1 if r <= 5 else 2, **kw)


def params_for(rec: dict) -> RiskParams:
    """Parameters for a record: the MPIC rules in force on the day it was collected."""
    try:
        return RiskParams.for_date(date.fromisoformat(rec["fetched_at"][:10]))
    except (KeyError, ValueError):
        return RiskParams()


def p_attempt(p: float, prm: RiskParams) -> float:
    """One issuance attempt succeeds: primary fooled and at least r-f of r remote perspectives fooled [6]."""
    r, f = prm.remote_perspectives, prm.allowed_non_corroborations
    return p * sum(math.comb(r, k) * p**k * (1 - p) ** (r - k) for k in range(r - f, r + 1))


# --------------------------------------------------------------------------- data model


@dataclass
class PathScore:
    path: str  # web | ns | contest
    target: str  # the validated name, "nameservers", or "web + nameservers"
    open: bool
    blocked_by: list[str]
    p: float  # share of CA perspectives that reach the attacker
    p_note: str
    h: int  # high-complexity conditions
    h_reasons: list[str]
    p_attempt: float
    likelihood: float
    complexity: float
    score: float
    severity: str
    evidence: list[str] = field(default_factory=list)  # why each captured address is forgeable


@dataclass
class Finding:
    id: str
    kind: str  # exposure | missing-defence | hygiene | data
    severity: str | None  # exposure findings carry the severity of the path they open
    detail: str
    evidence: list[str] = field(default_factory=list)
    refs: list[int] = field(default_factory=list)


@dataclass
class Fix:
    action: str
    owner: str
    score_after: float | None
    severity_after: str
    refs: list[int] = field(default_factory=list)


@dataclass
class Risk:
    domain: str
    score: float | None
    severity: str
    label: str
    headline: str
    best: PathScore | None
    paths: list[PathScore]
    findings: list[Finding]
    fixes: list[Fix]
    cvss31_vector: str | None
    cvss31_base: float | None
    cvss40_vector: str | None
    attack_techniques: list[dict]
    params: RiskParams
    errors: list[str]

    @property
    def fix(self) -> Fix | None:
        """The single action that lowers the score most (domain-owner actions win ties)."""
        singles = [f for f in self.fixes if "+" not in f.owner and " + " not in f.action]
        best = min(singles, key=lambda f: f.score_after, default=None)
        return best if best and best.score_after < (self.score or 0) else None

    @property
    def full_fix(self) -> Fix | None:
        """The fewest actions that bring the score to 0, when that differs from `fix`."""
        f = next((f for f in self.fixes if f.score_after == 0), None)
        return f if f and f is not self.fix else None

    def summary(self) -> dict:
        def brief(f: Fix | None) -> dict | None:
            return (
                {"action": f.action, "owner": f.owner, "score_after": f.score_after, "severity_after": f.severity_after}
                if f
                else None
            )

        return {
            "domain": self.domain,
            "score": self.score,
            "severity": self.severity,
            "label": self.label,
            "headline": self.headline,
            "fix": brief(self.fix),
            "full_fix": brief(self.full_fix),
        }

    def details(self) -> dict:
        refs = sorted({r for x in [*self.findings, *self.fixes] for r in x.refs} | {1, 2, 6})
        return {
            "calculation": asdict(self.best) if self.best else None,
            "paths": [asdict(p) for p in self.paths],
            "findings": [asdict(x) for x in self.findings],
            "fixes": [asdict(x) for x in self.fixes],
            "vectors": {"cvss31": self.cvss31_vector, "cvss31_base": self.cvss31_base, "cvss40": self.cvss40_vector},
            "attack_techniques": self.attack_techniques,
            "params": asdict(self.params) | {"complexity_step": round(COMPLEXITY_STEP, 4)},
            "data_quality": {"complete": not self.errors and self.score is not None, "errors": self.errors},
            "references": [
                {"n": n, "title": REFERENCES[n][0], "url": REFERENCES[n][1]} for n in refs if n in REFERENCES
            ],
        }

    def to_json(self) -> dict:
        return {"schema_version": 2, **self.summary(), "details": self.details()}


# --------------------------------------------------------------------------- MITRE ATT&CK

_RECON = [
    ("T1590.005", "Gather Victim Network Information: IP Addresses"),
    ("T1596", "Search Open Technical Databases (BGP, RPKI)"),
]
_INFRA = [("T1584.008", "Compromise Infrastructure: Network Devices (a BGP-speaking network)")]
_HIJACK = [("T1557", "Adversary-in-the-Middle (closest fit: ATT&CK has no BGP hijack technique)")]
_CERT = [
    ("T1588.004", "Obtain Capabilities: Digital Certificates"),
    ("T1608.003", "Stage Capabilities: Install Digital Certificate"),
]
ATTACK_TECHNIQUES = {
    "web": _RECON + _INFRA + _HIJACK + _CERT,
    "ns": [("T1590.002", "Gather Victim Network Information: DNS"), *_RECON, *_INFRA, *_HIJACK]
    + [("T1584.002", "Compromise Infrastructure: DNS Server (forged authoritative answers)")]
    + _CERT,
    "contest": _RECON + _INFRA + _HIJACK + _CERT,
}

# --------------------------------------------------------------------------- assessment


def _score(p: float, h: int, prm: RiskParams) -> tuple[float, float, float, float]:
    pa = p_attempt(p, prm)
    lik = 1 - (1 - pa) ** prm.attempts
    k = COMPLEXITY_STEP**h
    return pa, lik, k, roundup(10 * prm.impact * k * lik) if lik > 0 else 0.0


def _forgeable(a: AddressDerived, tight: bool) -> bool:
    return a.forgeable_more_specific and not tight


def _why(a: AddressDerived) -> str:
    if not a.prefix:
        return f"{a.ip}: no announced prefix, anyone can announce it"
    if a.rpki_derived == "not-found":
        return f"{a.ip} in {a.prefix}: no ROA, a forged more-specific is never RPKI-invalid"
    return f"{a.ip} in {a.prefix}: ROA {a.roa_summary} allows a longer, RPKI-valid prefix"


def assess(rec: dict, s: Scored, prm: RiskParams | None = None, ov: dict | None = None, *, fixes: bool = True) -> Risk:
    """Score one domain. `ov` applies what-if fixes: pinned, signed, web_tight, ns_tight."""
    prm = prm or params_for(rec)
    ov = ov or {}
    errors = list(s.errors)
    ns_all = {a.ip: a for v in s.ns_addresses.values() for a in v}
    if not s.web_addresses:
        errors.append("no web address: apex and www do not resolve")
    if not ns_all:
        errors.append("no nameserver address")
    if errors:
        return Risk(
            s.domain, None, "Unknown", "unknown", "Not scored: " + errors[0], None, [], _data_finding(errors), [],
            None, None, None, [], prm, errors,
        )  # fmt: skip

    pinned = ov.get("pinned", s.pinned)
    has_caa = pinned or s.has_caa
    dnssec = "secure" if ov.get("signed") else s.dnssec
    vm = set(s.caa.validationmethods) if has_caa and not ov.get("pinned") else set()
    forbids = has_caa and not ov.get("pinned") and s.caa.issue and all(x == "" for x in s.caa.issue)
    web_tight, ns_tight = ov.get("web_tight", False), ov.get("ns_tight", False)

    web_block = []
    if pinned:
        web_block.append("CAA accounturi: only the owner's ACME account may issue [19]")
    if forbids:
        web_block.append('CAA issue ";": no CA may issue [18]')
    if vm and not vm & {"http-01", "tls-alpn-01"}:
        web_block.append("CAA validationmethods excludes http-01 and tls-alpn-01 [19]")
    ns_block = []
    if dnssec == "secure":
        ns_block.append("DNSSEC: a validating CA rejects forged answers")
    elif dnssec == "bogus":
        ns_block.append("DNSSEC bogus: validating CAs fail closed")

    paths: list[PathScore] = []
    by_ip = {a.ip: a for a in s.web_addresses}
    for name, entry in rec.get("names", {}).items():
        addrs = [by_ip[ip] for ip in entry.get("A", []) + entry.get("AAAA", []) if ip in by_ip]
        forged = [a for a in addrs if _forgeable(a, web_tight)]
        if not addrs or not forged:
            continue
        p = len(forged) / len(addrs)
        prefixes = sorted({a.prefix or a.ip for a in forged})
        h_reasons = [f"{len(prefixes)} prefixes must be hijacked at once"] if len(prefixes) > 1 else []
        note = f"{len(forged)} of {len(addrs)} addresses forgeable"
        paths.append(_path("web", name, web_block, p, note, h_reasons, prm, [_why(a) for a in forged]))
    ns_forged = [a for a in ns_all.values() if _forgeable(a, ns_tight)]
    if ns_forged:
        p = len(ns_forged) / len(ns_all)
        prefixes = sorted({a.prefix or a.ip for a in ns_forged})
        h_reasons = ["attacker must run a forged authoritative DNS server"]
        if len(prefixes) > 1:
            h_reasons.append(f"{len(prefixes)} prefixes must be hijacked at once")
        note = f"{len(ns_forged)} of {len(ns_all)} nameserver addresses forgeable"
        paths.append(_path("ns", "nameservers", ns_block, p, note, h_reasons, prm, [_why(a) for a in ns_forged]))
    contest_block = web_block + ns_block if web_block and ns_block else []
    paths.append(
        _path(
            "contest", "web + nameservers", contest_block, prm.contest_share,
            "exact-prefix origin contest, always possible without ASPA (assumed share)",
            ["wins only where the attacker's route is preferred"], prm,
        )
    )  # fmt: skip

    order = {"web": 0, "ns": 1, "contest": 2}
    best = max(paths, key=lambda x: (x.score, -order[x.path]))
    score_ = best.score if best.open else 0.0
    label = _label(best, score_, has_caa)
    ac = "H" if best.h else "L"
    risk = Risk(
        domain=s.domain,
        score=score_,
        severity=severity(score_),
        label=label,
        headline=_headline(label, best, s, prm),
        best=best if score_ else None,
        paths=paths,
        findings=_findings(s, paths, ns_all, has_caa, pinned, dnssec),
        fixes=[],
        cvss31_vector=CVSS31_TEMPLATE.format(ac=ac) if score_ else None,
        cvss31_base=cvss31_base(CVSS31_TEMPLATE.format(ac=ac)) if score_ else None,
        cvss40_vector=CVSS40_TEMPLATE.format(ac=ac) if score_ else None,
        attack_techniques=[{"id": i, "name": n} for i, n in ATTACK_TECHNIQUES[best.path]] if score_ else [],
        params=prm,
        errors=[],
    )
    if fixes and score_:
        risk.fixes = _fixes(rec, s, prm, ov, has_caa)
    return risk


def _path(
    kind: str, target: str, block: list[str], p: float, note: str, h_reasons: list[str], prm: RiskParams,
    evidence: list[str] | None = None,
) -> PathScore:  # fmt: skip
    pa, lik, k, sc = _score(p, len(h_reasons), prm)
    open_ = not block
    sc = sc if open_ else 0.0
    return PathScore(
        kind, target, open_, block, round(p, 4), note, len(h_reasons), h_reasons,
        round(pa, 4), round(lik, 4), round(k, 4), sc, severity(sc), evidence or [],
    )  # fmt: skip


def _label(best: PathScore, score_: float, has_caa: bool) -> str:
    if not score_:
        return "closed"
    if best.path == "web":
        return "caa-bypassable" if has_caa else "open-web"
    if best.path == "ns":
        if best.p < 1:
            return "ns-partial"
        return "caa-erasable" if has_caa else "open-dns"
    return "contested"


def _headline(label: str, best: PathScore, s: Scored, prm: RiskParams) -> str:
    pct = f"{100 * best.likelihood:.0f}%"
    ca = ", ".join(x for x in s.caa.issue if x) or "the CA named in CAA"
    return {
        "closed": "Every path is blocked: DNSSEC plus CAA accounturi (or an equivalent CAA restriction).",
        "open-web": f"A forged more-specific route to the web server of {best.target} gets a certificate from any CA "
        f"({best.p_note}; {pct} success in {prm.attempts} attempts).",
        "caa-bypassable": f"A forged more-specific route to the web server of {best.target} gets a certificate from "
        f"{ca} with any account: CAA has no accounturi ({pct} success).",
        "open-dns": "Every nameserver address can be captured: forged DNS answers pass DNS-01 at any CA "
        f"({pct} success).",
        "caa-erasable": "Every nameserver address can be captured in an unsigned zone: the attacker answers "
        f"'no CAA' and passes validation ({pct} success).",
        "ns-partial": f"{best.p_note}: forged answers reach enough CA perspectives in {pct} of hijacks "
        f"({prm.attempts} attempts each).",
        "contested": "No forged more-specific route exists; only an exact-prefix contest remains, and no DNS-side "
        f"defence stops it ({pct} success, assumed contest share {prm.contest_share:.0%}).",
    }[label]


def _data_finding(errors: list[str]) -> list[Finding]:
    return [Finding("DATA_INCOMPLETE", "data", None, "the record is incomplete; no score is computed", errors)]


def _findings(s: Scored, paths: list[PathScore], ns_all: dict, has_caa: bool, pinned: bool, dnssec: str):
    out: list[Finding] = []
    for p in paths:
        if p.path == "web":
            out.append(
                Finding(
                    "WEB_MORE_SPECIFIC", "exposure", p.severity if p.open else "None", f"{p.target}: {p.p_note}",
                    p.evidence, [8, 9, 12],
                )
            )  # fmt: skip
        elif p.path == "ns":
            out.append(
                Finding(
                    "NS_CAPTURABLE", "exposure", p.severity if p.open else "None", p.p_note,
                    p.evidence, [6, 8, 12],
                )
            )  # fmt: skip
        else:
            out.append(Finding("EXACT_PREFIX_CONTEST", "exposure", p.severity if p.open else "None", p.p_note, [], [8]))
    every = list({a.ip: a for a in [*s.web_addresses, *ns_all.values()]}.values())
    no_roa = [a for a in every if a.rpki_derived != "found"]
    if no_roa:
        detail = f"{len(no_roa)} addresses not covered by any ROA"
        out.append(Finding("NO_ROA", "exposure", None, detail, [_why(a) for a in no_roa], [12]))
    if not has_caa:
        detail = "no CAA record at any label up to the TLD: every CA may issue"
        out.append(Finding("NO_CAA", "missing-defence", None, detail, [], [18]))
    elif not pinned:
        out.append(
            Finding(
                "CAA_NO_ACCOUNTURI", "missing-defence", None,
                f"CAA at {s.caa_from} names {', '.join(x for x in s.caa.issue if x) or '-'} but no accounturi: "
                "any account at that CA may issue", [], [19],
            )
        )  # fmt: skip
    if dnssec == "unsigned":
        out.append(Finding("UNSIGNED", "missing-defence", None, "no DS at the parent: DNS answers can be forged"))
    elif dnssec == "bogus":
        out.append(Finding("DNSSEC_BOGUS", "missing-defence", None, "DS present but answers do not validate", [], []))
    loose = list({a.prefix: a for a in every if a.roa_too_permissive and not a.forgeable_more_specific}.values())
    if loose:
        out.append(
            Finding(
                "ROA_TOO_PERMISSIVE", "hygiene", None, "ROA maxLength exceeds the announced length",
                [f"{a.prefix}: {a.roa_summary}" for a in loose], [12],
            )
        )  # fmt: skip
    return out


_FIX_ACTIONS = {
    "pinned": ("add accounturi=<your ACME account> to the CAA issue record", "domain-owner", [19]),
    "no_caa_pinned": ("publish CAA issue=<your CA>; accounturi=<your ACME account>", "domain-owner", [18, 19]),
    "signed": ("sign the zone and publish the DS at the registrar (DNSSEC)", "dns-host", []),
    "web_tight": ("set ROA maxLength = announced length for the web prefixes", "hosting-provider", [12]),
    "ns_tight": ("set ROA maxLength = announced length for the nameserver prefixes", "dns-host", [12]),
}


def _fixes(rec: dict, s: Scored, prm: RiskParams, ov: dict, has_caa: bool) -> list[Fix]:
    """Re-score with each fix applied; best (lowest score, fewest actions) first."""
    candidates = [("pinned",), ("signed",), ("web_tight",), ("ns_tight",), ("pinned", "signed")]
    out = []
    for i, keys in enumerate(candidates):
        r = assess(rec, s, prm, ov | {k: True for k in keys}, fixes=False)
        acts = [_FIX_ACTIONS["no_caa_pinned" if k == "pinned" and not has_caa else k] for k in keys]
        out.append(
            (
                r.score,
                len(keys),
                i,
                Fix(
                    " + ".join(a[0] for a in acts),
                    " + ".join(dict.fromkeys(a[1] for a in acts)),
                    r.score,
                    r.severity,
                    sorted({n for a in acts for n in a[2]}),
                ),
            )
        )
    return [f for *_, f in sorted(out, key=lambda t: t[:3])]
