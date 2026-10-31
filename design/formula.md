# Risk scoring: formula and severity

Status: implemented in `src/hijackscan/risk.py` (see §11). Date: 2026-10-31.

## 1. Problem

`score.py` used to put every domain into one of five classes (`closed`, `caa-only`, `caa-erasable`, `open`,
`contested-only`) with first-match-wins rules. On the 100-domain sample this has four weaknesses:

- **Missing data reads as safe.** All 13 domains with collection errors land in `contested-only`; 10 domains have
  no web or nameserver addresses at all and are scored as if nothing were forgeable.
- **A hidden rule.** `classify()` ends with an undocumented fallback (CAA + unsigned + forgeable web → `open`) that
  also mislabels a pinned (`accounturi`) domain whose nameservers cannot be captured.
- **Nameserver capture is all-or-nothing.** The nameserver path only counts when *every* nameserver address is
  forgeable; capturing 2 of 3 counts as nothing.
- **No ordering inside a class.** 78 of 100 domains are `contested-only`; the label says nothing about how hard the
  remaining attack is.

Goal: a numeric score, 0–10, that is derived from measured inputs by a closed formula, includes attack complexity,
maps to the CVSS severity scale by fixed thresholds, and keeps the specific vulnerability visible.

## 2. Prior art

| Source | What we take from it |
|---|---|
| CVSS v3.1 [1] | Closed-form base score; the AC:L/AC:H constants (0.77/0.44); the severity bands (Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0). |
| CVSS v4.0 [2] | Vocabulary: Attack Requirements (AT) names *network injection* as an example of a Present requirement; Subsequent System impact (SC/SI/SA) for harm to users of the domain. v4.0 scores by MacroVector lookup, not a formula, so it is used for the vector string only. |
| NIST IR 7502, CCSS [3] | Precedent for scoring *configuration* weaknesses (not software flaws) with CVSS-compatible metrics and vectors. Snyk applies the same idea to IaC misconfigurations [4]. |
| OWASP Risk Rating [5] | Risk = likelihood × impact, three bands. |
| CA/B Forum Baseline Requirements §3.2.2.9 [6, 7] | Multi-Perspective Issuance Corroboration (MPIC): the number of remote perspectives and the allowed non-corroborations, which set the success probability of a partial hijack. CAA checks are corroborated as well. |
| Birge-Lee et al. 2018 [8] | BGP attacks on domain validation work in practice (sub-prefix, equally-specific, prepended, AS-path poisoning); multiple vantage points as the countermeasure. |
| Hetzner / Softaculous incident, 28 Aug 2026 [9, 10, 11] | A forged-origin, RPKI-valid /24 inside `162.55.0.0/16` (ROA maxLength 24) propagated globally, so the CA's whole MPIC quorum saw the attacker. Justifies p = 1 for a forgeable more-specific. |
| RFC 9319 [12] | Avoid ROA maxLength; loose maxLength enables forged-origin sub-prefix hijacks. |
| MITRE ATT&CK [13, 14] | Technique IDs for the attack chain (§7). |

Why not CVSS alone: scoring the attack with CVSS 3.1 (`AV:N/PR:N/UI:N/S:C/C:H/I:H/A:N`) gives **10.0** with AC:L
and **8.7** with AC:H. Every domain would get one of two numbers. CVSS describes *how bad an exploitable issue is*,
not *how likely the attack is to succeed against this configuration*; the formula below adds the second part.

## 3. Attack paths

An attacker wants a publicly trusted certificate for a name of the domain. Three paths:

| Path | How | Blocked by |
|---|---|---|
| `web` | Announce an RPKI-valid more-specific of the web prefix; answer HTTP-01 / TLS-ALPN-01. | CAA `accounturi` [19]; CAA `issue ";"` [18]; CAA `validationmethods` without `http-01` [19]. Not blocked by DNSSEC (the A record is genuine; the route is not). Not blocked by CAA without `accounturi` (the attacker opens an account at the allowed CA). |
| `ns` | Capture nameserver prefixes; serve forged answers (DNS-01 TXT, or a forged A record plus "no CAA"). | DNSSEC (signed zone, CA validates). A bogus zone also blocks issuance. CAA, even with `accounturi`, does **not** block: the forged answer erases it. |
| `contest` | Announce the exact prefix with a forged origin; win route selection only where the attacker's path is preferred. Applies to web and nameserver prefixes. | As `web` for the web side, as `ns` for the nameserver side. Always possible absent ASPA. |

## 4. Formula

```
Score = 10 × I × max over paths a of ( open_a × K_a × L_a )

P_a = p_a × Σ_{k = r−f}^{r} C(r, k) · p_a^k · (1 − p_a)^(r−k)
L_a = 1 − (1 − P_a)^N
K_a = 0.87^h_a
```

| Symbol | Meaning |
|---|---|
| `open_a` | 0 if a defence in §3 blocks path a, else 1. |
| `p_a` | Probability that one CA network perspective reaches the attacker on path a. |
| `P_a` | Probability that one issuance attempt succeeds: the primary perspective is fooled **and** at least `r − f` of `r` remote perspectives are fooled (MPIC quorum). |
| `L_a` | Likelihood: probability of at least one success in `N` attempts during one hijack. |
| `K_a` | Attack-complexity factor; `h_a` is the number of high-complexity conditions. |
| `I` | Impact factor, 1 by default (hook for environmental weighting, e.g. banks or `gov.rs`). |

### 4.1 Inputs per path

| Path | `p` | `h` |
|---|---|---|
| `web` | Share of the validated name's addresses whose prefix is forgeable (computed per name: apex, `www`; the best name is used). | +1 if more than one distinct prefix must be hijacked at once. |
| `ns` | Share of all nameserver **addresses** (v4 and v6) that are forgeable. A CA's resolver may ask any of them. | +1 for running a forged authoritative server; +1 if more than one distinct prefix must be hijacked at once. |
| `contest` | `q` (parameter). | +1: success depends on topology between the attacker and each perspective (CVSS AC:H condition). |

### 4.2 Parameters

| Parameter | Default | Basis |
|---|---|---|
| `r` remote perspectives | 4 | BR §3.2.2.9: ≥ 4 from 2026-06-15; **≥ 5 from 2026-12-15** [6, 15]. |
| `f` allowed non-corroborations | 1 | BR §3.2.2.9 table: 2–5 perspectives → 1; 6+ → 2 [6]. |
| `N` attempts per hijack | 5 | Assumption. |
| `q` contest win share | 0.3 | Assumption, no measurement yet. The weakest parameter. |
| complexity ratio | 0.87 | CVSS 3.1 base score of this attack with AC:H divided by AC:L: 8.7 / 10.0 [1]. Each hard condition costs what CVSS charges for high complexity. |

All parameters are configurable and are written into `report.json` with the results.

### 4.3 Derivation of the 0.87 constant (CVSS 3.1)

Vector `AV:N/PR:N/UI:N/S:C/C:H/I:H/A:N`:

```
ISS            = 1 − (1 − 0.56)(1 − 0.56)(1 − 0) = 0.8064
Impact (S:C)   = 7.52 × (0.8064 − 0.029) − 3.25 × (0.8064 − 0.02)^15 = 5.758
Exploitability = 8.22 × 0.85 × AC × 0.85 × 0.85      → 3.887 (AC:L 0.77), 2.221 (AC:H 0.44)
Base (S:C)     = Roundup(min(1.08 × (Impact + Exploitability), 10))
               → 10.0 (AC:L), 8.7 (AC:H)
```

## 5. Severity

The CVSS qualitative severity rating scale, unchanged [1, 2]. Since `Score / 10 = K × L` (with `I = 1`), each band
also reads as a complexity-adjusted chance that the attack succeeds within `N` attempts.

| Severity | Score | Adjusted chance of success | Reading |
|---|---|---|---|
| None | 0.0 | 0 % | every path blocked |
| Low | 0.1–3.9 | < 40 % | the attack mostly fails, even with retries |
| Medium | 4.0–6.9 | 40–70 % | the attack succeeds on a substantial share of hijacks |
| High | 7.0–8.9 | 70–90 % | the attack usually succeeds |
| Critical | 9.0–10.0 | ≥ 90 % | the attack is near certain (the 28 Aug 2026 pattern) |
| Unknown | — | — | collection errors or no web / nameserver addresses; no score is computed |

Scores are rounded with the CVSS v3.1 `Roundup` function [1], so any non-zero chance scores at least 0.1 (Low) and
only a fully blocked domain scores 0.0 (None).

### 5.1 Two levels of output

| Level | Shown by default | Content |
|---|---|---|
| Summary | yes | domain, score, severity, label, one-sentence headline, **fix first** (the single action that lowers the score most), **to close** (the fewest actions that reach 0.0) |
| Details | `--details`, collapsed `<details>` in HTML, `details` key in JSON | the calculation with every input, all paths (including blocked ones and why), findings with evidence, the re-score of every fix, CVSS 3.1 and 4.0 vectors, ATT&CK techniques, references |

Reading a domain: *"nbs.rs CRITICAL 10.0 open-web — fix first: publish CAA with accounturi → 8.0 High; to close:
CAA with accounturi + DNSSEC → 0.0 None."* The details then show why CAA alone only reaches 8.0: 2 of 3 nameserver
addresses can also be captured in the unsigned zone.

### 5.2 Labels

The severity is the number; the label names the path that produced it, so the specific vulnerability stays
visible.

| Label | Driving path | Condition |
|---|---|---|
| `closed` | none | score 0 |
| `open-web` | `web` | no CAA |
| `caa-bypassable` | `web` | CAA without `accounturi` |
| `open-dns` | `ns` | no CAA, all nameserver addresses capturable |
| `caa-erasable` | `ns` | CAA present, all nameserver addresses capturable |
| `ns-partial` | `ns` | some, not all, nameserver addresses capturable |
| `contested` | `contest` | no more-specific path |

`ns-partial` may fall in any severity depending on `p`:

| `p` (nameservers capturable) | 1/3 | 1/2 | 2/3 | 4/5 | 1 |
|---|---|---|---|---|---|
| `P` per attempt | 0.04 | 0.16 | 0.40 | 0.66 | 1.00 |
| score (`h` = 1) | 1.5 Low | 5.0 Medium | 8.0 High | 8.7 High | 8.7 High |

## 6. Worked examples

**Forgeable web prefix, one prefix, no CAA.** `p = 1, h = 0` → `P = 1, L = 1, K = 1` → **10.0 Critical**, `open-web`.

**Two of three nameserver addresses forgeable, unsigned.**
`p = 0.67`: `P = 0.67 × (0.67⁴ + 4 × 0.67³ × 0.33) = 0.40`; `L = 1 − 0.60⁵ = 0.92`; `h = 1`, `K = 0.87`
→ **8.0 High**, `ns-partial`.

**Exact-prefix contest only.** `p = q = 0.3`: `P = 0.3 × (0.3⁴ + 4 × 0.3³ × 0.7) = 0.025`; `L = 1 − 0.975⁵ = 0.12`;
`K = 0.87` → `10 × 0.87 × 0.12 = 1.04` → Roundup → **1.1 Low**, `contested`.

**Signed zone with CAA `accounturi`.** Every path blocked → **0.0 None**, `closed`.

## 7. MITRE ATT&CK mapping

| Step | Technique |
|---|---|
| Reconnaissance: addresses, DNS, ROAs | T1590.005 Gather Victim Network Information: IP Addresses; T1590.002 DNS; T1596 Search Open Technical Databases |
| Get a network that can announce routes | T1583 Acquire Infrastructure; T1584.008 Compromise Infrastructure: Network Devices (the 2026 incident used an upstream, AS62390 [9]) |
| BGP hijack | **No ATT&CK technique.** Closest is T1557 Adversary-in-the-Middle, whose page does not mention BGP [14]. Reported as a gap. |
| `ns` path: forged DNS answers | T1557 against DNS; T1584.002 Compromise Infrastructure: DNS Server is the nearest fit |
| Obtain the certificate | T1588.004 Obtain Capabilities: Digital Certificates [13]; T1608.003 Stage Capabilities: Install Digital Certificate |
| Use it | T1557 (interception of users); T1659 Content Injection (the 2026 incident delivered a malicious update [9]) |

## 8. Output

Per domain, one line each in `data/out/domains.jsonl`, worst first (never in `report.json`, which stays free of
domain names). The top-level keys are the summary; `details` holds everything else:

```json
{
  "schema_version": 2,
  "domain": "example.rs", "score": 8.0, "severity": "High", "label": "ns-partial",
  "headline": "2 of 3 nameserver addresses forgeable: forged answers reach enough CA perspectives in 92% of hijacks (5 attempts each).",
  "fix": { "action": "sign the zone and publish the DS at the registrar (DNSSEC)", "owner": "dns-host",
           "score_after": 1.1, "severity_after": "Low" },
  "full_fix": null,
  "details": {
    "calculation": { "path": "ns", "p": 0.6667, "h": 1, "p_attempt": 0.4, "likelihood": 0.92, "complexity": 0.87,
                     "score": 8.0, "h_reasons": ["attacker must run a forged authoritative DNS server"], "...": "..." },
    "paths": [ "... every path, including blocked ones and what blocks them ..." ],
    "findings": [ { "id": "NS_CAPTURABLE", "kind": "exposure", "severity": "High",
                    "detail": "2 of 3 nameserver addresses forgeable", "evidence": ["..."], "refs": [6, 8, 12] } ],
    "fixes": [ "... every fix, re-scored ..." ],
    "vectors": { "cvss31": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N", "cvss31_base": 8.7,
                 "cvss40": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N" },
    "attack_techniques": [ { "id": "T1588.004", "name": "Obtain Capabilities: Digital Certificates" } ],
    "params": { "remote_perspectives": 4, "allowed_non_corroborations": 1, "attempts": 5, "contest_share": 0.3,
                "impact": 1.0, "complexity_step": 0.87 },
    "data_quality": { "complete": true, "errors": [] },
    "references": [ { "n": 6, "title": "CA/B Forum TLS Baseline Requirements 3.2.2.9 (MPIC)", "url": "..." } ]
  }
}
```

The `calculation` block lets any reader recompute the score by hand.

Findings (`kind`): exposure — `WEB_MORE_SPECIFIC`, `NS_CAPTURABLE`, `EXACT_PREFIX_CONTEST`, `NO_ROA`;
missing-defence — `NO_CAA`, `CAA_NO_ACCOUNTURI`, `UNSIGNED`, `DNSSEC_BOGUS`; hygiene — `ROA_TOO_PERMISSIVE`;
data — `DATA_INCOMPLETE`. An exposure finding carries the severity of the path it opens.

`report.json` (aggregate, no domain names, schema 2):

```json
{
  "schema_version": 2,
  "scope":    { "domains": 100, "tld": "ee", "resolver": "...", "rpki_date": "2026-10-31", "population": { "...": "zone file facts" } },
  "model":    { "formula": "design/formula.md", "score": "...", "scale": { "High": "7.0-8.9", "...": "..." }, "params": { "...": "..." } },
  "severity": { "Critical": { "band": "9.0-10.0", "domains": 36, "share": 0.36 }, "...": "..." },
  "summary":  { "severity": { "...": "..." }, "scored": 89, "mean_score": 4.6, "median_score": 1.1, "high_or_critical": 37 },
  "labels":   { "open-web": { "domains": 35, "meaning": "..." }, "...": "..." },
  "findings": { "UNSIGNED": 62, "...": "..." },
  "defences": { "dnssec_secure": 25, "dnssec_bogus": 0, "dnssec_unsigned": 75, "caa": 3, "caa_accounturi": 0 },
  "fixes":    { "first_fix": { "<action>": 30 }, "to_close": { "<actions>": 70 } },
  "by_ns_operator": [ { "operator": "zone.ee", "domains": 34, "severity": { "...": "..." }, "mean_score": 7.1,
                        "high_or_critical": 25, "signed": 22, "zone_delegations": 78223, "zone_ds": 50446 } ],
  "by_hosting_as":  [ { "asn": "24940", "name": "HETZNER-AS", "domains": 12, "severity": { "...": "..." },
                        "mean_score": 9.2, "high_or_critical": 11, "web_forgeable": 11 } ],
  "what_if":  [ { "scenario": "sign all zones", "overrides": { "signed": true }, "reads_as": "...",
                  "severity": { "...": "..." }, "mean_score": 4.1, "high_or_critical": 35 } ]
}
```

The numbers above are illustrative; see the generated file.

## 9. Results on the 100-domain sample (2026-10-31 data, computed by `risk.py`)

| Severity | Domains | Labels |
|---|---|---|
| Critical | 16 | 15 `open-web` (10.0), 1 `caa-bypassable` (10.0) |
| High | 5 | 3 `open-web` (8.7), 2 `open-dns` (7.6) |
| Medium | 0 | — |
| Low | 60 | 58 `contested` (1.1), 1 `ns-partial` (1.5), 1 `open-web` (1.8) |
| None | 0 | — |
| Unknown | 19 | 13 collection errors (see below), 6 with no web or nameserver address |

Medium is empty as a worst-path score because every partial capture that drives a score is about 1/3. Medium and
High partial captures do exist behind a worse web path: the fix re-scores show them (e.g. CAA alone takes a
Critical domain to 8.0 High because 2 of 3 nameserver addresses are capturable).

The 13 collection errors were a Windows file-name bug (IPv6 colons in RIPEstat cache file names), fixed in
`collect/ripestat.py`; re-collecting those domains with `--force` should score most of them.

## 10. Limitations

- **`q = 0.3` is assumed.** It sets the score of every `contested` domain. Replace with routing simulation or
  published measurements of equally-specific hijack reach.
- **Independent, uniform choice of nameserver per perspective.** Real resolvers prefer the fastest server
  (smoothed RTT), which makes capture closer to all-or-nothing per perspective; the true `P` may be higher or lower.
- **`N = 5` is assumed.**
- **`r` changes on 2026-12-15** (5 remote perspectives); scores of partial paths drop slightly.
- **Global propagation of a forgeable more-specific is assumed (p = 1).** Filtering reduced propagation slightly in
  the 2026 incident [9].
- **Impact is constant.** Domain sensitivity is not modelled yet (`I` hook).
- **ASPA is ignored.** An ASPA record (as Hetzner added after the incident [9]) would reduce `p` for some paths.
- **"No ROA" counts as forgeable at any prefix length** (inherited from `score.py`). For a /24 (IPv4) or /48 (IPv6)
  without a ROA, no routable more-specific exists; the attacker gets an exact-prefix contest that ROV never drops,
  not a guaranteed global win. Those domains may be over-scored; to be decided.

## 11. Implementation

| File | Role |
|---|---|
| `src/hijackscan/risk.py` | The formula: CVSS 3.1 base-score equations (so 0.87 is computed, not typed in), MPIC quorum, paths, findings, fix re-scoring, summary/details JSON. Every constant cites its reference number. |
| `src/hijackscan/report/risk_view.py` | Summary and details rendering for terminal and HTML. |
| `src/hijackscan/report/listing.py` | `hijackscan list`: filter and sort collected records, no network. |
| `src/hijackscan/report/browse.py` | `hijackscan browse <domains.jsonl>`: `domains.html`, one row per domain (summary), click for details; filters by severity, label, finding and name. `zone` writes it too. |
| `src/hijackscan/report/zone.py` | Adds the `risk` block to `report.json`, writes `domains.jsonl`, adds the severity section to `report.html`. |
| `src/hijackscan/report/domain.py` | Summary by default, `--details` for the rest; the HTML page folds the details. |

```bash
hijackscan blic.rs                                  # summary: score, severity, headline, fix first, to close
hijackscan blic.rs --details --html blic.html       # + calculation, paths, findings, vectors, ATT&CK, references
hijackscan list --severity High,Critical            # filter collected records (no network)
hijackscan list --label ns-partial --details
hijackscan list --finding NO_CAA,UNSIGNED --min-score 4 --json
hijackscan zone data/samples/dev100.txt --out data/out/   # report.json + report.html + domains.jsonl
```

Exit code of `hijackscan <domain>`: 0 None, 1 Low or Medium, 2 High or Critical, 3 Unknown.

The previous exposure classes (§1) are removed: `score.py` only derives facts, and `report.json`, `report.html` and
the per-domain output are built entirely from the risk model. `report.json` (schema 2) has `scope`, `model`
(formula, scale, parameters), `severity`, `summary`, `labels`, `findings`, `defences`, `fixes`, `by_ns_operator`,
`by_hosting_as` and `what_if`; every group carries severity counts and the mean score.

## References

1. FIRST. *Common Vulnerability Scoring System v3.1: Specification Document.* https://www.first.org/cvss/v3.1/specification-document
2. FIRST. *Common Vulnerability Scoring System v4.0: Specification Document.* https://www.first.org/cvss/v4.0/specification-document
3. P. Mell, K. Scarfone. *NIST IR 7502: The Common Configuration Scoring System (CCSS).* NIST, Dec 2010. https://csrc.nist.gov/pubs/ir/7502/final
4. Snyk. *Enhancing code to cloud security with the Common Configuration Scoring System.* https://snyk.io/blog/enhancing-code-to-cloud-security-common-configuration-scoring/
5. OWASP. *OWASP Risk Rating Methodology.* https://community.owasp.org/OWASP_Risk_Rating_Methodology
6. CA/Browser Forum. *Baseline Requirements for the Issuance and Management of Publicly-Trusted TLS Server Certificates*, §3.2.2.9 Multi-Perspective Issuance Corroboration. https://github.com/cabforum/servercert/blob/main/docs/BR.md
7. CA/Browser Forum. *Ballot SC-067v3: Require domain validation and CAA checks to be performed from multiple Network Perspectives.* Aug 2024. https://cabforum.org/2024/08/05/ballot-sc067v3-require-domain-validation-and-caa-checks-to-be-performed-from-multiple-network-perspectives-corroboration
8. H. Birge-Lee, Y. Sun, A. Edmundson, J. Rexford, P. Mittal. *Bamboozling Certificate Authorities with BGP.* USENIX Security 2018. https://www.usenix.org/conference/usenixsecurity18/presentation/birge-lee
9. APNIC Blog. *Latest BGP hijack targets hosting software vendor.* 22 Sep 2026. https://blog.apnic.net/2026/09/22/latest-bgp-hijack-targets-hosting-software-vendor/
10. Kentik. *Latest BGP hijack targets hosting software vendor.* https://kentik.com/blog/latest-bgp-hijack-targets-hosting-software-vendor
11. Ipregistry. *A 33-Hour BGP Hijack Passed RPKI, Fooled Let's Encrypt, and Shipped Malware.* https://ipregistry.co/blog/virtualizor-hetzner-bgp-hijack-rpki-valid
12. Y. Gilad, S. Goldberg, K. Sriram, J. Snijders, B. Maddison. *RFC 9319: The Use of maxLength in the RPKI.* https://www.rfc-editor.org/rfc/rfc9319
13. MITRE ATT&CK. *T1588.004 Obtain Capabilities: Digital Certificates.* https://attack.mitre.org/techniques/T1588/004
14. MITRE ATT&CK. *T1557 Adversary-in-the-Middle.* https://attack.mitre.org/techniques/T1557/
15. SwissSign. *MPIC validation (SC-067 / SMC-010) phase-in.* https://www.swisssign.com/en/blog/ca-browser-forum/mpic-validierung-sc067-smc010
18. IETF. *RFC 8659: DNS Certification Authority Authorization (CAA) Resource Record.* https://www.rfc-editor.org/rfc/rfc8659
19. IETF. *RFC 8657: CAA Record Extensions for Account URI and ACME Method Binding.* https://www.rfc-editor.org/rfc/rfc8657
