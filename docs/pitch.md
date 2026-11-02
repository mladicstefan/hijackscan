# hijackscan: pitch deck source

Two-minute pitch, seven slides. The three-minute live demo (`uv run demo`) carries the results. One `##` per
slide; bullets are speaker-ready.

---

## 1. Title

**hijackscan**
How exposed is a ccTLD namespace to certificate theft through BGP hijacks below DNS, and how much do DNSSEC + CAA close?

team dogma, DNS SEC Hackathon 2026
github.com/mladicstefan/hijackscan

---

## 2. Problem: BGP hijacks steal certificates, not DNS

- A certificate authority proves you own a domain by connecting to your server (HTTP-01) or reading a DNS record (DNS-01).
- BGP decides where those packets go. Whoever announces the longest matching prefix receives them.
- An attacker who hijacks your prefix answers the CA's check and walks away with a valid certificate for your name.
- DNS was never touched. Every answer was correct. The route was not.

---

## 3. Attacks: this is not theory

| when | victim | how | result |
|---|---|---|---|
| 28 Aug 2026 | Hetzner / Virtualizor | forged-origin /24 inside Hetzner's /16, RPKI **valid** (ROA maxLength 24) | Let's Encrypt cert for 26 names, malicious hypervisor update, 33 hours |
| 17 Aug 2022 | Celer Bridge (AWS) | forged Amazon origin inside a maxLength-24 ROA, RPKI valid | GoGetSSL cert in 3 minutes, 235 000 USD stolen |
| 3 Feb 2022 | KLAYswap / Kakao SDK | more-specifics of unsigned space | ZeroSSL cert, tampered JS, 1.9 M USD |
| 24 Apr 2018 | MyEtherWallet / Route 53 | more-specifics of nameserver space, no ROA | self-signed cert, 150 000 USD |

Links:
- Hetzner: https://kentik.com/blog/latest-bgp-hijack-targets-hosting-software-vendor
- Hetzner: https://blog.apnic.net/2026/09/22/latest-bgp-hijack-targets-hosting-software-vendor/
- Hetzner: https://ipregistry.co/blog/virtualizor-hetzner-bgp-hijack-rpki-valid
- Celer: https://www.coinbase.com/blog/celer-bridge-incident-analysis
- KLAYswap: https://medium.com/s2wblog/post-mortem-of-klayswap-incident-through-bgp-hijacking-en-3ed7e33de600
- MyEtherWallet: https://blog.cloudflare.com/bgp-leaks-and-crypto-currencies/
- Academic root: Birge-Lee et al., Bamboozling Certificate Authorities with BGP, USENIX Security 2018, https://www.usenix.org/conference/usenixsecurity18/presentation/birge-lee

---

## 4. The defence lives in DNS, and it needs both halves

| defence alone | what the attacker does | outcome |
|---|---|---|
| nothing | hijack the web prefix, pass HTTP-01 | certificate issued |
| DNSSEC only | same: the A record is genuine, only the route is forged | certificate issued |
| CAA only (`issue "letsencrypt.org"`) | opens their own Let's Encrypt account | certificate issued |
| CAA with `accounturi` only | hijacks the nameserver prefixes too, answers "no CAA record" | certificate issued |
| **CAA `accounturi` in a DNSSEC-signed zone** | the forged "no CAA" fails validation; the CA must validate DNSSEC since 15 Mar 2026 (SC-085v2) | **refused** |

- RFC 8657 `accounturi` pins issuance to one ACME account.
- CA/B Forum MPIC (SC-067): CAs check from 4 remote perspectives since 15 Jun 2026, 5 from 15 Dec 2026, at most one may disagree. A global hijack fools all of them.

---

## 5. What hijackscan does

- **Scans a TLD**: samples a zone (the full .ee zone file, a .rs top list), collects DNS, routing and RPKI facts, scores every domain 0 to 10 on the CVSS scale, and names the one fix that helps most and who owns it.
- **Replays the four incidents** against the ROAs of their day.
- **Proves every verdict in a sealed lab** where a real CA tries to issue to a real hijacker.
- Data: RIPE NCC RPKI archive (every ROA, any day), RIPEstat, Quad9 over DoT, .ee AXFR. Public, read-only, rate-limited. Hijacks only inside the lab.

---

## 6. Threat model and score: one formula, three paths

**Attacker**: anyone who can announce BGP routes. **Goal**: a publicly trusted certificate for your name.
**CA assumed**: CA/B BR 3.2.2.9, primary plus 4 remote perspectives, at most 1 may disagree; validates DNSSEC on CAA and DCV lookups. **Attempts**: 5 per hijack.

| path | how | blocked by | not blocked by |
|---|---|---|---|
| web | RPKI-valid more-specific of the web prefix, answer HTTP-01 | CAA `accounturi` | DNSSEC; CAA without accounturi |
| ns | capture nameserver prefixes, forge DNS-01 or "no CAA" | DNSSEC | CAA, even with accounturi: the forged answer erases it |
| contest | exact prefix with forged origin, wins only where preferred | as web / as ns per side | always possible without ASPA |

```
Score = 10 × max over paths ( open × K × L )
P = p × Σ_{k=r−f}^{r} C(r,k) p^k (1−p)^(r−k)      the MPIC quorum is fooled in one attempt
L = 1 − (1 − P)^N                                  at least one of N = 5 attempts succeeds
K = 0.87^h                                         CVSS 3.1 AC:H / AC:L per hard step
```

- p = share of the path's addresses the attacker can capture; r = 4, f = 1 from the CA/B table; 0.87 from CVSS 3.1.
- Severity is the CVSS scale (None, Low, Medium, High, Critical) and reads as the adjusted chance of success.
- The label names the path that produced the score: open-web 10.0, caa-erasable 8.7, ns-partial 1.5 to 8.7, contested 1.1, closed 0.0.
- The same function with overrides gives "fix first" and "to close", each with an owner: domain owner, DNS host, registrar, hosting provider.

Speaker line: "Every constant comes from a published document except two, and we say which two."

---

## 7. The lab: the whole attack chain, for real, in a box

- **The problem**: a score is a claim. No public dataset shows what a CA would do under a hijack. So we built the Internet in miniature and ran the attack.
- **Ten containers**: five FRR routers (two doing Route Origin Validation from a StayRTR cache), a validating Unbound with its own root, NSD and a web server on the victim and on the attacker, and a CA that does CAA with `accounturi`, HTTP-01 from a primary plus four remote perspectives on separate links, and the MPIC quorum in force today.
- **The attack**: the attacker router announces a more-specific of the victim with the victim's AS forged as origin. Exactly the Hetzner route, scaled to RFC 5737 space.
- **The unmodified scanner** scans the victim through the lab's resolver and a routing feed served from the lab's own BGP table, then the CA tries to issue to the attacker. Scanner label must predict CA decision in every row of a five-row matrix. Four negative controls remove one mechanism each (the validator, ROV, the attacker's address, the ROA day) and the verdict must flip and come back.
- **Sealed**: RFC 5737 addresses, private ASNs, no NAT, default routes deleted, a containment check that fails the run on any violation. Images pinned by digest, signatures with a fixed window, a manifest per run. Signed zones, DS in a lab `rs`, a lab root trust anchor.
- **What it cost**: five router configs, two DNSSEC chains, a CA written from the RFCs, a RIPEstat emulator, bounded polling of three planes (BGP table, data plane, resolver cache) so no row ever passes on luck. It was most of the project's engineering time and it is the reason the numbers in the demo can be trusted.

Speaker line: "The scanner never saw the lab's answers. It predicted them."

