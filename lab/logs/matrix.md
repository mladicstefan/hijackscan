| scenario | attack | data plane | scanner | evidence | CA → attacker | HTTP-01 hosts | CA → legit (attack off) | expected | ok |
|---|---|---|---|---|---|---|---|---|---|
| baseline | web | web=attacker ns=victim | open-web (CRITICAL 10.0) | complete | ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker | primary=attacker r1=attacker r2=attacker r3=victim r4=attacker | ISSUED | open-web / ISSUED | yes |
| tight-maxlength | web | web=victim ns=victim | contested (LOW 1.1) | complete | REFUSED: domain control not demonstrated | primary=victim r1=victim r2=attacker r3=victim r4=victim | ISSUED | contested / REFUSED | yes |
| caa-unsigned | web | web=attacker ns=victim | caa-erasable (HIGH 8.7) | complete | REFUSED: CAA forbids this issuance (accounturi pins https://ca.lab/acct/legit) | - | ISSUED | caa-erasable / REFUSED | yes |
| caa-unsigned | web+ns | web=attacker ns=attacker | caa-erasable (HIGH 8.7) | complete | ISSUED: certificate for victim.rs to https://ca.lab/acct/attacker | primary=attacker r1=attacker r2=attacker r3=victim r4=attacker | ISSUED | caa-erasable / ISSUED | yes |
| caa-signed | web+ns | web=attacker ns=attacker | closed (NONE 0.0) | complete | REFUSED: DNSSEC validation failed (reachable but bogus) | - | ISSUED | closed / REFUSED | yes |
