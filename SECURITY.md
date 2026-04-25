# Security Policy

PhishBuster UK is built by a CEH-certified security professional with bug-bounty experience (ECB, ORF Hall of Fame). Vulnerability reports are taken seriously and handled responsibly.

## Reporting a vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Email: **saran.sengottuvel.security [at] gmail.com** with:

- A clear description of the vulnerability
- Steps to reproduce or proof-of-concept code
- Affected version / commit SHA
- (Optional) suggested mitigation

You can also use GitHub Security Advisories (private): https://github.com/saranrocks007/phishbuster-uk/security/advisories/new

## What to expect

| Step | Time |
|------|------|
| Initial acknowledgement | within 48 hours |
| Triage & severity classification | within 5 working days |
| Fix / mitigation timeline | within 30 days for high/critical, 90 days otherwise |
| Public disclosure | coordinated; credit given (unless you'd rather stay anonymous) |

## Scope

In scope:
- Authentication / authorisation issues in the dashboard
- SQL injection, XSS, SSRF, RCE in the codebase
- Issues with the M365 Graph integration that could expose tenant data
- Issues with the URL sandbox that could result in attacker-controlled traffic from your infrastructure
- Container escape / privilege escalation in the Docker image
- Secrets being logged or leaked

Out of scope:
- Issues caused by user misconfiguration (e.g. setting `ENABLE_URL_SANDBOX=true` on a public-facing scanner without proper egress controls — this is documented in `docs/UPGRADE_V2.md`)
- Issues in third-party dependencies (please report those upstream)
- Self-XSS, clickjacking on pages without sensitive actions
- Theoretical issues without a working PoC

## Hall of fame

Researchers who responsibly disclose are credited here unless they request anonymity:

_(none yet — be the first)_
