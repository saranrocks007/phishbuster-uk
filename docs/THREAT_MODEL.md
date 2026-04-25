# Threat Model — PhishBuster UK

> Honest, public documentation of what this project does well, where it has security limitations, and how to deploy it safely.

This document exists because security tools should be transparent about their own attack surface. If you're considering deploying PhishBuster UK, read this first. If you're auditing the codebase, this tells you where to look hardest.

**Last reviewed:** April 2026
**Maintainer:** Saran Sengottuvel ([@saranrocks007](https://github.com/saranrocks007))

---

## 1 · Scope and design intent

PhishBuster UK is a **defensive complement** to Microsoft 365's built-in email security, tuned to UK threat patterns. It is explicitly NOT:

- A replacement for Microsoft Defender for Office 365, Mimecast, or Proofpoint
- A real-time inline blocker (it processes mail post-delivery from a quarantine/triage mailbox)
- A certified product (no SOC 2, ISO 27001, or Cyber Essentials Plus vendor certification)
- Suitable for regulated industries (healthcare, banking, government) without significant additional hardening

It IS:

- An auditable, open-source detection pipeline for UK SMEs and MSPs
- A SOC analyst review tool that complements existing email security
- A learning platform for detection engineering
- A reference implementation of multi-detector phishing analysis

If your use case falls outside the "IS" list, this tool may still be useful but the threat model below applies.

---

## 2 · Threat actors considered

| Actor | Capability | In scope? |
|-------|-----------|-----------|
| Opportunistic phishing operator | Mass-mailing UK brand impersonations | ✅ Primary target |
| Quishing campaign operator | Royal Mail / parking-meter QR scams | ✅ Primary target |
| BEC actor | Targeted finance-team impersonation | ✅ Secondary target |
| Nation-state spearphishing | Highly targeted, OpSec-aware | ⚠️ Partial — header forensics catch some, but novel zero-day phish kits will evade |
| Insider threat | Authenticated user attempting data exfil via email | ❌ Out of scope — different problem space |
| Attacker against PhishBuster itself | Compromising the scanner to access mail | ⚠️ Considered — mitigations below |

---

## 3 · Trust boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  Untrusted: incoming email content, URLs, attachments       │
│  ───────────────────────────────────────────────────────    │
│   • Treated as adversarial input throughout the pipeline    │
│   • Parsed in memory; never executed                        │
│   • Bytes capped (200KB HTML, 500KB PDF head)              │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  Semi-trusted: M365 Graph API responses                     │
│  ───────────────────────────────────────────────────────    │
│   • Auth tokens isolated to scanner process                 │
│   • Application Access Policy scopes to single mailbox     │
│   • Rate limits respected via backoff                       │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  Semi-trusted: third-party threat intel APIs                │
│  ───────────────────────────────────────────────────────    │
│   • VirusTotal / AbuseIPDB / URLhaus / PhishTank            │
│   • Lookups send IOCs (URLs, domains, IPs) outward         │
│   • SQLite-cached to minimise outbound traffic              │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  Trusted: SQLite/Postgres database                          │
│  ───────────────────────────────────────────────────────    │
│   • Stores incident metadata, IOCs, sender baselines        │
│   • Body content NOT stored — only hashes + summaries       │
│   • Filesystem permissions enforced via Docker non-root     │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  Operator-trusted: dashboard                                │
│  ───────────────────────────────────────────────────────    │
│   • Read-only view of incidents + KPIs                      │
│   • No built-in auth — operator must add nginx/CF Access    │
│   • Single mutating endpoint: POST /api/incidents/{id}/fp   │
└─────────────────────────────────────────────────────────────┘
```

---

## 4 · Known risks and mitigations

### 4.1 · No authentication on the dashboard

**Risk:** The dashboard ships with no built-in login. Anyone who reaches the URL sees all incident data, sender names, subjects, IOCs, and BEC baselines. This is sensitive — it's effectively a SOC dashboard.

**Severity:** HIGH if exposed to public internet without protection.

**Mitigations:**
- Default `DASHBOARD_HOST=127.0.0.1` would prevent external exposure (currently `0.0.0.0` — see issue: should we change the default?)
- `docs/LIVE_DEPLOY.md` documents three auth options: nginx basic auth, Cloudflare Access, Tailscale Funnel
- Public demo deployments should ONLY contain seeded synthetic data (look for `[DEMO]` prefix in summaries)

**Status:** Documented but not enforced. Operators must read the docs.

**Roadmap:** v1.1 will ship optional OAuth2 / OIDC integration via `fastapi-users`.

### 4.2 · URL sandbox visits attacker-controlled URLs

**Risk:** When `ENABLE_URL_SANDBOX=true`, the scanner visits URLs from incoming emails. This:
- Reveals the scanner's IP to attackers
- Could trigger drive-by exploits if the HTML parser has a vulnerability
- If deployed on a corporate network without egress controls, routes hostile traffic from inside the perimeter

**Severity:** MEDIUM — attacker-controlled HTML is downloaded but never executed (no JavaScript engine).

**Mitigations:**
- Off by default
- Hard timeout (8s default), capped redirects (4 default)
- HTML size capped at 200KB
- Uses httpx with no JavaScript runtime
- Documented in `.env.example` with explicit warning
- Recommended deployment: route through a forward proxy / dedicated NAT IP / urlscan.io API instead

**Operator action required:** before enabling, ensure scanner egress is isolated.

### 4.3 · Threat intel integrations leak indicators externally

**Risk:** Enabling VirusTotal lookups sends URL/domain/file-hash data to a Google subsidiary. AbuseIPDB sees IP queries. This is normal threat intel use, but for some operators (UK government, NHS, regulated finance) it may violate data sharing policies.

**Severity:** LOW for most users, MEDIUM for regulated sectors.

**Mitigations:**
- All TI integrations off by default (`ENABLE_THREAT_INTEL=false`)
- Each vendor configurable independently
- `THREAT_INTEL_CACHE_TTL_HOURS` (default 24) minimises repeat queries
- Documentation explicitly lists vendors used
- URLhaus and PhishTank are non-commercial / abuse.ch based, lower-privacy concern than VirusTotal

**Operator action required:** review each vendor's privacy policy before enabling.

### 4.4 · SQLite database is single-point-of-failure

**Risk:** Default SQLite deployment has no replication. Volume corruption or accidental deletion loses all incident history and BEC baselines.

**Severity:** LOW — affects historical analytics only, not real-time detection.

**Mitigations:**
- `DATABASE_URL` accepts Postgres for production deployments
- Docker volume separates data from container lifecycle
- WAL journaling enabled
- Documented in `docs/DEPLOYMENT.md`

### 4.5 · BEC baselines update only on benign verdicts

**Design choice (not a vulnerability):** Sender baselines update only when a message is classified BENIGN. This prevents an attacker from poisoning their own baseline by sending malicious mail.

**Tradeoff:** New legitimate senders show up as `sender_first_seen` finding (weight 0.15) for their first 5 messages — minor false-positive contribution, well below the 0.35 SUSPICIOUS threshold.

### 4.6 · NLP classifier trained on small corpus

**Risk:** Out-of-the-box, the classifier is trained on ~60 hand-curated UK lure samples. This is a starting point, not a production-grade model. False positives and missed novel phish styles are expected.

**Severity:** Operational, not security.

**Mitigations:**
- `scripts/import_corpus.py` bootstraps from public corpora (Nazario, SpamAssassin)
- Classifier is one signal among ten; doesn't dominate the score
- 5-fold CV F1 reported on every retrain
- Recommended workflow: retrain monthly with confirmed phish + ham from your SOC queue

### 4.7 · Container is not signed or attested

**Risk:** Docker image is built from an unsigned `python:3.12-slim` base. No SBOM, no Sigstore attestation, no Notary signing.

**Severity:** LOW for portfolio / hobbyist use, MEDIUM for paid commercial deployments.

**Mitigations:**
- `apt` packages pinned via `--no-install-recommends`
- Pip dependencies pinned to specific versions in `requirements.txt`
- Runs as non-root user (UID 1001)
- Filesystem mounted read-only except `/app/data`
- CodeQL scans codebase weekly via GitHub Actions

**Roadmap:** v1.1 will publish signed images via Sigstore cosign on GitHub releases.

### 4.8 · No protection against compromised dependencies

**Risk:** A malicious update to any dependency (e.g. `pyzbar`, `tldextract`) could compromise the scanner.

**Severity:** This is a universal Python ecosystem risk, not specific to PhishBuster.

**Mitigations:**
- All dependencies version-pinned
- Dependabot enabled on the GitHub repo (PRs for security updates)
- CodeQL scans for known vulnerable patterns
- No use of arbitrary code execution (`eval`, `pickle.loads` on untrusted data, etc.)

### 4.9 · M365 service principal credentials

**Risk:** The scanner needs Graph API credentials with `Mail.ReadWrite` and (optionally) `Mail.Send` permissions. If the credentials leak, an attacker has full mailbox access.

**Severity:** HIGH if leaked — they're the keys to the kingdom.

**Mitigations:**
- Stored as environment variables, never logged
- `.env` is in `.gitignore` and `.dockerignore`
- Recommend Application Access Policy to scope to a single mailbox
- Documented credential rotation procedure in `docs/RUNBOOK.md`
- Recommend Azure Key Vault / AWS Secrets Manager / Doppler for production

**Operator action required:** rotate credentials on a schedule, scope to minimum mailbox set.

### 4.10 · Demo data on public deployments

**Risk:** Operators may forget to wipe `[DEMO]` rows when transitioning to production, causing real metrics to be polluted with fake data.

**Severity:** Operational, not security.

**Mitigations:**
- All seeded rows tagged `[DEMO]` in summary field
- `python scripts/seed_demo_data.py --reset` wipes them
- Documented in `docs/LIVE_DEPLOY.md`

---

## 5 · What we explicitly do NOT defend against

Being honest about scope:

- **Phishing kits using legitimate auth services** (e.g. Microsoft AiTM via genuine Azure tenants) — partially detected via heuristics but not reliably
- **Encrypted attachment payloads** (password-protected ZIPs) — we can detect the encryption but not the contents
- **Polymorphic payloads** that change content per recipient — we score per-message, not across campaigns
- **Voice-message phishing (vishing) referenced in email** — we don't transcribe audio
- **Mobile-only display attacks** (e.g. sender name truncation on small screens) — out of scope for an email-server-side tool
- **Insider abuse of the dashboard** — anyone with dashboard access can see all incidents
- **DDoS against the scanner** — no rate limiting on Graph polling

---

## 6 · Vulnerability disclosure

**Don't open public GitHub issues for security vulnerabilities.**

Email: `saran.sengottuvel.security [at] gmail.com`

Or use private GitHub Security Advisories: https://github.com/saranrocks007/phishbuster-uk/security/advisories/new

See `SECURITY.md` for the full disclosure policy.

---

## 7 · Recommended deployment posture by use case

### 7.1 · Personal lab / learning environment

```bash
# Acceptable defaults — local-only, no internet exposure
DASHBOARD_HOST=127.0.0.1
ENABLE_THREAT_INTEL=false
ENABLE_URL_SANDBOX=false
ENABLE_DOMAIN_AGE_CHECK=true
ENABLE_BEC_DETECTOR=true
```

### 7.2 · Small UK SME (10–50 staff), MSP-managed

```bash
# Behind nginx with basic auth or Cloudflare Access
DASHBOARD_HOST=0.0.0.0
ENABLE_THREAT_INTEL=true            # add VT free tier API key
ENABLE_URL_SANDBOX=false            # leave off until egress isolated
ENABLE_DOMAIN_AGE_CHECK=true
ENABLE_BEC_DETECTOR=true
ENABLE_NCSC_SERS_FORWARDING=true    # contribute to NCSC takedowns
```

Plus: TLS via Let's Encrypt, weekly DB backups, monthly classifier retrain.

### 7.3 · Public portfolio demo (your case)

```bash
# Synthetic data only; auth optional
DASHBOARD_HOST=0.0.0.0
ENABLE_THREAT_INTEL=false           # no real mail to enrich
ENABLE_URL_SANDBOX=false            # no real URLs to visit
ENABLE_DOMAIN_AGE_CHECK=false       # avoids hammering WHOIS
ENABLE_BEC_DETECTOR=true
M365_*=disabled                      # no real mailbox connection
```

Run `scripts/seed_demo_data.py` on first deploy.

### 7.4 · Production paid deployment (NOT yet recommended)

Before deploying for paying customers, you should:

1. Commission a third-party penetration test (£500–1500 via freelance platforms)
2. Add OAuth2 / OIDC authentication to the dashboard
3. Obtain professional indemnity insurance (£300–600/year UK solo consultant)
4. Sign a Data Processing Agreement with the customer
5. Optionally: get Cyber Essentials Plus certification yourself (~£1500)
6. Set up PagerDuty / Opsgenie for incident response
7. Establish a 24/7 contact channel with customers

These steps protect both you and your customers and are standard for commercial security software.

---

## 8 · Audit trail

This threat model will be revised whenever:

- A new detector is added (re-evaluate trust boundaries)
- A new third-party integration is added (privacy implications)
- A vulnerability is disclosed and fixed (document in changelog)
- A major version is released

Revision history will appear at the bottom of this file.

### Revisions

| Date | Author | Change |
|------|--------|--------|
| 2026-04-25 | rogermax | Initial threat model published |
