<div align="center">

# 🛡️ PhishBuster UK

### Open-source phishing detection & response automation for Microsoft 365, tuned to the UK threat landscape

[![CI](https://github.com/saranrocks007/phishbuster-uk/actions/workflows/ci.yml/badge.svg)](https://github.com/saranrocks007/phishbuster-uk/actions/workflows/ci.yml)
[![CodeQL](https://github.com/saranrocks007/phishbuster-uk/actions/workflows/codeql.yml/badge.svg)](https://github.com/saranrocks007/phishbuster-uk/actions/workflows/codeql.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-46%20passing-brightgreen.svg)](#)
[![Docker Ready](https://img.shields.io/badge/docker-ready-2496ED.svg?logo=docker&logoColor=white)](Dockerfile)

**[🌐 Live Demo](https://saranrocks007-phishbuster-uk.hf.space)** · **[📖 Documentation](docs/)** · **[🚀 Deploy](docs/LIVE_DEPLOY.md)** · **[🛡️ Threat Model](docs/THREAT_MODEL.md)**

</div>

---

## What it does, in one paragraph

PhishBuster UK is a **10-detector analysis pipeline** that classifies emails from a Microsoft 365 mailbox as benign / suspicious / phishing, then auto-quarantines, raises a ticket, alerts the SOC, exports IOCs in STIX 2.1 format, and optionally forwards confirmed phishing to NCSC's [Suspicious Email Reporting Service](https://www.ncsc.gov.uk/information/report-suspicious-emails). It's purpose-built for UK threat patterns — HMRC, Royal Mail, NHS, NatWest, Barclays, DVLA, TV Licensing impersonation — that generic global tools under-detect.

## Why this exists

> **84% of UK businesses** that suffered a cyber breach in 2023 cited phishing as the attack vector ([UK Government Cyber Security Breaches Survey 2024](https://www.gov.uk/government/statistics/cyber-security-breaches-survey-2024)).
> HMRC alone identified **~£47m** in losses to tax-themed phishing in 2022.

The UK attack surface is shaped by impersonation of a narrow set of brands. Generic global solutions are trained on US-dominated data and **under-detect UK-specific patterns**: HMRC tax-refund lures, Royal Mail £1.99 redelivery scams, NatWest "new payee added" alerts, NHS COVID-pass re-verification phish, council-tax direct-debit failures.

PhishBuster UK is purpose-built for this threat landscape. It ships with:

- A dedicated UK brand database (HMRC, Royal Mail, NHS, NatWest, Barclays, Lloyds, HSBC, Halifax, Santander, Monzo, DVLA, DWP, TV Licensing, British Gas, Octopus Energy, council tax, Companies House, Student Loans Company)
- UK-aware NCSC SERS auto-forwarding (`report@phishing.gov.uk`)
- Cyber Essentials Plus audit evidence packs
- UK-GDPR-aware logging (PII hashed at rest)
- SOC SLA bands aligned to UK incident response practice

---

## ⚡ Quick demo

```bash
# Local in 30 seconds
git clone https://github.com/saranrocks007/phishbuster-uk.git
cd phishbuster-uk
docker compose up -d dashboard
docker compose run --rm dashboard python scripts/seed_demo_data.py --count 80
open http://localhost:8080
```

Or just visit the **[live demo](https://saranrocks007-phishbuster-uk.hf.space)** — pre-seeded with 80 synthetic incidents across HMRC / Royal Mail / NatWest / DVLA / NHS impersonation patterns.

---

## 🧠 Detection pipeline — 10 detectors, all opt-in

| Detector | What it catches | Default |
|----------|----------------|---------|
| **Header forensics** | SPF / DKIM / DMARC / ARC failures, Reply-To anomalies, Return-Path mismatches | ✅ on |
| **URL analyser** | Homoglyph domains (Cyrillic→Latin fold), Levenshtein typosquats vs UK brand domains, high-risk TLDs (`.xyz`, `.click`, `.buzz`), URL shorteners, anchor-text mismatch, IP-in-URL | ✅ on |
| **UK lure detector** | Display-alias spoofing + From-domain legitimacy check, brand keyword density, urgency language, credential-form detection, suspicious phrases | ✅ on |
| **NLP classifier** | TF-IDF (word 1-2grams + char_wb 3-5grams) → Logistic Regression, bootstrappable from public corpora (Nazario, SpamAssassin) | ✅ on |
| **Quishing detector** | QR codes in inline images / PDF attachments → URL extraction → suspicion scoring | ✅ on |
| **AI-content heuristic** | 8-feature statistical ensemble: boilerplate density, sentence burstiness, type-token ratio, hedge density, US-English-in-UK-context | ✅ on |
| **🆕 Threat intelligence** | Multi-vendor lookups: VirusTotal v3, AbuseIPDB v2, URLhaus, PhishTank — SQLite-cached, fail-open, quota-respecting | ⚙️ opt-in |
| **🆕 Domain age** | python-whois lookup with 30-day cache; flags domains registered ≤ N days ago | ✅ on |
| **🆕 URL sandbox** | Direct fetch (no JS) for credential-form detection + UK-brand asset theft + redirect-chain analysis. Optional urlscan.io integration | ⚙️ opt-in |
| **🆕 Attachment scanner** | YARA rules (UK-themed starter set), Office VBA macro + auto-execute hook detection, PDF JavaScript detection, optional ClamAV | ✅ on |
| **🆕 BEC sender anomaly** | Per-sender baseline: hour histogram, recipient set, vocabulary cosine similarity. Catches "CEO suddenly emails finance from new device" | ✅ on |

Each detector contributes a weighted score (0.0–1.0). Aggregated total bands into:

| Score | Verdict | Default action |
|-------|---------|---------------|
| ≥ 0.65 | **PHISHING** | Quarantine + ticket + alert + NCSC forward |
| 0.35–0.65 | **SUSPICIOUS** | Ticket for analyst review |
| < 0.35 | **BENIGN** | Log only |

Severity (CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL) maps to SLA windows (15m / 1h / 4h / 8h / 24h).

---

## 📊 SOC dashboard

The bundled FastAPI + Chart.js dashboard surfaces:

- **MTTD** — Mean Time To Detect
- **MTTR** — Mean Time To Respond
- **Dwell time** — oldest unresponded phishing incident
- **FP rate** — analyst-flagged false positives
- **SLA adherence** — % of incidents responded within severity window
- **UK brand impersonation heatmap** — HMRC, Royal Mail, NHS, banks frequency
- **Detector yield** — which rules are earning their weight
- **MITRE ATT&CK coverage** — techniques observed over time
- **IOC velocity** — hourly emission rate by indicator type

Drill-down per incident shows all findings, IOCs, MITRE techniques, and an analyst FP-toggle.

**[See the live dashboard](https://saranrocks007-phishbuster-uk.hf.space)** with seeded synthetic data.

---

## 🇬🇧 UK-specific innovations (beyond generic phishing detection)

1. **NCSC SERS bridge** — optional automatic forwarding of confirmed phishing to `report@phishing.gov.uk`. Contributes to a national takedown layer that benefits everyone.
2. **Action Fraud alignment** — incident records include the fields Action Fraud expects in bulk reports.
3. **Cyber Essentials Plus evidence packs** — STIX 2.1 IOC bundles + JSON + CSV serve as auditor-ready evidence of operating phishing controls.
4. **UK-GDPR-aware logging** — email addresses and message-IDs SHA-256 hashed at rest; configurable retention.
5. **Council-tax + energy-bill lure pack** — categories commonly missed by US-centric detectors.
6. **Quishing focus** — UK saw a sharp rise in QR-code phishing around parking meters and Royal Mail "missed delivery" cards. Pipeline handles QR extraction from PNG/JPEG/PDF.
7. **AiTM indicator detection** — flags reverse-proxy phish kits (Evilginx, EvilnoVNC patterns) via URL structure heuristics.

---

## 🎯 MITRE ATT&CK coverage

| Technique | Name | Example trigger |
|-----------|------|-----------------|
| `T1566.001` | Spearphishing Attachment | Suspicious attachment + auth failures |
| `T1566.002` | Spearphishing Link | Malicious URL indicators |
| `T1566.003` | Spearphishing via Service | Service-spoofing patterns |
| `T1598.003` | Spearphishing for Information | Credential-harvesting form detected |
| `T1656`     | Impersonation | UK brand display-name spoofing |
| `T1204.002` | Malicious File (User Execution) | YARA-malicious / VirusTotal-flagged file / auto-exec macro |
| `T1534`     | Internal Spearphishing / BEC | Sender first-seen + finance keywords + style shift |

---

## 🚀 Get started

### Local install (Python)

```bash
git clone https://github.com/saranrocks007/phishbuster-uk.git
cd phishbuster-uk

python -m venv .venv && source .venv/bin/activate    # Linux/Mac
# or:  .venv\Scripts\activate                          # Windows

pip install -r requirements.txt

cp .env.example .env       # then edit with your settings
python scripts/setup_db.py
python scripts/train_model.py

# Try a sample
python -m src.main --scan-file tests/samples/hmrc_refund.eml
# → PHISHING / CRITICAL · score 1.00 · brand=HMRC · MITRE T1566.002 + T1656

# Seed demo data + launch dashboard
python scripts/seed_demo_data.py --count 80 --days 14
python -m src.dashboard.app
# → http://localhost:8080
```

### Docker

```bash
docker compose up -d
docker compose run --rm dashboard python scripts/seed_demo_data.py
```

### Live URL deployment

See **[`docs/LIVE_DEPLOY.md`](docs/LIVE_DEPLOY.md)** for step-by-step guides on:

- **Hugging Face Spaces** (recommended — free, no card, persistent storage)
- **Fly.io** (free hobby tier, London region)
- **Render.com** (free Docker hosting)
- **Oracle Cloud Free Tier** (always-on VM)
- **Cloudflare Tunnel** (instant URL from your laptop)

The repo includes a working `fly.toml` and a GitHub Actions deploy workflow.

---

## 🏗️ Architecture

```
                    ┌──────────────────────────────────────┐
                    │   Microsoft 365 mailbox (Graph API)  │
                    └──────────────────┬───────────────────┘
                                       ▼
                ┌──────────────────────────────────────┐
                │    Ingestion (RFC 822 + Graph JSON)  │
                └──────────────────┬───────────────────┘
                                   ▼
       ┌───────────────────────────────────────────────────────┐
       │           AnalysisEngine (10 detectors)               │
       │   ──────────────────────────────────────────────      │
       │   header  url  uk-lure  nlp  quishing  ai-content     │
       │   threat-intel  domain-age  sandbox  attachment  bec  │
       └───────────────────────────────┬───────────────────────┘
                                       ▼
                       ┌──────────────────────────┐
                       │   AnalysisReport         │
                       │   (verdict + score +     │
                       │    findings + IOCs +     │
                       │    MITRE techniques)     │
                       └────────┬─────────────────┘
                                ▼
        ┌────────────┬──────────┴─────────┬──────────────┐
        ▼            ▼                    ▼              ▼
   Quarantine   Ticketing             Alerters      NCSC SERS
   (Graph       (Jira/                (Slack/       forwarder
    move)        ServiceNow)           Teams)
                                                    │
                                                    ▼
                              ┌─────────────────────────────┐
                              │   Persistence + Dashboard   │
                              │   (SQLAlchemy + FastAPI)    │
                              └─────────────────────────────┘
```

Full architecture: **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**

---

## 🛡️ Is it safe?

**Short answer: yes for personal labs, SOC review queues, and SME defensive deployments. With caveats for paid commercial use.**

PhishBuster UK is:

- ✅ Apache 2.0 licensed — every line auditable, no obfuscation
- ✅ No telemetry, no phone-home, no data exfiltration
- ✅ All optional integrations off by default
- ✅ Email content processed in-memory; only hashed metadata persisted
- ✅ Runs as non-root in Docker
- ✅ Scanned weekly by GitHub CodeQL
- ✅ 46-test suite covering the analysis pipeline
- ✅ Honest, public threat model

But also:

- ⚠️ Solo-developer software — not third-party pentested
- ⚠️ Dashboard has no built-in auth (operator must add nginx basic auth / Cloudflare Access)
- ⚠️ URL sandbox visits attacker-controlled URLs (off by default; documented)
- ⚠️ Threat intel integrations leak indicators to vendors (off by default; documented)
- ⚠️ No SOC 2 / ISO 27001 / Cyber Essentials Plus vendor certification

**Read the full threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)** — it documents every known limitation, mitigation, and recommended deployment posture.

---

## 👥 Who is this for?

| Audience | Use case |
|----------|---------|
| **UK MSPs serving SMEs (10–250 staff)** | Deploy as a phishing-detection layer for clients on M365. Charge for setup + monitoring. |
| **Internal IT teams at UK SMEs** | Cyber Essentials Plus audit evidence + detection beyond M365 defaults. |
| **UK charities / education / public sector (small)** | Free defensive layer where commercial alternatives are unaffordable. |
| **SOC analysts** | Triage queue review tool with explainable verdicts and FP-feedback loop. |
| **Detection engineers** | Reference implementation of multi-detector phishing analysis with BEC sender baselining. |
| **Cybersecurity students** | Hands-on lab for SOC fundamentals + detection engineering. |

It is **not** a replacement for Microsoft Defender for Office 365, Mimecast, or Proofpoint — it complements them.

---

## 🤝 Contributing

Contributions welcome. See **[`CONTRIBUTING.md`](CONTRIBUTING.md)** for the dev setup, PR checklist, and a recipe for adding new detectors.

Good first issues are tagged on the [issue tracker](https://github.com/saranrocks007/phishbuster-uk/issues?q=is:issue+is:open+label:%22good+first+issue%22). Areas that always need help:

- Additional UK brands in `config/uk_brands.yaml`
- New YARA rules for emerging UK campaign patterns
- Threat-intel vendor integrations (CIRCL Hashlookup, MalwareBazaar, AlienVault OTX)
- Ticketing backends (Zendesk, Freshdesk, Linear)
- Documentation translations / runbook scenarios

---

## 🔐 Security

For vulnerability disclosure, see **[`SECURITY.md`](SECURITY.md)**. Don't open public issues for security bugs — use the private email or GitHub Security Advisories.

---

## 📜 License

Apache License 2.0 — free for personal and commercial use. See **[`LICENSE`](LICENSE)** for the full text.

---

## 🙋 About

Built by **[Saran Sengottuvel](https://saransengottuvelportfolio.vercel.app)** ([@saranrocks007](https://github.com/saranrocks007)) — CEH-certified cybersecurity analyst and bug bounty hunter with **European Central Bank** and **ORF (Austrian Broadcasting)** Hall-of-Fame credentials.

Designed as a portfolio-grade demonstration of UK detection engineering and a credible foundation for production deployment by UK SMEs.

If you found this useful, a ⭐ on the repo helps others discover it.

---

<div align="center">

**[🌐 Live Demo](https://saranrocks007-phishbuster-uk.hf.space)** · **[📖 Docs](docs/)** · **[🐙 GitHub](https://github.com/saranrocks007/phishbuster-uk)** · **[💼 Portfolio](https://saransengottuvelportfolio.vercel.app)**

Made with ☕ in Tamil Nadu · Aiming for Amsterdam 🇳🇱 / Dublin 🇮🇪

</div>
