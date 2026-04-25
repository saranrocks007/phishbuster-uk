# Architecture — PhishBuster UK

> AI-augmented phishing detection & response automation for Microsoft 365, tuned to the UK threat landscape.

---

## 1 · Design goals

| # | Goal | How it lands |
|---|------|-------------|
| 1 | Catch UK-specific phish that generic M365 filters miss | Dedicated UK brand impersonation detector (HMRC / Royal Mail / NHS / NatWest / DVLA / TV Licensing / DWP / Big-6 banks / Octopus & British Gas) with per-brand severity weights |
| 2 | Give SOC analysts explainable decisions | Every verdict carries a list of `DetectionFinding` objects (detector + rule + weight + detail) and classifier top-tokens |
| 3 | Bridge into NCSC ecosystem | Auto-forward confirmed phishing to `report@phishing.gov.uk` (NCSC SERS) when enabled |
| 4 | Be SOC-SLA aware | Severity bands map to response-window minutes; dashboard surfaces MTTD/MTTR/SLA adherence/dwell |
| 5 | UK-GDPR-safe logging | All email addresses and message IDs are SHA-256 hashed in logs |
| 6 | Deploy anywhere | Single Docker image, SQLite by default, Postgres profile available, no cloud lock-in |

---

## 2 · Component map

```
                        ┌───────────────────────────────────────┐
                        │         Microsoft 365 mailbox         │
                        └──────────────┬────────────────────────┘
                                       │ Graph API (client-credentials)
                                       ▼
  ┌───────────────────────┐   ┌───────────────────────────┐   ┌─────────────┐
  │ Local .eml (CLI scan) │──▶│  Ingestion (src/ingestion)│◀──│ IMAP import │
  └───────────────────────┘   │  • EML parsing            │   │ (future)    │
                              │  • Graph message → Parsed │   └─────────────┘
                              └──────────────┬────────────┘
                                             ▼
                              ┌─────────────────────────────┐
                              │   Analysis engine facade    │
                              │   (src/analysis/__init__.py)│
                              └─┬─┬─┬─┬─┬─┬──────────────────┘
                                │ │ │ │ │ │
          ┌─────────────────────┘ │ │ │ │ └────────────────────────┐
          ▼                       ▼ ▼ ▼ ▼                          ▼
   Header forensics        URL analyser   UK lure detector   NLP classifier
   (SPF/DKIM/DMARC/        (homoglyph,    (brand impersonate, (TF-IDF word+
    reply-to, return-      typosquat,     keyword density,    char n-grams →
    path anomalies)        bad TLDs,      urgency, credential LogisticReg)
                           shorteners)    request)
                                │                     │
                                ▼                     ▼
                        Quishing detector     AI-content detector
                        (pyzbar → QR URL)     (LLM-boilerplate heuristic)
                                             │
                                             ▼
                              ┌─────────────────────────────┐
                              │  AnalysisReport             │
                              │  • score, verdict, severity │
                              │  • findings[]               │
                              │  • iocs[]                   │
                              │  • MITRE techniques         │
                              └──────────────┬──────────────┘
                                             ▼
                              ┌─────────────────────────────┐
                              │  Response orchestrator      │
                              │  (src/response)             │
                              └─┬────────┬─────────┬────────┘
                                ▼        ▼         ▼
                          Quarantine  Ticketing   Alerters
                          (Graph      (Jira /     (Slack /
                           move to    ServiceNow) Teams webhooks)
                           folder)
                                ▼
                                NCSC SERS forwarder
                                (report@phishing.gov.uk)
                                             │
                                             ▼
                              ┌─────────────────────────────┐
                              │  Persistence (SQLAlchemy)   │
                              │  SQLite (default) / Postgres│
                              │  • incidents                │
                              │  • findings                 │
                              │  • iocs                     │
                              └──────────────┬──────────────┘
                                             ▼
                              ┌─────────────────────────────┐
                              │  FastAPI dashboard          │
                              │  (src/dashboard)            │
                              │  • live KPIs                │
                              │  • UK brand heatmap         │
                              │  • MITRE coverage           │
                              │  • IOC velocity             │
                              │  • drill-down + FP toggle   │
                              └─────────────────────────────┘
```

---

## 3 · Scoring model

The analysis engine produces a single float `score ∈ [0, 1]` by summing per-finding weights (from `config/detection_rules.yaml`) and then clamping. The verdict is banded:

| Score | Verdict | Default action |
|-------|---------|---------------|
| `≥ CLASSIFIER_THRESHOLD` (default 0.65) | **PHISHING** | Quarantine + ticket + alert + NCSC forward |
| 0.35 – 0.65 | **SUSPICIOUS** | Ticket for analyst review |
| < 0.35 | **BENIGN** | Log only |

Severity is derived from the score + finding context:

| Severity | SLA (min) | Trigger |
|----------|-----------|---------|
| CRITICAL | 15 | Banking-brand impersonation + credential form |
| HIGH     | 60 | HMRC / Royal Mail impersonation, auth-fail trio |
| MEDIUM   | 240 | Single brand hit, partial auth fail |
| LOW      | 480 | Language-only signals |
| INFORMATIONAL | 1440 | Missing auth records on borderline content |

The NLP classifier is a TF-IDF feature union (word 1-2grams + char_wb 3-5grams) → Logistic Regression, trained on a curated UK corpus (`scripts/train_model.py`). The training script reports 5-fold F1 so regressions surface immediately.

---

## 4 · Data model

```
incidents (one row per processed message)
├── id (PK)
├── message_id (unique, indexed)
├── received_at / detected_at / responded_at  ─ MTTD / MTTR / dwell inputs
├── verdict / severity / score / sla_minutes
├── brand_impersonated   ─ powers UK brand heatmap
├── from_address / subject / summary
├── quarantined / ticket_id / mitre_techniques
└── is_false_positive    ─ analyst-flipped FP rate denominator

findings (one-to-many from incidents)
├── detector / rule / weight / detail

iocs (one-to-many from incidents)
├── type / value / source_detector / tags
```

---

## 5 · MITRE ATT&CK coverage

The engine annotates every incident with applicable ATT&CK techniques:

| Technique | Name | Trigger |
|-----------|------|---------|
| T1566.001 | Spearphishing Attachment | suspicious attachment types |
| T1566.002 | Spearphishing Link | malicious URL indicators |
| T1566.003 | Spearphishing via Service | detected from legit service spoof |
| T1598.003 | Spearphishing for Information | credential-harvesting form |
| T1656     | Impersonation | UK brand display-name spoof |

These feed the dashboard's coverage panel.

---

## 6 · UK-specific innovations

- **Quishing detection** — pyzbar decodes QR codes from inline images and attachments (pdf2image for PDFs); legitimate UK government / Royal Mail mail rarely embeds external-host QR codes.
- **Homoglyph + typosquat detection** — Cyrillic/Greek → ASCII fold, Levenshtein distance against UK brand registrable domains. Catches `royаl-mail-redeliver.click` (Cyrillic "а") and `natwest-secure-banking.buzz`.
- **UK-lure corpus** — `config/uk_brands.yaml` captures display-alias spoofing, with legitimate domain whitelists so an impersonation is flagged even when only the display name is faked.
- **NCSC SERS bridge** — confirmed phishing auto-forwards to `report@phishing.gov.uk` (opt-in via `ENABLE_NCSC_SERS_FORWARDING`).
- **Action Fraud-aligned** — incident payloads include the fields Action Fraud requires for bulk reporting.
- **Cyber Essentials Plus evidence** — the `data/iocs/*.json` + STIX 2.1 bundle exports serve as auditor-ready evidence of phishing control operation.
- **UK-GDPR-aware logging** — PII (email addresses, message IDs) is SHA-256 hashed in log lines.

---

## 7 · Extension points

- Swap SQLite → Postgres via `DATABASE_URL` (no code changes).
- Drop in additional detectors by adding a class with an `analyse(...)` method and registering it in `AnalysisEngine.__init__`.
- Add ticketing backends under `src/response/__init__.py` by subclassing the strategy pattern.
- Ship IOCs to MISP by adding a handler in `IocReporter.emit()` — STIX 2.1 output is already produced.
