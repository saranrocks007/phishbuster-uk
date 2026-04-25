# v2 Detection Upgrade — Closing the production-readiness gaps

This release adds seven detection capabilities that were missing from the v1 prototype. Every new feature is **opt-in** via environment variable so the simple deployment path still works exactly as before.

---

## 1 · Threat-intelligence enrichment

**What:** Multi-vendor reputation lookups for URLs, domains, IPs, and file hashes.

**Vendors integrated:**
| Vendor | What it covers | API key required? |
|--------|---------------|-------------------|
| **VirusTotal** v3 | URLs, domains, file hashes | Yes (free tier: 4/min, 500/day) |
| **AbuseIPDB** v2 | IP reputation | Yes (free tier: 1k/day) |
| **URLhaus** (abuse.ch) | Live malware-distribution URLs | Optional auth key |
| **PhishTank** | Verified phishing URLs | Optional username |

**Where:** `src/analysis/threat_intel.py`

**Enable:**
```bash
ENABLE_THREAT_INTEL=true
VIRUSTOTAL_API_KEY=xxx
ABUSEIPDB_API_KEY=xxx
```

**Findings emitted:** `ti_url_malicious`, `ti_url_suspicious`, `ti_domain_malicious`, `ti_ip_abuse`, `ti_filehash_known_malicious`

**Quota protection:** Every lookup is cached in `data/ti_cache.sqlite` for `THREAT_INTEL_CACHE_TTL_HOURS` (default 24). Repeat scans of the same URL within the TTL don't burn quota. The detector is **fail-open** — vendor errors log a warning but never block the pipeline.

---

## 2 · Domain age via WHOIS

**What:** Looks up registered domains for the sender and every URL, flags those registered ≤ N days ago.

**Where:** `src/analysis/domain_age.py`

**Enable:** On by default (`ENABLE_DOMAIN_AGE_CHECK=true`).

**Threshold:** `DOMAIN_AGE_RECENT_DAYS=30` — anything younger fires `newly_registered` (weight 0.15).

**Caching:** WHOIS results are cached for **30 days** since creation dates don't change. Negative results are also cached short-term to avoid hammering rate-limited WHOIS servers (especially `.uk`).

---

## 3 · Live URL sandbox

**What:** Two modes for actually visiting suspicious URLs:

1. **Direct fetch** — `httpx` with hard timeout (8s default) and capped redirects (4). Inspects final HTML for credential forms, UK-brand asset theft, and excessive redirects. Never executes JavaScript — we only download HTML.
2. **urlscan.io** — searches existing public scans (no quota cost) and ingests their verdict.

**Where:** `src/analysis/url_sandbox.py`

**Enable:**
```bash
ENABLE_URL_SANDBOX=true                # off by default — visits URLs!
SANDBOX_TIMEOUT_SECONDS=8
SANDBOX_MAX_REDIRECTS=4
URLSCAN_API_KEY=xxx                    # optional
```

**Findings:** `sandbox_credential_form` (0.30), `sandbox_brand_asset_steal` (0.35), `sandbox_redirect_chain` (0.15).

**Threat model:** Even at worst, only HTML is downloaded — never persisted. To run in a deployment that talks to attacker-controlled hosts, route the egress through your network security stack.

---

## 4 · Attachment scanning

**What:** YARA rules + Office macro detection + PDF JavaScript detection + optional ClamAV.

**Where:** `src/analysis/attachment_scanner.py`, rules in `config/yara/*.yar`

**Enable:**
```bash
ENABLE_YARA_SCANNING=true              # default true; auto-disables if yara-python missing
YARA_RULES_DIR=./config/yara
ENABLE_CLAMAV=false                    # set true if you have clamd reachable
```

**Starter ruleset shipped** (`config/yara/phishbuster_uk_starter.yar`):
- `HTML_Credential_Harvester_UK` — login form posting to non-bank host
- `Phish_HTML_Auto_Submit` — auto-submitting credential form
- `HMRC_Lure_HTML` / `Royal_Mail_Lure_HTML` — UK-brand themed HTML
- `Suspicious_ISO_Container` / `Suspicious_LNK_Loader` — MOTW-bypass loaders
- `Office_VBA_With_Shell_Exec` — VBA macros invoking shell
- `Encoded_Powershell_Payload` — base64-encoded PowerShell
- `Double_Extension_Hint` — `.pdf.exe`, `.invoice.html`, etc.

**Office macro detection** works on raw bytes — looks for VBA marker strings (`vbaProject.bin`, `Auto_Open`, `Document_Open`, `Workbook_Open`) without needing oletools. Emits `macro_office_with_autoexec` (0.30) when an auto-execute hook is present.

**PDF JavaScript** detection scans the first 500KB for `/JS`, `/JavaScript`, or `/OpenAction` markers.

---

## 5 · BEC / sender anomaly detector

**What:** Maintains a per-sender baseline (first-seen, hour-of-day histogram, recipient set, vocabulary fingerprint, length stats) and scores incoming mail against it. Catches Business Email Compromise patterns that other detectors miss.

**Where:** `src/analysis/bec_detector.py` + new `sender_profiles` table.

**Enable:** On by default (`ENABLE_BEC_DETECTOR=true`).

**Findings:**
| Rule | Weight | Trigger |
|------|--------|---------|
| `sender_first_seen` | 0.15 | Sender never sent to org before |
| `sender_unusual_hour` | 0.08 | Send-time outside sender's 2%-percentile hour band |
| `sender_new_recipient` | 0.10 | sender→recipient pair never observed |
| `sender_writing_style_shift` | 0.20 | Cosine similarity to sender's vocabulary baseline < 0.20 |
| `bec_finance_keywords` | 0.20 | "wire transfer", "change of bank", "new payee", invoice patterns |

**Baseline integrity:** Profiles **only update on confirmed BENIGN messages**. Attackers cannot poison their own baseline by sending malicious mail.

**Cold-start:** Anomaly scoring activates after `BEC_BASELINE_MIN_MESSAGES=5` benign messages from a sender. Below that threshold, only `sender_first_seen` and `bec_finance_keywords` can fire.

---

## 6 · Improved AI-content detector

**What:** Replaced the single-heuristic detector with a **statistical ensemble** of 8 features. Requires ≥ 3 to fire (precision over recall).

**Where:** `src/analysis/ai_content_detector.py`

**Features:**
1. LLM boilerplate phrase density (19 known LLM phrases)
2. Sentence-length burstiness (CV < 0.35 = LLM-like)
3. Vocabulary type-token ratio (outside [0.40, 0.88] = atypical)
4. Punctuation diversity (humans use em-dashes, ellipses idiosyncratically)
5. Hedge/transition adverb density (`furthermore`, `moreover`, `consequently`...)
6. Excessive politeness markers (`kindly`, `please be advised`...)
7. UK-brand context with US-English spelling cues
8. Word-length variance

Weight scales with signal count: 3 signals = base weight (0.10), 7 signals = 2× base (0.20).

---

## 7 · Public-corpus loader for the classifier

**What:** Bootstraps the NLP classifier from public phishing/ham datasets so you don't have to start from 60 hand-labelled samples.

**Where:** `scripts/import_corpus.py`

**Sources:**
- **Nazario phishing corpus** (mirrored on GitHub) — historical phishing emails
- **SpamAssassin public corpus** — ham + spam (~6k each)
- **User-supplied CSV** — for org-specific labelled data (`label,text` columns)

**Usage:**
```bash
# Pull both public corpora; cap each to a sane size
python scripts/import_corpus.py --nazario --spam-assassin \
    --nazario-limit 5000 --sa-phish-limit 1500 --sa-ham-limit 3000

# Or import your SOC's labelled queue
python scripts/import_corpus.py --csv ./labelled_phish.csv

# Then retrain — train_model.py auto-picks up data/corpus/labelled_corpus.jsonl
python scripts/train_model.py
```

The classifier scales gracefully — TF-IDF + LogisticRegression handles 10k+ samples in seconds with no architecture changes.

---

## Updated MITRE ATT&CK coverage

| Technique | Name | New trigger |
|-----------|------|-------------|
| `T1204.002` | Malicious File (User Execution) | YARA-malicious / VT-malicious file / macro with auto-exec |
| `T1534` | Internal Spearphishing / BEC | Sender first-seen, style shift, finance keywords |
| `T1598.003` | Spearphishing for Information | TI-malicious URL, sandbox credential form |

---

## Migration notes

**Database schema:** A new `sender_profiles` table is added. SQLAlchemy creates it automatically on first run via `init_db()` — no manual migration needed.

**EmailAttachment model:** Now allows extra fields (`model_config = {"extra": "allow"}`) so ingestion can stash raw bytes for YARA/ClamAV without persisting them.

**Score caps:** Verdicts may shift on existing fixtures because more detectors fire. The four sample emails were re-tested:
- HMRC / NatWest / Royal Mail phish → still PHISHING / CRITICAL
- Legit Octopus mail → BENIGN at 0.15 (was 0.00) — `sender_first_seen` fires once, well below the 0.35 suspicious threshold. After 5 benign messages from that sender, the finding stops firing.

**Performance:** With all detectors enabled and external lookups configured, expect ~600ms–2.5s per message (dominated by the first WHOIS / TI lookup; cached results are sub-10ms). For 1000 msg/h throughput, you'll want to enable all caches and consider adding a Redis layer in front of `data/ti_cache.sqlite`.
