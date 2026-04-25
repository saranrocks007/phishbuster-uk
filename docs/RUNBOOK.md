# Runbook — PhishBuster UK

Day-to-day operational guide for SOC analysts and detection engineers.

---

## 1 · Daily checks (start of shift, 5 minutes)

1. Open the console at `http://<host>:8080/`.
2. Verify **OPERATIONAL** banner is lit and `generated` timestamp is recent.
3. Check the **KPI strip**:
   - `Confirmed phishing` — baseline against your rolling 7-day average.
   - `MTTD` — should stay < 5 minutes; > 15 minutes is an amber flag.
   - `MTTR` — should stay within the severity SLA window (15/60/240/480 min).
   - `SLA adherence` — target ≥ 95%.
   - `FP rate` — target ≤ 5%; > 10% indicates model drift (retrain).
   - `Dwell` — **zero-tolerance** if > severity SLA; an open unresponded phish is an active exposure.
4. Scan the **UK brand impersonation** panel for spikes (HMRC around tax season, Royal Mail during holidays, banking brands around quarter-end).
5. Clear the overnight **Incident stream** — triage any `SUSPICIOUS` items not yet actioned.

---

## 2 · Triaging an incident

1. Click the row in the stream → the detail modal opens.
2. Review in order:
   - **Summary** — one-line engine verdict.
   - **Findings table** — each row is a single detector's hit with its weight. If 3+ detectors agree, the verdict is usually solid.
   - **Indicators** — urls, domains, attachment hashes; these go out as IOCs.
   - **MITRE** — technique coverage for threat-hunt pivots.
3. Decide:
   - **Confirmed phishing** — leave as-is (response is already automated: quarantined + ticket + alert + optional NCSC forward).
   - **False positive** — click *Toggle false positive*. This adjusts the FP-rate KPI and flags the row for the next retraining cycle.
   - **Needs more context** — copy the `message_id` and pull the full raw email from the M365 admin console.

---

## 3 · Response actions already taken by the engine

When verdict = `PHISHING`:

| Action | Component | Condition |
|--------|-----------|-----------|
| Moved to quarantine folder | `Quarantiner` | `ENABLE_AUTO_QUARANTINE=true` |
| Incident ticket created | `TicketingBackend` | `ENABLE_TICKETING=true` |
| Slack / Teams alert | `Alerter` | webhook URL configured |
| NCSC SERS forward | `NcscForwarder` | `ENABLE_NCSC_SERS_FORWARDING=true` |
| IOC export (JSON + CSV + STIX 2.1) | `IocReporter` | always |
| Persisted to database | `persist_report` | always |

For `SUSPICIOUS`: ticket only (no quarantine, no NCSC forward). Analyst decides the final disposition.

---

## 4 · Common operational scenarios

### 4.1 · Sudden HMRC-themed spike (tax-season scenario)

- Open brand panel → confirm HMRC is top-of-list.
- Pull all 7-day HMRC incidents via API: `curl '/api/incidents?brand=hmrc&limit=200'`.
- Check for common From-domain patterns; add the domains to your upstream perimeter block list.
- Raise the HMRC severity multiplier in `config/uk_brands.yaml` temporarily (e.g. 1.4 → 1.6) to shift more borderline incidents into HIGH.

### 4.2 · Quishing campaign (QR-code phish)

- Filter stream by detector: look for `quishing_detector` in findings.
- Target audience is usually mobile users (Royal Mail QR scam pattern).
- If rate > 10/day, push an awareness comms with screenshots.

### 4.3 · Analyst-reported false positive burst

- If FP rate > 15% in 24h, assume model drift.
- Export the FP incidents as CSV:
  ```sql
  SELECT * FROM incidents WHERE is_false_positive = 1 AND received_at > datetime('now','-7 days');
  ```
- Add the representative samples to `scripts/train_model.py` HAM corpus, retrain, redeploy.

### 4.4 · AiTM (Adversary-in-the-Middle) indicators

- The URL analyser flags tokenised look-alike login domains.
- Pivot: query for incidents with findings `rule = 'aitm_indicator'`.
- Cross-reference the destination domains against Entra ID sign-in logs; block any successfully-authenticated sessions.

### 4.5 · Dashboard shows no data

1. Check `docker compose ps` — are `scanner` and `dashboard` both running?
2. Tail scanner logs: `docker compose logs -f scanner | tail -100`.
3. Confirm Graph auth works: `curl -s http://localhost:8080/api/health` returns `ok`.
4. Verify mailbox permission: the app registration must be granted `Mail.ReadWrite` **application** (not delegated) for the target mailbox.

---

## 5 · Weekly tasks

- **Monday**: review the **Detector yield** panel. Detectors contributing < 1% over 7 days are candidates for tuning (raise weight) or removal.
- **Wednesday**: retrain the classifier if 50+ new labelled samples exist: `python scripts/train_model.py`. Diff the printed F1 against last week; regressions require investigation.
- **Friday**: export the weekly IOC bundle for downstream sharing:
  ```bash
  find data/iocs -name "*.stix.json" -mtime -7 | zip ../weekly-iocs.zip -@
  ```
  Share to MISP / partner SOCs as contractually permitted.

---

## 6 · Incident escalation thresholds

| Condition | Action |
|-----------|--------|
| Banking-brand phish targeting exec mailbox | Page on-call IR; treat as potential BEC |
| 20+ credential-form phish landing in 1h | Trigger mass password-reset workflow |
| Known breached URL appears in IOCs | Block at perimeter + notify ISP abuse desk |
| Malware-bearing attachment detected | Isolate endpoint if user clicked; follow incident response plan |
| NHS-themed phish campaign | Notify NHS Digital via CSIRT email; Action Fraud report |

---

## 7 · Contact & escalation

- **SOC Manager** — tier-2 escalation for policy decisions
- **Detection Engineering** — model retraining and rule tuning
- **NCSC SERS** — `report@phishing.gov.uk` (auto-forwarded)
- **Action Fraud** — `0300 123 2040` for criminal reporting
- **ICO** — breach-notification within 72h if personal data exfiltrated

---

## 8 · KPI targets (first 90 days)

| KPI | Target |
|-----|--------|
| MTTD | < 5 min |
| MTTR | < severity SLA (95% adherence) |
| FP rate | < 5% |
| Coverage (scanned / received) | ≥ 99% of mailbox traffic |
| UK brand catch rate | ≥ 98% (validated weekly with holdout set) |
| Dwell time (open phish) | 0 > 15 min |
