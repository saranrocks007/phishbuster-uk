"""Seed the database with realistic-looking synthetic incidents for demos.

Public deployments need data so the dashboard isn't empty when a recruiter
or interviewer clicks the live URL. This script produces ~80 incidents
spread across the past 14 days with realistic verdict / severity / brand /
detector distributions, so KPIs look plausible.

Usage:
    python scripts/seed_demo_data.py            # 80 incidents over 14 days
    python scripts/seed_demo_data.py --count 200 --days 30
    python scripts/seed_demo_data.py --reset    # wipe before seeding

Safe to run in production-shaped environments — every seeded row is
tagged with `summary` starting "[DEMO]" so it's distinguishable from
real incidents and easy to delete later.
"""
from __future__ import annotations

import argparse
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.database import (
    FindingRow, IncidentRow, IocRow, init_db, session_scope,
)

# ============================================================ FIXTURES

UK_BRANDS = [
    ("HMRC",          "noreply@hmrc-tax-refund.{tld}",   "HMRC",          1.5),
    ("Royal Mail",    "delivery@royalmail-redeliver.{tld}", "Royal Mail",  1.4),
    ("NatWest",       "alerts@natwest-secure-banking.{tld}","NatWest",     1.5),
    ("Barclays",      "security@barclays-online.{tld}",   "Barclays",     1.5),
    ("Lloyds",        "service@lloyds-account.{tld}",     "Lloyds",       1.4),
    ("HSBC",          "alerts@hsbc-uk-online.{tld}",      "HSBC",         1.4),
    ("Halifax",       "team@halifax-secure.{tld}",        "Halifax",      1.4),
    ("DVLA",          "noreply@dvla-licence-renew.{tld}", "DVLA",         1.3),
    ("NHS",           "covidpass@nhs-verify.{tld}",       "NHS",          1.2),
    ("DWP",           "benefits@dwp-cost-of-living.{tld}","DWP",          1.2),
    ("TV Licensing",  "billing@tvlicensing-renew.{tld}",  "TV Licensing", 1.1),
    ("British Gas",   "refund@britishgas-account.{tld}",  "British Gas",  1.1),
    ("Octopus Energy","auto@octopus-energy-refund.{tld}", "Octopus Energy",1.0),
    ("Monzo",         "support@monzo-card-frozen.{tld}",  "Monzo",        1.2),
    ("Council Tax",   "council@council-tax-refund.{tld}", "Council Tax",  1.0),
]

# Brands that should sometimes appear as legitimate (no impersonation)
LEGIT_SENDERS = [
    ("hello@octopus.energy",       "Octopus Energy", "Your monthly summary is ready"),
    ("noreply@github.com",         "GitHub",         "[GitHub] You have 3 new notifications"),
    ("invoices@xero.com",          "Xero",           "Invoice INV-2024-0418 — paid"),
    ("calendar-noreply@google.com","Google Calendar","Invitation: Sync with Maya"),
    ("team@stripe.com",            "Stripe",         "Your weekly payment summary"),
    ("noreply@linkedin.com",       "LinkedIn",       "5 people viewed your profile"),
    ("orders@amazon.co.uk",        "Amazon UK",      "Your order has been dispatched"),
    ("hello@notion.so",            "Notion",         "Weekly digest from your team"),
]

LURE_SUBJECTS = {
    "HMRC":         ["Tax refund of £{amt} pending", "URGENT: HMRC investigation P800",
                     "Your VAT reclaim is ready", "Final notice — self-assessment overdue"],
    "Royal Mail":   ["Parcel held — £{small} redelivery fee", "We tried to deliver your parcel",
                     "Customs charge required for parcel #{num}", "Scan QR to reschedule delivery"],
    "NatWest":      ["New payee added to your account", "Suspicious sign-in detected",
                     "Account temporarily locked", "Unusual transaction £{amt}"],
    "Barclays":     ["Verify recent £{amt} transaction", "Card has been blocked",
                     "Sign-in from unrecognised device"],
    "Lloyds":       ["Account suspended — verify identity", "Confirm £{amt} payment"],
    "HSBC":         ["New device added — confirm identity", "Re-enter card details"],
    "Halifax":      ["Suspicious £{amt} payment detected", "Unauthorised activity"],
    "DVLA":         ["Vehicle tax direct debit failed", "Driving licence renewal required"],
    "NHS":          ["COVID pass verification needed", "Re-verify NHS account"],
    "DWP":          ["£{amt} cost-of-living payment ready", "Confirm NI number to release funds"],
    "TV Licensing": ["Direct debit declined — £{small} fine", "TV Licence renewal required"],
    "British Gas":  ["Energy refund of £{amt} owed", "Update bank details for credit"],
    "Octopus Energy":["Annual refund — £{amt}", "Account update required"],
    "Monzo":        ["Card frozen — confirm identity", "Unusual spending detected"],
    "Council Tax":  ["Council tax refund £{amt} pending", "Direct debit failure — bailiff visit"],
}

DETECTORS = [
    ("header_forensics", "spf_fail", 0.20, "SPF authentication failed."),
    ("header_forensics", "dkim_fail", 0.20, "DKIM signature invalid."),
    ("header_forensics", "dmarc_fail", 0.20, "DMARC policy violation."),
    ("header_forensics", "reply_to_mismatch", 0.15, "Reply-To differs from From domain."),
    ("uk_lure", "display_name_spoof", 0.25, "Brand name impersonated; from-domain unrelated."),
    ("uk_lure", "uk_lure_match", 0.25, "UK brand keywords matched."),
    ("uk_lure", "urgency_language", 0.10, "Urgency language detected."),
    ("uk_lure", "credential_form", 0.25, "Credential request form detected."),
    ("url_analyser", "high_risk_tld", 0.10, "URL uses high-risk TLD."),
    ("url_analyser", "url_shortener", 0.10, "URL shortener used."),
    ("url_analyser", "homoglyph_domain", 0.30, "Homoglyph domain detected."),
    ("url_analyser", "typosquat_domain", 0.25, "Typosquat domain detected."),
    ("nlp", "ml_phishing_likely", 0.20, "Classifier confidence above threshold."),
    ("threat_intel", "ti_url_malicious", 0.40, "VirusTotal flagged URL malicious."),
    ("threat_intel", "ti_domain_malicious", 0.35, "Domain has TI hits."),
    ("domain_age", "newly_registered", 0.15, "Domain registered <30 days ago."),
    ("bec", "sender_first_seen", 0.15, "Sender unknown to organisation."),
    ("ai_content", "ai_generated_likely", 0.10, "Stylistic markers suggest LLM generation."),
    ("quishing_detector", "qr_code_to_suspicious", 0.30, "QR code resolves to suspicious URL."),
]

HIGH_RISK_TLDS = [".xyz", ".top", ".click", ".buzz", ".rest", ".link", ".bond", ".cam", ".support"]
SHORTENERS    = ["bit.ly", "tinyurl.com", "t.co", "shorturl.at"]


def _randdate(days_back: int) -> datetime:
    """Random datetime within the past N days, weighted toward recent."""
    bias = random.random() ** 1.4   # bias toward recent
    seconds_ago = int(bias * days_back * 86400)
    return datetime.utcnow() - timedelta(seconds=seconds_ago)


def _build_phish(brand_tuple, when: datetime):
    name, addr_tmpl, brand, _sev = brand_tuple
    tld = random.choice(HIGH_RISK_TLDS).lstrip(".")
    sender = addr_tmpl.format(tld=tld)
    subj_tmpl = random.choice(LURE_SUBJECTS.get(brand, ["Action required on your account"]))
    subject = subj_tmpl.format(
        amt=random.choice([129.50, 326.41, 489.20, 948.20, 1240.00, 312.00]),
        small=random.choice([1.99, 2.50, 2.99, 3.50, 5.00]),
        num=random.randint(100000, 999999),
    )

    # Choose detectors that fired (weighted by realism for this brand)
    fired = []
    # Always fire auth + brand for phish
    fired.append(random.choice([d for d in DETECTORS if d[0] == "header_forensics"]))
    fired.append(("uk_lure", "display_name_spoof", 0.25,
                  f"'{brand}' impersonated; from-domain unrelated to legitimate domain."))
    fired.append(random.choice([d for d in DETECTORS if d[0] == "url_analyser"]))
    if random.random() > 0.4:
        fired.append(("uk_lure", "urgency_language", 0.10, "Urgency language: ['within 24 hours']."))
    if random.random() > 0.5:
        fired.append(("uk_lure", "credential_form", 0.25,
                      "Credential request: sort code + account number + password."))
    if random.random() > 0.6:
        fired.append(("nlp", "ml_phishing_likely", 0.20,
                      "Classifier probability=0.94 (top tokens: refund, click, kindly)."))
    if random.random() > 0.7:
        fired.append(("threat_intel", "ti_url_malicious", 0.40,
                      "URL flagged by URLhaus, PhishTank, VirusTotal (3 engines)."))
    if random.random() > 0.6:
        fired.append(("domain_age", "newly_registered", 0.15,
                      f"Domain registered {random.randint(1, 28)}d ago."))
    if random.random() > 0.7:
        fired.append(("bec", "sender_first_seen", 0.15, f"Sender '{sender}' unknown to org."))

    score = min(sum(f[2] for f in fired), 1.0)
    if score >= 0.65:
        verdict = "phishing"
    elif score >= 0.35:
        verdict = "suspicious"
    else:
        verdict = "benign"

    if score >= 0.90:    severity, sla = "critical", 15
    elif score >= 0.75:  severity, sla = "high", 60
    elif score >= 0.55:  severity, sla = "medium", 240
    elif score >= 0.35:  severity, sla = "low", 480
    else:                severity, sla = "informational", 1440

    detected_at = when + timedelta(seconds=random.randint(15, 240))
    responded_at = None
    if verdict in {"phishing", "suspicious"} and random.random() > 0.1:
        responded_at = detected_at + timedelta(minutes=random.randint(2, sla * 2))

    quarantined = verdict == "phishing" and random.random() > 0.05
    ticket_id = f"PB-{random.randint(1000, 9999)}" if verdict != "benign" else None
    is_fp = verdict == "phishing" and random.random() < 0.03

    mitre = []
    if any(f[0] == "url_analyser" for f in fired):  mitre.append("T1566.002")
    if brand:                                       mitre.append("T1656")
    if any(f[1] == "sender_first_seen" for f in fired): mitre.append("T1534")
    if any(f[1] == "ti_url_malicious" for f in fired):  mitre.append("T1598.003")

    return {
        "message_id": f"<demo-{random.randint(10**14, 10**15)}@{sender.split('@')[1]}>",
        "received_at": when, "detected_at": detected_at, "responded_at": responded_at,
        "verdict": verdict, "severity": severity, "score": round(score, 3),
        "sla_minutes": sla, "brand": brand, "from_address": sender, "subject": subject,
        "summary": f"[DEMO] {brand} impersonation; {len(fired)} detections; score {score:.2f}",
        "quarantined": quarantined, "ticket_id": ticket_id,
        "mitre": ",".join(mitre), "is_fp": is_fp,
        "findings": [(d, r, w, det) for d, r, w, det in fired],
        "iocs": [
            ("url",    f"https://{addr_tmpl.split('@')[1].format(tld=tld)}/login", "url_analyser"),
            ("domain", addr_tmpl.split("@")[1].format(tld=tld), "url_analyser"),
            ("email",  sender, "ingestion"),
        ],
    }


def _build_benign(when: datetime):
    sender, name, subject = random.choice(LEGIT_SENDERS)
    detected_at = when + timedelta(seconds=random.randint(10, 60))
    return {
        "message_id": f"<demo-{random.randint(10**14, 10**15)}@{sender.split('@')[1]}>",
        "received_at": when, "detected_at": detected_at, "responded_at": detected_at,
        "verdict": "benign", "severity": "informational", "score": 0.0,
        "sla_minutes": 1440, "brand": None, "from_address": sender, "subject": subject,
        "summary": f"[DEMO] Benign mail from {name}.",
        "quarantined": False, "ticket_id": None,
        "mitre": "", "is_fp": False,
        "findings": [], "iocs": [("email", sender, "ingestion")],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=80)
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--reset", action="store_true",
                    help="Delete previous [DEMO] rows before seeding.")
    ap.add_argument("--phish-ratio", type=float, default=0.45,
                    help="Fraction of seeded rows that should be phishing/suspicious.")
    args = ap.parse_args()

    init_db()

    if args.reset:
        with session_scope() as s:
            n = s.query(IncidentRow).filter(IncidentRow.summary.like("[DEMO]%")).count()
            s.query(IocRow).filter(
                IocRow.incident_id.in_(
                    s.query(IncidentRow.id).filter(IncidentRow.summary.like("[DEMO]%"))
                )
            ).delete(synchronize_session=False)
            s.query(FindingRow).filter(
                FindingRow.incident_id.in_(
                    s.query(IncidentRow.id).filter(IncidentRow.summary.like("[DEMO]%"))
                )
            ).delete(synchronize_session=False)
            s.query(IncidentRow).filter(IncidentRow.summary.like("[DEMO]%")).delete(
                synchronize_session=False)
            print(f"[reset] removed {n} prior demo incidents")

    n_phish = int(args.count * args.phish_ratio)
    n_benign = args.count - n_phish

    incidents = []
    for _ in range(n_phish):
        incidents.append(_build_phish(random.choice(UK_BRANDS), _randdate(args.days)))
    for _ in range(n_benign):
        incidents.append(_build_benign(_randdate(args.days)))

    incidents.sort(key=lambda i: i["received_at"])

    with session_scope() as s:
        for inc in incidents:
            row = IncidentRow(
                message_id=inc["message_id"],
                received_at=inc["received_at"],
                detected_at=inc["detected_at"],
                responded_at=inc["responded_at"],
                verdict=inc["verdict"], severity=inc["severity"],
                score=inc["score"], sla_minutes=inc["sla_minutes"],
                brand_impersonated=inc["brand"],
                from_address=inc["from_address"], subject=inc["subject"],
                summary=inc["summary"], quarantined=inc["quarantined"],
                ticket_id=inc["ticket_id"], mitre_techniques=inc["mitre"],
                is_false_positive=inc["is_fp"],
            )
            for d, r, w, det in inc["findings"]:
                row.findings.append(FindingRow(detector=d, rule=r, weight=w, detail=det))
            for t, v, src in inc["iocs"]:
                row.iocs.append(IocRow(type=t, value=v, source_detector=src, tags=""))
            s.add(row)

    print(f"\nSeeded {args.count} incidents "
          f"({n_phish} phishing/suspicious, {n_benign} benign) "
          f"across the past {args.days} days.")
    print("Open the dashboard to verify KPIs and panels populate.")


if __name__ == "__main__":
    main()
