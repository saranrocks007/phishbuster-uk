"""Train the PhishBuster UK NLP classifier.

Ships with a small curated UK-specific corpus of phishing and ham
examples. In production you would swap this for a labelled corpus from
your own SOC queue (review-confirmed phish + review-confirmed ham).

    python scripts/train_model.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import joblib
from dotenv import load_dotenv
from sklearn.metrics import classification_report
from sklearn.model_selection import cross_val_score, train_test_split

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.analysis.nlp_classifier import PhishingClassifier


# ---- UK lure corpus (curated; condensed) ---------------------------
PHISH = [
    # HMRC
    "Dear Customer, HMRC owes you a tax refund of £326.41. Click here to claim within 24 hours to avoid cancellation.",
    "Final notice: your self-assessment submission is overdue and a penalty of £100 has been applied. Settle immediately via secure link.",
    "HM Revenue and Customs: tax calculation P800 ready. Verify your identity to receive your rebate.",
    "URGENT — HMRC tax investigation opened against your UTR. Respond within 48 hours to avoid court.",
    "You are eligible for a VAT reclaim of £948.20. Please click the link to re-enter your bank details.",
    # Royal Mail
    "Royal Mail: Your parcel is being held pending a £1.99 redelivery fee. Schedule redelivery now.",
    "We were unable to deliver your parcel. A small shipping fee of £2.99 is required to complete delivery.",
    "ROYAL MAIL — Customs clearance charge outstanding. Failure to pay will return the parcel to sender.",
    "Your Royal Mail parcel is awaiting collection. Please scan the QR code to reschedule delivery.",
    # NHS / DVLA / DWP
    "NHS: Your COVID-19 digital pass needs re-verification. Log in with your NHS account credentials.",
    "DVLA: Your vehicle tax direct debit failed. Update your card details to avoid a £80 penalty.",
    "DWP Cost of Living Payment — £301 pending. Confirm your National Insurance number to release funds.",
    "DVLA — your driving licence is due to expire. Kindly renew online to avoid disqualification.",
    # UK banks
    "NatWest alert: A new payee was added to your account. If this was not you click here to remove within 24 hours.",
    "Barclays: unusual sign-in from an unrecognised device. Verify your identity to restore account access.",
    "Lloyds Bank — your account has been temporarily suspended due to suspicious activity. Confirm your identity.",
    "HSBC: new device added. Re-enter your card number, sort code and account number to confirm.",
    "Halifax: we have detected a £312.00 transaction we believe you did not authorise. Cancel it now.",
    "Monzo: your card has been frozen due to unusual spending. Please confirm your identity to unfreeze.",
    # Utilities
    "British Gas: you are entitled to an energy bill refund of £129.50. Click below to update your bank details.",
    "Ofgem refund notice: due to recent changes you are owed a credit on your account. Verify to receive.",
    # Generic urgency / credential
    "Your email account will be closed in 24 hours due to unusual activity. Kindly verify your password to continue.",
    "Dear user, we have temporarily suspended your Microsoft 365 access. Sign in here to re-enable.",
    "Congratulations, you have been selected to receive a £500 Tesco Clubcard bonus. Claim before it expires.",
    # Quishing lure body (text would accompany QR image)
    "To schedule your Royal Mail redelivery quickly, please scan the QR code on this delivery card.",
    "Your parking session has expired. Scan the QR code to renew and avoid a penalty charge notice.",
    # Council / TV Licensing
    "Your council tax direct debit failed. A bailiff visit will be arranged unless you pay within 48 hours.",
    "TV Licensing: your direct debit was declined. Update your card details or face a £1000 fine.",
    # AiTM-style
    "Microsoft 365: your password will expire today. Re-authenticate via the secure portal to prevent lockout.",
    # Typosquat bait
    "N0tification from H-M-R-C regarding your tax affairs. Immediate action required.",
]

HAM = [
    "Hi team, just circulating the notes from yesterday's product review. Happy to chat further in stand-up tomorrow.",
    "Reminder that the fire drill will take place at 11:00 on Thursday. Please ensure visitors are briefed.",
    "Your flight itinerary from London Heathrow to Amsterdam on 12 May is attached. Have a good trip.",
    "Order confirmation: 1x Raspberry Pi 5 and accessories. Estimated delivery Wednesday.",
    "Invoice INV-2025-0417 attached for last month's services. Payment terms: 30 days.",
    "Congratulations on completing the annual compliance training. Certificate attached.",
    "Your monthly energy usage report is ready. Log in to the British Gas app to review.",
    "Hi Sarah, please find attached the quarterly board pack for your review ahead of Friday.",
    "This is a gentle reminder of your dental appointment on Tuesday 10:30 at the Tiruchengode clinic.",
    "Welcome to the engineering guild. Onboarding documents and calendar invites to follow.",
    "Weekly newsletter: team wins, hiring updates, and a deep-dive on our observability stack.",
    "Your Uber receipt for the journey on 14 March is attached. Thanks for riding with us.",
    "Annual leave request approved. Enjoy your time off.",
    "Security bulletin: please restart your workstation to apply this week's patches before Friday.",
    "Your Amazon Prime subscription has been renewed for £95.00. Thanks for being a member.",
    "Companies House reminder: your confirmation statement is due in 21 days. Filing link in your portal.",
    "Minutes from the steering group are published on SharePoint — link in this thread.",
    "A new release of the design system is available. Changelog and migration notes in Confluence.",
    "Your LinkedIn weekly digest: 4 new profile views, 2 posts performing above average.",
    "NHS: your annual health check is available to book via your GP surgery.",
    "Octopus Energy: your Direct Debit schedule has been updated as requested. No action required.",
    "Here is a calendar invite for our customer call next Wednesday — agenda attached.",
    "Hi, the pull request for the search indexing bug is ready for review. Tests green.",
    "Quarterly feedback: thanks for the steady work on the migration; see comments inside.",
    "Revolut: your monthly spending summary for April is now available in the app.",
    "Your Spotify invoice for April is attached. No action required.",
    "Training announcement: CEH recertification webinar on Friday at 14:00 BST.",
    "Reminder: please submit your expense claim for the London conference by Friday.",
    "Office broadband maintenance window Saturday 23:00–02:00. Apologies for any disruption.",
    "Hi all, sharing a write-up on bug-bounty workflows I gave last week. Feedback welcome.",
]


def _load_external_corpus():
    """Pull additional samples from data/corpus/labelled_corpus.jsonl if present."""
    import json
    extra_x, extra_y = [], []
    path = Path("data/corpus/labelled_corpus.jsonl")
    if not path.exists():
        return extra_x, extra_y
    print(f"[corpus] loading {path}")
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            label = rec.get("label")
            text = (rec.get("subject", "") + " " + rec.get("body", "")).strip()
            if not text or label not in {"phish", "ham"}:
                continue
            extra_x.append(text)
            extra_y.append(1 if label == "phish" else 0)
    print(f"[corpus] external samples loaded: phish={extra_y.count(1)} ham={extra_y.count(0)}")
    return extra_x, extra_y


def main():
    load_dotenv()
    X = list(PHISH + HAM)
    y = [1] * len(PHISH) + [0] * len(HAM)

    extra_x, extra_y = _load_external_corpus()
    X.extend(extra_x)
    y.extend(extra_y)
    print(f"Total training samples: {len(X)}  (phish={y.count(1)}  ham={y.count(0)})")

    pipeline = PhishingClassifier.build_pipeline()

    # Stratified split — small corpus so keep test small.
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    pipeline.fit(X_tr, y_tr)
    y_pred = pipeline.predict(X_te)
    print("=== Holdout evaluation ===")
    print(classification_report(y_te, y_pred, digits=3))

    cv_folds = min(5, min(y.count(1), y.count(0)))
    if cv_folds >= 2:
        scores = cross_val_score(pipeline, X, y, cv=cv_folds, scoring="f1")
        print(f"{cv_folds}-fold CV F1: mean={scores.mean():.3f} std={scores.std():.3f}")
    else:
        print("Skipping CV — too few samples per class.")

    # Fit on full dataset for the shipped model.
    pipeline.fit(X, y)
    out = Path(os.getenv("MODEL_PATH", "./data/classifier.joblib"))
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, out)
    print(f"Saved classifier to {out}")


if __name__ == "__main__":
    main()
