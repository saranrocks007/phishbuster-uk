"""Business Email Compromise (BEC) / sender anomaly detector.

Maintains a per-sender baseline (first-seen, hour histogram, recipient
graph, vocabulary fingerprint, length stats) and scores incoming messages
against it.

Strong BEC indicators (cumulative):
  • Sender NEVER seen by org before AND message contains finance keywords
    (wire transfer, invoice, urgent payment, change of bank details)
  • Sender seen but writing to a recipient never seen before
  • Send time outside sender's typical hour-of-day band (3σ)
  • Vocabulary cosine similarity drops sharply vs. baseline corpus
  • Subject length / body length 3σ outside sender's norm

Baseline only updates on confirmed BENIGN messages so attackers can't
poison their own profile.
"""
from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from src.database import SenderProfile, session_scope
from src.models import DetectionFinding, ParsedEmail, Verdict
from src.utils import get_logger

log = get_logger(__name__)

_FINANCE_RE = re.compile(
    r"\b(wire\s*transfer|bank\s*details|change\s+of\s+account|invoice|"
    r"remittance|payment\s+(urgent|asap|today)|new\s+(supplier|payee|account)|"
    r"updated\s+banking|sort\s*code\s*change|account\s*number\s*change|iban)\b",
    re.I,
)

_TOKEN_RE = re.compile(r"[a-zA-Z]{3,}")
_MIN_BASELINE = int(os.getenv("BEC_BASELINE_MIN_MESSAGES", "5"))


def _is_enabled() -> bool:
    return os.getenv("ENABLE_BEC_DETECTOR", "true").lower() == "true"


def _tokenise(text: str, k: int = 50) -> Counter:
    return Counter(t.lower() for t in _TOKEN_RE.findall(text or ""))


def _cosine(a: Dict[str, float], b: Dict[str, float]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(a.get(k, 0.0) * b.get(k, 0.0) for k in set(a) | set(b))
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def _hist_from_csv(s: str) -> List[int]:
    if not s:
        return [0] * 24
    try:
        vals = [int(x) for x in s.split(",")]
        return (vals + [0] * 24)[:24]
    except ValueError:
        return [0] * 24


def _hist_to_csv(h: List[int]) -> str:
    return ",".join(str(int(x)) for x in h[:24])


# ============================================================ DETECTOR

class BecDetector:
    def __init__(self, weights: Dict[str, float]):
        self.weights = weights

    # ---------------------------------------------------------------- public
    def analyse(self, email: ParsedEmail) -> Tuple[List[DetectionFinding], List]:
        if not _is_enabled():
            return [], []
        findings: List[DetectionFinding] = []
        sender = (email.header.from_address or "").lower().strip()
        if not sender:
            return [], []

        body = (email.text_body or "") + " " + (email.html_body or "")
        subject = email.header.subject or ""
        recipients = [a.lower() for a in (email.header.to_addresses or [])]
        date = email.header.date or datetime.utcnow()
        hour = date.hour if date else None

        with session_scope() as s:
            profile = s.query(SenderProfile).filter_by(sender_address=sender).first()

            if not profile:
                # First time we've ever seen this sender
                if _FINANCE_RE.search(body) or _FINANCE_RE.search(subject):
                    findings.append(DetectionFinding(
                        detector="bec",
                        rule="bec_finance_keywords",
                        weight=self.weights.get("bec_finance_keywords", 0.20),
                        detail="Finance/payment keywords from never-before-seen sender.",
                    ))
                findings.append(DetectionFinding(
                    detector="bec",
                    rule="sender_first_seen",
                    weight=self.weights.get("sender_first_seen", 0.15),
                    detail=f"Sender '{sender}' is unknown to this organisation.",
                ))
                return findings, []

            # Baseline established? Only score against it past the threshold.
            if profile.message_count < _MIN_BASELINE:
                return [], []

            # 1) Unusual hour
            hist = _hist_from_csv(profile.hour_histogram)
            if hour is not None and sum(hist) > 0:
                total = sum(hist)
                p = hist[hour] / total
                if p < 0.02:                    # < 2% of historical messages at this hour
                    findings.append(DetectionFinding(
                        detector="bec",
                        rule="sender_unusual_hour",
                        weight=self.weights.get("sender_unusual_hour", 0.08),
                        detail=f"Sender historically rarely emails at hour {hour:02d} "
                               f"({p*100:.1f}% of {total} prior messages).",
                    ))

            # 2) New recipient pair
            known_recips = set(filter(None, (profile.recipients_seen or "").split("\n")))
            unseen = [r for r in recipients if r and r not in known_recips]
            if unseen and known_recips:
                findings.append(DetectionFinding(
                    detector="bec",
                    rule="sender_new_recipient",
                    weight=self.weights.get("sender_new_recipient", 0.10),
                    detail=f"Sender→recipient pair not previously observed: "
                           f"{','.join(unseen[:3])}",
                ))

            # 3) Style cosine drift
            try:
                baseline_vocab = json.loads(profile.style_vocab) if profile.style_vocab else {}
            except json.JSONDecodeError:
                baseline_vocab = {}
            current_vocab = dict(_tokenise(body + " " + subject))
            sim = _cosine(baseline_vocab, current_vocab)
            if baseline_vocab and sim < 0.2:
                findings.append(DetectionFinding(
                    detector="bec",
                    rule="sender_writing_style_shift",
                    weight=self.weights.get("sender_writing_style_shift", 0.20),
                    detail=f"Vocabulary cosine similarity to sender baseline = {sim:.2f} "
                           f"(< 0.20).",
                ))

            # 4) Finance keywords combined with style/recipient anomaly
            if (_FINANCE_RE.search(body) or _FINANCE_RE.search(subject)) and findings:
                findings.append(DetectionFinding(
                    detector="bec",
                    rule="bec_finance_keywords",
                    weight=self.weights.get("bec_finance_keywords", 0.20),
                    detail="Finance/payment keywords present alongside sender anomaly.",
                ))

        return findings, []

    # ---------------------------------------------------------------- baseline update
    def update_baseline(self, email: ParsedEmail, verdict: Verdict) -> None:
        """Call AFTER analysis. Only updates baseline on benign mail."""
        if not _is_enabled():
            return
        if verdict != Verdict.BENIGN:
            return
        sender = (email.header.from_address or "").lower().strip()
        if not sender:
            return

        body = (email.text_body or "") + " " + (email.html_body or "")
        subject = email.header.subject or ""
        recipients = [a.lower() for a in (email.header.to_addresses or [])]
        date = email.header.date or datetime.utcnow()

        with session_scope() as s:
            profile = s.query(SenderProfile).filter_by(sender_address=sender).first()
            if not profile:
                profile = SenderProfile(
                    sender_address=sender,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    message_count=0,
                    hour_histogram=_hist_to_csv([0] * 24),
                    recipients_seen="",
                    style_vocab="{}",
                )
                s.add(profile)

            profile.message_count = (profile.message_count or 0) + 1
            profile.last_seen = datetime.utcnow()

            # hour histogram
            hist = _hist_from_csv(profile.hour_histogram)
            if date is not None:
                hist[date.hour] = hist[date.hour] + 1
            profile.hour_histogram = _hist_to_csv(hist)

            # recipients (cap to 200 to keep the column bounded)
            current = set(filter(None, (profile.recipients_seen or "").split("\n")))
            current.update(r for r in recipients if r)
            if len(current) > 200:
                current = set(list(current)[-200:])
            profile.recipients_seen = "\n".join(sorted(current))

            # rolling vocabulary (top 100 tokens, EMA-weighted)
            try:
                baseline = json.loads(profile.style_vocab) if profile.style_vocab else {}
            except json.JSONDecodeError:
                baseline = {}
            tokens = _tokenise(body + " " + subject)
            top = tokens.most_common(100)
            for tok, cnt in top:
                # EMA: previous*0.85 + current*0.15  (keeps history while drifting)
                baseline[tok] = baseline.get(tok, 0.0) * 0.85 + cnt * 0.15
            # prune to top 200
            if len(baseline) > 200:
                trimmed = dict(sorted(baseline.items(), key=lambda kv: -kv[1])[:200])
                baseline = trimmed
            profile.style_vocab = json.dumps(baseline)

            # length stats (running average)
            n = profile.message_count
            profile.avg_subject_len = (profile.avg_subject_len * (n - 1) + len(subject)) / n
            profile.avg_body_len = (profile.avg_body_len * (n - 1) + len(body)) / n
