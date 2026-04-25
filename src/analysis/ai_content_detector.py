"""AI-generated content detector — statistical + heuristic ensemble.

Uses a battery of textual features rather than a single brittle heuristic.
Each feature is a weak signal; we require ≥ 3 to fire to keep false
positives manageable. This trades sensitivity for precision (which is
what an analyst-facing tool needs).

Features:
  1. LLM boilerplate phrase density
  2. Sentence-length uniformity (low burstiness — human mail varies more)
  3. Vocabulary diversity (type-token ratio) outside human band [0.40, 0.88]
  4. Punctuation regularity — humans use em-dashes, ellipses, exclamations
     idiosyncratically; LLM output is more uniform
  5. Hedge-word density (transitional adverbs: "moreover", "furthermore",
     "consequently", "additionally", "however")
  6. UK-brand context with US-English spelling cues
  7. Excessive politeness markers ("kindly", "please be advised")
  8. Burstiness deficit on word-length variance
"""
from __future__ import annotations

import re
import statistics
from collections import Counter
from typing import List, Optional

from src.models import DetectionFinding, ParsedEmail

_LLM_BOILERPLATE = [
    "i hope this email finds you well",
    "i hope this message finds you well",
    "i hope you're doing well",
    "please do not hesitate to reach out",
    "should you have any questions please do not hesitate",
    "thank you for your understanding and cooperation",
    "we value your trust and continued",
    "your prompt attention to this matter",
    "we kindly request that you",
    "kindly note that",
    "as a valued customer of",
    "in order to ensure the continued",
    "please be advised that",
    "rest assured that",
    "we appreciate your patience",
    "feel free to let me know",
    "i would like to bring to your attention",
    "i wanted to take a moment to",
    "it is imperative that",
]

_HEDGE_TRANSITIONS = [
    "furthermore", "moreover", "additionally", "consequently", "however",
    "nevertheless", "therefore", "subsequently", "in addition", "in conclusion",
    "as such", "in light of", "on the other hand",
]

_POLITENESS = [
    "kindly", "respectfully", "please be advised", "we humbly",
    "at your earliest convenience", "should you require",
]

_US_ENGLISH_TELL = [
    "authorize", "authorization", " organize ", "organization",
    " center ", " color ", "license plate", "zip code",
    "checking account", "routing number", "social security",
    "favorite", "behavior", " labor ", " analyze ",
]

UK_BRAND_CONTEXT = [
    "hmrc", "royal mail", "nhs", "dvla", "dwp", "tv licensing",
    "natwest", "barclays", "lloyds", "hsbc", "halifax", "santander",
    "monzo", "starling", "british gas", "octopus energy", "council tax",
]

_TOKEN_RE = re.compile(r"[a-zA-Z]{2,}")


def _type_token_ratio(text: str) -> float:
    tokens = _TOKEN_RE.findall(text.lower())
    if len(tokens) < 30:
        return 0.5
    return len(set(tokens)) / len(tokens)


def _punctuation_diversity(text: str) -> float:
    puncts = re.findall(r"[—–…!?;:()\"']", text)
    if not puncts:
        return 0.0
    counts = Counter(puncts)
    most = max(counts.values())
    return 1.0 - (most / len(puncts))


class AiContentDetector:
    def __init__(self, rules: dict):
        self.weights = rules.get("scoring", {}).get("weights", {})

    def analyse(self, email: ParsedEmail) -> Optional[DetectionFinding]:
        text = (email.text_body or "").strip()
        if len(text) < 200:
            return None

        lower = text.lower()
        signals: List[str] = []
        feature_scores: dict = {}

        # 1. Boilerplate phrase density
        boiler_hits = [p for p in _LLM_BOILERPLATE if p in lower]
        feature_scores["boilerplate_count"] = len(boiler_hits)
        if len(boiler_hits) >= 2:
            signals.append(f"{len(boiler_hits)} LLM-style boilerplate phrases")

        # 2. Sentence-length burstiness
        sentences = [s for s in re.split(r"[.!?]\s+", text) if s.strip()]
        if len(sentences) >= 6:
            lengths = [len(s.split()) for s in sentences]
            try:
                stdev = statistics.pstdev(lengths)
                mean = statistics.mean(lengths)
                cv = stdev / mean if mean > 0 else 0
                feature_scores["sentence_cv"] = round(cv, 3)
                if cv < 0.35:
                    signals.append(f"uniform sentence length (CV={cv:.2f})")
            except statistics.StatisticsError:
                pass

        # 3. Vocabulary diversity
        ttr = _type_token_ratio(text)
        feature_scores["type_token_ratio"] = round(ttr, 3)
        if ttr < 0.40 or ttr > 0.88:
            signals.append(f"atypical type-token ratio ({ttr:.2f})")

        # 4. Punctuation diversity
        pdiv = _punctuation_diversity(text)
        feature_scores["punctuation_diversity"] = round(pdiv, 3)
        if pdiv < 0.20 and len(text) > 500:
            signals.append(f"low punctuation diversity ({pdiv:.2f})")

        # 5. Hedge / transition density
        hedge_hits = sum(1 for h in _HEDGE_TRANSITIONS if h in lower)
        feature_scores["hedge_count"] = hedge_hits
        if hedge_hits >= 4:
            signals.append(f"{hedge_hits} hedge/transition adverbs")

        # 6. Politeness density
        polite_hits = sum(1 for p in _POLITENESS if p in lower)
        feature_scores["politeness_count"] = polite_hits
        if polite_hits >= 3:
            signals.append(f"{polite_hits} excessive politeness markers")

        # 7. UK brand context with US-English cues
        context = " ".join([
            (email.header.subject or "").lower(),
            (email.header.from_name or "").lower(),
        ])
        if any(b in context for b in UK_BRAND_CONTEXT):
            us_hits = [t.strip() for t in _US_ENGLISH_TELL if t in lower]
            feature_scores["us_english_in_uk_context"] = len(us_hits)
            if us_hits:
                signals.append(
                    f"UK brand context but US-English cues: {us_hits[:3]}"
                )

        # 8. Word-length variance
        words = _TOKEN_RE.findall(text)
        if len(words) >= 100:
            lengths = [len(w) for w in words]
            try:
                wcv = statistics.pstdev(lengths) / statistics.mean(lengths)
                feature_scores["word_length_cv"] = round(wcv, 3)
                if wcv < 0.30:
                    signals.append(f"uniform word lengths (CV={wcv:.2f})")
            except statistics.StatisticsError:
                pass

        if len(signals) < 3:
            return None

        base_weight = self.weights.get("ai_generated_likely", 0.10)
        scaled = min(base_weight * (1 + 0.25 * (len(signals) - 3)), base_weight * 2.0)

        return DetectionFinding(
            detector="ai_content",
            rule="ai_generated_likely",
            weight=round(scaled, 3),
            detail=f"{len(signals)} stylistic indicators of LLM-generated content: "
                   + "; ".join(signals),
            evidence={"signals": signals, "features": feature_scores},
        )
