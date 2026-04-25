"""NLP phishing classifier.

Baseline: TF-IDF (word + char n-grams) + Logistic Regression.
This is intentionally small and fast — SOC pipelines need sub-second
per-email inference and easy explainability. Top contributing n-grams
are surfaced as evidence in the finding.

Training corpus is curated UK phishing + ham in `scripts/train_model.py`.
For richer coverage, the class can be swapped for a transformer backbone
without changing callers (same `predict_proba` contract).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Tuple

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from src.models import DetectionFinding, ParsedEmail
from src.utils import get_logger

log = get_logger("phishbuster.nlp")


class PhishingClassifier:
    """Wraps a scikit-learn pipeline with a stable predict_proba interface."""

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or os.getenv(
            "MODEL_PATH", "./data/classifier.joblib"
        )
        self.pipeline: Optional[Pipeline] = None
        self._load()

    # ------------------------------------------------------------------
    @staticmethod
    def build_pipeline() -> Pipeline:
        """Return an untrained pipeline. Exposed so scripts/train_model.py
        uses exactly the same architecture as runtime."""
        word_vec = TfidfVectorizer(
            analyzer="word", ngram_range=(1, 2),
            min_df=1, max_df=0.95, sublinear_tf=True,
            strip_accents="unicode", lowercase=True,
        )
        char_vec = TfidfVectorizer(
            analyzer="char_wb", ngram_range=(3, 5),
            min_df=1, max_df=0.95, sublinear_tf=True, lowercase=True,
        )
        union = FeatureUnion([("word", word_vec), ("char", char_vec)])
        clf = LogisticRegression(max_iter=1000, C=4.0, class_weight="balanced")
        return Pipeline([("features", union), ("clf", clf)])

    # ------------------------------------------------------------------
    def _load(self) -> None:
        path = Path(self.model_path)
        if path.exists():
            try:
                self.pipeline = joblib.load(path)
                log.info("Loaded classifier from %s", path)
            except Exception as e:
                log.warning("Failed to load classifier %s: %s", path, e)
                self.pipeline = None
        else:
            log.warning(
                "Classifier model not found at %s — run scripts/train_model.py. "
                "Falling back to neutral NLP score (0.0).", path
            )

    # ------------------------------------------------------------------
    def is_ready(self) -> bool:
        return self.pipeline is not None

    # ------------------------------------------------------------------
    def predict(self, email: ParsedEmail) -> Tuple[float, List[str]]:
        """Return (phishing_probability, top_tokens)."""
        if not self.pipeline:
            return 0.0, []
        text = self._featurise(email)
        try:
            proba = float(self.pipeline.predict_proba([text])[0][1])
        except Exception as e:
            log.warning("Classifier prediction failed: %s", e)
            return 0.0, []
        top_tokens = self._top_tokens(text, k=6)
        return proba, top_tokens

    # ------------------------------------------------------------------
    def analyse(
        self, email: ParsedEmail, threshold: float
    ) -> Tuple[Optional[DetectionFinding], float]:
        """Integrate with the orchestrator: return a finding if above threshold."""
        proba, tokens = self.predict(email)
        if proba >= threshold:
            finding = DetectionFinding(
                detector="nlp_classifier",
                rule="ml_phishing_probability",
                weight=min(proba, 0.5),  # cap influence on the aggregate
                detail=(
                    f"ML classifier rates this message as phishing with "
                    f"probability {proba:.2f}."
                ),
                evidence={"probability": proba, "top_tokens": tokens},
            )
            return finding, proba
        return None, proba

    # ------------------------------------------------------------------
    @staticmethod
    def _featurise(email: ParsedEmail) -> str:
        return " ".join([
            email.header.subject or "",
            email.header.from_name or "",
            email.text_body or "",
        ]).strip()

    # ------------------------------------------------------------------
    def _top_tokens(self, text: str, k: int = 6) -> List[str]:
        """Return the top-k word-n-gram features that most increased
        the phishing score for this message."""
        if not self.pipeline:
            return []
        try:
            union: FeatureUnion = self.pipeline.named_steps["features"]
            clf: LogisticRegression = self.pipeline.named_steps["clf"]
            word_vec: TfidfVectorizer = dict(union.transformer_list)["word"]
            x = word_vec.transform([text])
            coefs = clf.coef_[0][: x.shape[1]]
            # Contributions = coefficient * tf-idf value.
            contrib = x.multiply(coefs).toarray()[0]
            top_idx = np.argsort(contrib)[::-1][:k]
            vocab = word_vec.get_feature_names_out()
            return [vocab[i] for i in top_idx if contrib[i] > 0]
        except Exception:
            return []
