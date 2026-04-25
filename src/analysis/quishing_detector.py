"""Quishing detector — QR-code phishing.

UK-specific context: Royal Mail "missed delivery" cards with QR codes
and QR-code parking-meter scams drove a 2024–2025 UK spike. QR codes
in legitimate business mail from HMRC / Royal Mail / NHS are rare at
the inbound-mail level, so a QR whose resolved URL lands on a newly-
registered domain or a non-brand-aligned host is a very strong signal.
"""
from __future__ import annotations

import io
import re
from typing import List, Tuple
from urllib.parse import urlparse

from src.models import DetectionFinding, IOC, IOCType, ParsedEmail


class QuishingDetector:
    def __init__(self, rules: dict):
        self.weights = rules.get("scoring", {}).get("weights", {})
        self._backend = None
        self._pil = None
        try:
            from PIL import Image  # type: ignore
            from pyzbar import pyzbar  # type: ignore
            self._pil = Image
            self._backend = pyzbar
        except Exception:
            # Detector degrades gracefully when optional deps aren't installed.
            self._backend = None

    # ------------------------------------------------------------------
    def is_ready(self) -> bool:
        return self._backend is not None

    # ------------------------------------------------------------------
    def analyse(self, email: ParsedEmail) -> Tuple[List[DetectionFinding], List[IOC]]:
        findings: List[DetectionFinding] = []
        iocs: List[IOC] = []
        if not self.is_ready() or not email.images:
            return findings, iocs

        for idx, image_bytes in enumerate(email.images):
            urls = self._decode_qrs(image_bytes)
            for u in urls:
                if not re.match(r"(?i)^https?://", u):
                    continue
                host = (urlparse(u).hostname or "").lower()
                if not host:
                    continue
                iocs.append(IOC(
                    type=IOCType.URL, value=u,
                    source_detector="quishing",
                    tags=["quishing"],
                ))
                findings.append(DetectionFinding(
                    detector="quishing",
                    rule="qr_code_to_suspicious",
                    weight=self.weights.get("qr_code_to_suspicious", 0.3),
                    detail=(
                        f"QR code in attachment/image resolves to {u}. "
                        f"Legitimate UK government / Royal Mail mail rarely "
                        f"embeds QR links to external hosts."
                    ),
                    evidence={"image_index": idx, "url": u, "host": host},
                ))
        return findings, iocs

    # ------------------------------------------------------------------
    def _decode_qrs(self, image_bytes: bytes) -> List[str]:
        if not self._backend or not self._pil:
            return []
        try:
            img = self._pil.open(io.BytesIO(image_bytes))
        except Exception:
            return []
        out: List[str] = []
        try:
            for sym in self._backend.decode(img):
                try:
                    data = sym.data.decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if data:
                    out.append(data.strip())
        except Exception:
            return []
        return out
