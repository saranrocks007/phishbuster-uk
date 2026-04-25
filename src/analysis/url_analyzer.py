"""URL and domain analysis.

Detects:
  * URL shorteners
  * High-risk TLDs
  * IP-in-URL
  * Homoglyph / confusable characters
  * Typosquats against UK brand registrable domains
  * Mismatched anchor text vs href (HTML bodies)
"""
from __future__ import annotations

import re
import unicodedata
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

import tldextract
from bs4 import BeautifulSoup

from src.models import DetectionFinding, IOC, IOCType, ParsedEmail


# Homoglyph map: characters frequently used to impersonate ASCII letters.
# This is not exhaustive — it covers the high-frequency Cyrillic + Greek
# look-alikes that dominate real-world brand-impersonation domains.
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g",
    "ο": "o", "ρ": "p", "α": "a", "ν": "v",
}


def _confusable_ascii(s: str) -> str:
    """Return `s` with common Cyrillic/Greek look-alikes folded to ASCII."""
    out = []
    for ch in s:
        low = ch.lower()
        out.append(_HOMOGLYPHS.get(low, ch))
    return unicodedata.normalize("NFKC", "".join(out))


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            curr[j] = min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + (ca != cb),
            )
        prev = curr
    return prev[-1]


class UrlAnalyser:
    """Analyses URLs in an email against configured signals."""

    def __init__(self, rules: Dict, brand_domains: Set[str]):
        self.rules = rules
        self.weights = rules.get("scoring", {}).get("weights", {})
        self.high_risk_tlds = {t.lower().lstrip(".") for t in rules.get("high_risk_tlds", [])}
        self.shorteners = {s.lower() for s in rules.get("url_shorteners", [])}
        # Registrable forms of trusted UK brand domains (e.g. "royalmail.com").
        self.brand_registrables: Set[str] = set()
        for d in brand_domains:
            ext = tldextract.extract(d)
            if ext.domain and ext.suffix:
                self.brand_registrables.add(f"{ext.domain}.{ext.suffix}".lower())

    # ------------------------------------------------------------------
    def analyse(self, email: ParsedEmail) -> Tuple[List[DetectionFinding], List[IOC]]:
        findings: List[DetectionFinding] = []
        iocs: List[IOC] = []
        seen: Set[str] = set()

        # Pass 1: iterate URLs.
        for url in email.urls:
            if url in seen:
                continue
            seen.add(url)
            f, i = self._analyse_url(url)
            findings.extend(f)
            iocs.extend(i)

        # Pass 2: mismatched anchor-text URL vs href.
        if email.html_body:
            findings.extend(self._check_anchor_mismatch(email.html_body))

        return findings, iocs

    # ------------------------------------------------------------------
    def _analyse_url(self, url: str) -> Tuple[List[DetectionFinding], List[IOC]]:
        findings: List[DetectionFinding] = []
        iocs: List[IOC] = []

        parsed = urlparse(url if re.match(r"^[a-zA-Z]+://", url) else f"http://{url}")
        host = (parsed.hostname or "").lower()
        if not host:
            return findings, iocs

        ext = tldextract.extract(host)
        registrable = f"{ext.domain}.{ext.suffix}".lower() if ext.domain and ext.suffix else host

        iocs.append(IOC(
            type=IOCType.URL,
            value=url,
            source_detector="url_analyser",
        ))
        iocs.append(IOC(
            type=IOCType.DOMAIN,
            value=registrable,
            source_detector="url_analyser",
        ))

        # IP literal
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            findings.append(DetectionFinding(
                detector="url_analyser", rule="ip_url",
                weight=self.weights.get("ip_url", 0.15),
                detail=f"URL uses raw IP address ({host}).",
                evidence={"url": url},
            ))

        # High-risk TLD
        if ext.suffix and ext.suffix.lower() in self.high_risk_tlds:
            findings.append(DetectionFinding(
                detector="url_analyser", rule="high_risk_tld",
                weight=self.weights.get("high_risk_tld", 0.1),
                detail=f"URL uses high-risk TLD .{ext.suffix}.",
                evidence={"url": url, "tld": ext.suffix},
            ))

        # URL shortener
        if registrable in self.shorteners or host in self.shorteners:
            findings.append(DetectionFinding(
                detector="url_analyser", rule="url_shortener",
                weight=self.weights.get("url_shortener", 0.1),
                detail=f"URL uses a shortener ({registrable}).",
                evidence={"url": url},
            ))

        # Homoglyph
        folded = _confusable_ascii(host)
        if folded != host:
            findings.append(DetectionFinding(
                detector="url_analyser", rule="homoglyph_domain",
                weight=self.weights.get("homoglyph_domain", 0.3),
                detail=f"Host contains confusable characters: {host} (folds to {folded}).",
                evidence={"url": url, "original": host, "folded": folded},
            ))

        # Typosquat vs UK brand registrables (skip if already a legit brand domain)
        if registrable not in self.brand_registrables:
            for brand in self.brand_registrables:
                distance = _levenshtein(registrable, brand)
                if 0 < distance <= 2 and len(brand) >= 6:
                    findings.append(DetectionFinding(
                        detector="url_analyser", rule="typosquat_domain",
                        weight=self.weights.get("typosquat_domain", 0.25),
                        detail=(
                            f"Domain '{registrable}' is within edit distance "
                            f"{distance} of UK brand '{brand}'."
                        ),
                        evidence={"url": url, "brand": brand, "distance": distance},
                    ))
                    break

        return findings, iocs

    # ------------------------------------------------------------------
    def _check_anchor_mismatch(self, html: str) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            text = (a.get_text() or "").strip()
            if not text or not href:
                continue
            # Only act when the anchor text itself looks like a URL or a
            # brand reference — otherwise legitimate CTA buttons trip this.
            if not re.search(r"(?i)https?://|www\.|\.co\.uk|\.com|hmrc|royal mail|nhs|natwest|barclays|lloyds|hsbc|dvla", text):
                continue
            href_host = (urlparse(href).hostname or "").lower()
            text_host_match = re.search(r"(?i)(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", text)
            text_host = text_host_match.group(1).lower() if text_host_match else ""
            if href_host and text_host and text_host not in href_host and href_host not in text_host:
                findings.append(DetectionFinding(
                    detector="url_analyser", rule="mismatched_url_text",
                    weight=self.weights.get("mismatched_url_text", 0.2),
                    detail=f"Anchor text '{text_host}' does not match href host '{href_host}'.",
                    evidence={"text_host": text_host, "href_host": href_host},
                ))
        return findings
