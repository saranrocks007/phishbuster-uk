"""UK-specific lure detector.

For each configured UK brand, score:
  * Display-name alias match in From:
  * From-domain legitimacy (against brand's legitimate_domains list)
  * Body/subject keyword density

The core signal this catches (and that most global tools miss) is:
  From-name is "HMRC" or "Royal Mail", body talks about tax refunds
  or missed parcels, but the From-domain is something like
  secure-gov.xyz or parcel-rescheduling.top.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

import tldextract

from src.models import DetectionFinding, ParsedEmail


def _domain_of(address: str) -> str:
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().strip(">").lower()


def _registrable(domain: str) -> str:
    ext = tldextract.extract(domain)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return domain.lower()


class UkLureDetector:
    """Brand-impersonation detector keyed on the uk_brands.yaml config."""

    def __init__(self, brand_config: Dict, rules: Dict):
        self.brands: Dict[str, Dict] = brand_config.get("brands", {}) or {}
        self.suspicious_phrases: List[str] = [
            p.lower() for p in (brand_config.get("suspicious_phrases") or [])
        ]
        self.weights = rules.get("scoring", {}).get("weights", {})
        self.urgency_terms: List[str] = [
            t.lower() for t in rules.get("urgency_terms", [])
        ]
        self.credential_request_terms: List[str] = [
            t.lower() for t in rules.get("credential_request_terms", [])
        ]

    # ------------------------------------------------------------------
    def all_brand_domains(self) -> List[str]:
        domains: List[str] = []
        for b in self.brands.values():
            domains.extend(b.get("legitimate_domains", []) or [])
        return domains

    # ------------------------------------------------------------------
    def analyse(
        self, email: ParsedEmail
    ) -> Tuple[List[DetectionFinding], Optional[str]]:
        findings: List[DetectionFinding] = []
        content = " ".join([
            email.header.subject or "",
            email.header.from_name or "",
            email.text_body or "",
        ]).lower()

        from_domain = _domain_of(email.header.from_address)
        from_reg = _registrable(from_domain)
        from_name = (email.header.from_name or "").lower()

        best_brand: Optional[str] = None
        best_score: float = 0.0

        for key, b in self.brands.items():
            aliases = [a.lower() for a in b.get("display_aliases", []) or []]
            keywords = [k.lower() for k in b.get("keywords", []) or []]
            legit = [d.lower() for d in b.get("legitimate_domains", []) or []]
            severity = float(b.get("severity", 1.0))

            # Display-name alias match in From-name?
            alias_hit = any(a in from_name for a in aliases) if from_name else False

            # From-domain legitimacy check.
            domain_legit = any(
                from_reg == d or from_reg.endswith("." + d) or from_reg == _registrable(d)
                for d in legit
            )

            # Keyword density in body/subject.
            kw_hits = [k for k in keywords if k in content]
            kw_hit_count = len(kw_hits)

            # Score this brand.
            local_score = 0.0

            if alias_hit and not domain_legit:
                # Display-name impersonation with non-aligned domain.
                weight = self.weights.get("display_name_spoof", 0.25) * severity
                findings.append(DetectionFinding(
                    detector="uk_lure", rule="display_name_spoof",
                    weight=weight,
                    detail=(
                        f"From-name impersonates {b.get('name', key)} "
                        f"(alias hit) but From-domain '{from_reg}' is not in the "
                        f"brand's legitimate sending domains."
                    ),
                    evidence={"brand": key, "from_domain": from_reg,
                              "aliases_matched": [a for a in aliases if a in from_name]},
                ))
                local_score += weight

            if kw_hit_count >= 2:
                weight = self.weights.get("uk_lure_match", 0.25) * severity
                findings.append(DetectionFinding(
                    detector="uk_lure", rule="uk_lure_match",
                    weight=weight,
                    detail=(
                        f"Body/subject contains {kw_hit_count} {b.get('name', key)} "
                        f"lure keywords: {kw_hits[:4]}."
                    ),
                    evidence={"brand": key, "keywords_hit": kw_hits},
                ))
                local_score += weight

            if local_score > best_score:
                best_score = local_score
                best_brand = b.get("name", key)

        # --- Generic UK phishing phrase heuristics ---
        phrase_hits = [p for p in self.suspicious_phrases if p in content]
        if phrase_hits:
            per = self.weights.get("suspicious_phrase", 0.05)
            total = min(per * len(phrase_hits), 0.2)
            findings.append(DetectionFinding(
                detector="uk_lure", rule="suspicious_phrase",
                weight=total,
                detail=f"{len(phrase_hits)} suspicious phrase(s) detected.",
                evidence={"phrases": phrase_hits[:6]},
            ))

        # --- Urgency language ---
        urgency_hits = [t for t in self.urgency_terms if t in content]
        if urgency_hits:
            findings.append(DetectionFinding(
                detector="uk_lure", rule="urgency_language",
                weight=self.weights.get("urgency_language", 0.1),
                detail=f"Urgency language present: {urgency_hits[:4]}.",
                evidence={"terms": urgency_hits},
            ))

        # --- Credential request ---
        cred_hits = [t for t in self.credential_request_terms if t in content]
        if cred_hits or self._has_credential_form(email.html_body):
            findings.append(DetectionFinding(
                detector="uk_lure", rule="credential_form",
                weight=self.weights.get("credential_form", 0.25),
                detail="Message requests credentials or contains a credential form.",
                evidence={"terms": cred_hits},
            ))

        return findings, best_brand

    # ------------------------------------------------------------------
    def _has_credential_form(self, html: str) -> bool:
        if not html:
            return False
        # Cheap regex-based check; the anchor-mismatch detector uses BS4.
        return bool(
            re.search(r"(?i)<input[^>]+type\s*=\s*['\"]?(password|tel|email)['\"]?", html)
            and re.search(r"(?i)<form\b", html)
        )
