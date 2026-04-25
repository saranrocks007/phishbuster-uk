"""High-level analysis orchestrator.

Runs all detectors against a ParsedEmail and produces an AnalysisReport
containing the final verdict, severity, IOCs, and findings.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from src.analysis.ai_content_detector import AiContentDetector
from src.analysis.attachment_scanner import AttachmentScanner
from src.analysis.bec_detector import BecDetector
from src.analysis.domain_age import DomainAgeDetector
from src.analysis.header_forensics import analyse_headers
from src.analysis.nlp_classifier import PhishingClassifier
from src.analysis.quishing_detector import QuishingDetector
from src.analysis.threat_intel import ThreatIntelDetector
from src.analysis.uk_lure_detector import UkLureDetector
from src.analysis.url_analyzer import UrlAnalyser
from src.analysis.url_sandbox import UrlSandboxDetector
from src.models import (
    AnalysisReport,
    DetectionFinding,
    IOC,
    IOCType,
    ParsedEmail,
    Severity,
    Verdict,
)
from src.utils import get_logger

log = get_logger("phishbuster.analysis")

CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"


def _load_yaml(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


class AnalysisEngine:
    """Facade that ties all detectors together."""

    def __init__(self,
                 brand_config_path: Optional[Path] = None,
                 rules_path: Optional[Path] = None):
        self.brand_config = _load_yaml(brand_config_path or (CONFIG_DIR / "uk_brands.yaml"))
        self.rules = _load_yaml(rules_path or (CONFIG_DIR / "detection_rules.yaml"))
        self.weights = self.rules.get("scoring", {}).get("weights", {})
        self.severity_bands = self.rules.get("severity_bands", [])

        self.lure = UkLureDetector(self.brand_config, self.rules)
        self.urls = UrlAnalyser(self.rules, set(self.lure.all_brand_domains()))
        self.nlp = PhishingClassifier()
        self.quishing = QuishingDetector(self.rules)
        self.ai_content = AiContentDetector(self.rules)

        # New v2 detectors — each is enabled/disabled by env vars
        self.threat_intel = ThreatIntelDetector(self.weights)
        self.domain_age = DomainAgeDetector(self.weights)
        self.url_sandbox = UrlSandboxDetector(self.weights)
        self.attachments = AttachmentScanner(self.weights)
        self.bec = BecDetector(self.weights)

        self.threshold = float(os.getenv("CLASSIFIER_THRESHOLD", "0.65"))

    # ------------------------------------------------------------------
    def analyse(self, email: ParsedEmail) -> AnalysisReport:
        findings: List[DetectionFinding] = []
        iocs: List[IOC] = []
        mitre: List[str] = []

        # Header forensics + auth
        auth_verdict, header_findings = analyse_headers(email, self.weights)
        findings.extend(header_findings)

        # UK brand lure detection
        lure_findings, brand = self.lure.analyse(email)
        findings.extend(lure_findings)

        # URL analysis
        url_findings, url_iocs = self.urls.analyse(email)
        findings.extend(url_findings)
        iocs.extend(url_iocs)

        # NLP classifier
        nlp_finding, nlp_proba = self.nlp.analyse(email, threshold=0.0)
        # We take the ML finding as an additive signal when above threshold.
        if nlp_proba >= self.threshold and nlp_finding:
            findings.append(nlp_finding)

        # Quishing
        q_findings, q_iocs = self.quishing.analyse(email)
        findings.extend(q_findings)
        iocs.extend(q_iocs)

        # AI content heuristics
        ai_finding = self.ai_content.analyse(email)
        if ai_finding:
            findings.append(ai_finding)

        # ---- v2 detectors (each is gated by env-var feature flag) ----
        ti_findings, ti_iocs = self.threat_intel.analyse(email)
        findings.extend(ti_findings)
        iocs.extend(ti_iocs)

        age_findings, _ = self.domain_age.analyse(email)
        findings.extend(age_findings)

        sb_findings, sb_iocs = self.url_sandbox.analyse(email)
        findings.extend(sb_findings)
        iocs.extend(sb_iocs)

        att_findings, att_iocs = self.attachments.analyse(email)
        findings.extend(att_findings)
        iocs.extend(att_iocs)

        bec_findings, _ = self.bec.analyse(email)
        findings.extend(bec_findings)

        # Always add the From-address as an email IOC.
        if email.header.from_address:
            iocs.append(IOC(
                type=IOCType.EMAIL,
                value=email.header.from_address,
                source_detector="ingestion",
            ))

        # --- MITRE mapping ---
        rule_set = {f.rule for f in findings}
        if any(url_iocs) or "mismatched_url_text" in rule_set:
            mitre.append("T1566.002")
        if email.attachments:
            mitre.append("T1566.001")
        if brand:
            mitre.append("T1656")
        # New v2 mappings
        if rule_set & {"yara_match_malicious", "ti_filehash_known_malicious",
                        "macro_office_with_autoexec"}:
            mitre.append("T1204.002")     # Malicious file user-execution
        if rule_set & {"sender_first_seen", "sender_writing_style_shift",
                        "bec_finance_keywords"}:
            mitre.append("T1534")         # Internal Spearphishing / BEC
        if rule_set & {"ti_url_malicious", "ti_domain_malicious",
                        "sandbox_credential_form"}:
            mitre.append("T1598.003")     # Spearphishing for Information

        # --- Aggregate score ---
        score = min(sum(f.weight for f in findings), 1.0)
        verdict, severity, sla = self._derive_verdict(score)

        summary = self._summarise(email, findings, brand, score, verdict)

        report = AnalysisReport(
            message_id=email.header.message_id,
            received_at=datetime.now(timezone.utc),
            verdict=verdict,
            severity=severity,
            score=round(score, 3),
            sla_minutes=sla,
            findings=findings,
            auth=auth_verdict,
            iocs=iocs,
            brand_impersonated=brand,
            mitre_techniques=list(dict.fromkeys(mitre)),
            summary=summary,
            detected_at=datetime.now(timezone.utc),
        )

        # Update BEC sender baseline (benign messages only — see detector docstring)
        try:
            self.bec.update_baseline(email, verdict)
        except Exception as exc:
            log.warning("bec.update_baseline_failed err=%s", exc)
        log.info(
            "Analysis %s score=%.2f verdict=%s brand=%s sev=%s",
            email.header.message_id, score, verdict, brand, severity,
        )
        return report

    # ------------------------------------------------------------------
    def _derive_verdict(self, score: float) -> tuple[Verdict, Severity, int]:
        # Severity band mapping.
        level = "informational"
        sla = 1440
        for band in self.severity_bands:
            if score < float(band["max"]):
                level = band["level"]
                sla = int(band["sla_minutes"])
                break

        if score >= self.threshold:
            verdict = Verdict.PHISHING
        elif score >= 0.35:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.BENIGN

        sev_map = {
            "informational": Severity.INFORMATIONAL,
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }
        return verdict, sev_map.get(level, Severity.INFORMATIONAL), sla

    # ------------------------------------------------------------------
    def _summarise(
        self,
        email: ParsedEmail,
        findings: List[DetectionFinding],
        brand: Optional[str],
        score: float,
        verdict: Verdict,
    ) -> str:
        top = sorted(findings, key=lambda f: f.weight, reverse=True)[:3]
        top_rules = ", ".join(f.rule for f in top) or "no strong signals"
        brand_part = f" (brand impersonated: {brand})" if brand else ""
        return (
            f"Verdict {verdict.value} with score {score:.2f}{brand_part}. "
            f"Top signals: {top_rules}. From: {email.header.from_address or 'unknown'}, "
            f"Subject: {email.header.subject[:120] if email.header.subject else '(no subject)'}."
        )
