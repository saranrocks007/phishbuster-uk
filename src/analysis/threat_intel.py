"""Threat-intelligence enrichment for URLs, domains, IPs and file hashes.

Vendors integrated:
  • VirusTotal v3      (URLs, domains, file hashes, IPs)        — API key required
  • AbuseIPDB v2       (IP reputation)                          — API key required
  • URLhaus (abuse.ch) (live malware-distribution URLs)         — free, optional auth
  • PhishTank          (verified phishing URL list)             — free, optional auth

Design principles:
  • Fail-open: if a vendor is offline / unauthorised / rate-limited, we
    log a warning and skip it. We never block the pipeline on a 3rd-party
    flake.
  • All lookups are cached in SQLite for THREAT_INTEL_CACHE_TTL_HOURS.
  • Findings are emitted with severity proportional to vendor consensus.
  • Quota-respecting: VirusTotal free is 4/min, 500/day — we deduplicate
    same-URL-per-message and skip if the cache is fresh.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
import tldextract

from src.models import DetectionFinding, IOC, IOCType, ParsedEmail
from src.utils import get_logger
from src.utils.cache import cache_get, cache_put

log = get_logger(__name__)


def _is_enabled() -> bool:
    return os.getenv("ENABLE_THREAT_INTEL", "false").lower() == "true"


def _hostname(url: str) -> Optional[str]:
    try:
        host = urlparse(url).hostname
        return host.lower() if host else None
    except Exception:
        return None


def _registered_domain(host: str) -> Optional[str]:
    if not host:
        return None
    parts = tldextract.extract(host)
    if parts.registered_domain:
        return parts.registered_domain.lower()
    return None


# ============================================================ VENDORS

class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client = httpx.Client(
            timeout=10.0,
            headers={"x-apikey": api_key, "Accept": "application/json"},
        )

    def lookup_url(self, url: str) -> Optional[Dict[str, Any]]:
        # VT v3 needs URL identifier = base64(url) without padding
        import base64
        ident = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            r = self._client.get(f"{self.BASE}/urls/{ident}")
            if r.status_code == 200:
                return r.json().get("data", {}).get("attributes", {})
            if r.status_code == 404:
                return {"_unseen": True}
        except httpx.HTTPError as exc:
            log.warning("vt.url_lookup_failed url_hash=%s err=%s",
                        hashlib.sha256(url.encode()).hexdigest()[:12], exc)
        return None

    def lookup_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        try:
            r = self._client.get(f"{self.BASE}/domains/{domain}")
            if r.status_code == 200:
                return r.json().get("data", {}).get("attributes", {})
        except httpx.HTTPError as exc:
            log.warning("vt.domain_lookup_failed domain=%s err=%s", domain, exc)
        return None

    def lookup_filehash(self, sha256: str) -> Optional[Dict[str, Any]]:
        try:
            r = self._client.get(f"{self.BASE}/files/{sha256}")
            if r.status_code == 200:
                return r.json().get("data", {}).get("attributes", {})
            if r.status_code == 404:
                return {"_unseen": True}
        except httpx.HTTPError as exc:
            log.warning("vt.file_lookup_failed sha=%s err=%s", sha256[:12], exc)
        return None

    @staticmethod
    def malicious_count(attrs: Dict[str, Any]) -> int:
        stats = attrs.get("last_analysis_stats", {}) or {}
        return int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))


class AbuseIpdbClient:
    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self._client = httpx.Client(
            timeout=10.0,
            headers={"Key": api_key, "Accept": "application/json"},
        )

    def check(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            r = self._client.get(
                f"{self.BASE}/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            if r.status_code == 200:
                return r.json().get("data", {})
        except httpx.HTTPError as exc:
            log.warning("abuseipdb.lookup_failed ip=%s err=%s", ip, exc)
        return None


class UrlhausClient:
    """abuse.ch URLhaus — JSON API, no key required for basic lookups."""
    URL = "https://urlhaus-api.abuse.ch/v1/url/"
    HOST = "https://urlhaus-api.abuse.ch/v1/host/"

    def __init__(self, auth_key: str = ""):
        headers = {"Accept": "application/json"}
        if auth_key:
            headers["Auth-Key"] = auth_key
        self._client = httpx.Client(timeout=8.0, headers=headers)

    def lookup_url(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            r = self._client.post(self.URL, data={"url": url})
            if r.status_code == 200:
                data = r.json()
                if data.get("query_status") == "ok":
                    return data
        except httpx.HTTPError as exc:
            log.warning("urlhaus.url_lookup_failed err=%s", exc)
        return None

    def lookup_host(self, host: str) -> Optional[Dict[str, Any]]:
        try:
            r = self._client.post(self.HOST, data={"host": host})
            if r.status_code == 200:
                data = r.json()
                if data.get("query_status") == "ok":
                    return data
        except httpx.HTTPError as exc:
            log.warning("urlhaus.host_lookup_failed err=%s", exc)
        return None


class PhishTankClient:
    """PhishTank verified phish URL lookup. Optional username for higher rate."""
    BASE = "https://checkurl.phishtank.com/checkurl/"

    def __init__(self, username: str = ""):
        self.username = username or "phishbuster-uk"
        self._client = httpx.Client(
            timeout=8.0,
            headers={"User-Agent": f"phishtank/{self.username}"},
        )

    def lookup(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            r = self._client.post(
                self.BASE,
                data={"url": url, "format": "json"},
            )
            if r.status_code == 200 and r.headers.get("content-type", "").startswith("application/json"):
                return r.json().get("results", {})
        except httpx.HTTPError as exc:
            log.warning("phishtank.lookup_failed err=%s", exc)
        return None


# ============================================================ DETECTOR

class ThreatIntelDetector:
    """Aggregates multi-vendor TI signals into findings & IOCs."""

    def __init__(self, weights: Dict[str, float]):
        self.weights = weights
        self.vt = (VirusTotalClient(os.getenv("VIRUSTOTAL_API_KEY", ""))
                   if os.getenv("VIRUSTOTAL_API_KEY") else None)
        self.aip = (AbuseIpdbClient(os.getenv("ABUSEIPDB_API_KEY", ""))
                    if os.getenv("ABUSEIPDB_API_KEY") else None)
        self.urlhaus = UrlhausClient(os.getenv("URLHAUS_AUTH_KEY", ""))   # always available
        self.phishtank = PhishTankClient(os.getenv("PHISHTANK_USERNAME", ""))

    # ------------------------------------------------------------ public
    def analyse(self, email: ParsedEmail) -> Tuple[List[DetectionFinding], List[IOC]]:
        if not _is_enabled():
            return [], []

        findings: List[DetectionFinding] = []
        iocs: List[IOC] = []

        seen_urls: set = set()
        seen_domains: set = set()

        for url in email.urls[:25]:                           # cap per message
            if url in seen_urls:
                continue
            seen_urls.add(url)
            self._enrich_url(url, findings, iocs)

            host = _hostname(url)
            domain = _registered_domain(host) if host else None
            if domain and domain not in seen_domains:
                seen_domains.add(domain)
                self._enrich_domain(domain, findings, iocs)

        # File-hash lookups for attachments
        for att in (email.attachments or [])[:10]:
            if att.sha256:
                self._enrich_filehash(att.sha256, att.filename or "?", findings, iocs)

        return findings, iocs

    # ------------------------------------------------------------ helpers
    def _cached(self, ns: str, key: str, fetch):
        hit = cache_get(ns, key)
        if hit is not None:
            return hit
        result = fetch()
        if result is not None:
            cache_put(ns, key, result)
        return result

    def _enrich_url(self, url: str,
                    findings: List[DetectionFinding],
                    iocs: List[IOC]) -> None:
        verdicts = []   # list of (vendor, malicious_bool, detail)

        # URLhaus
        uh = self._cached("urlhaus_url", url, lambda: self.urlhaus.lookup_url(url))
        if uh and uh.get("threat"):
            verdicts.append(("URLhaus", True,
                             f"threat={uh.get('threat')} status={uh.get('url_status')}"))

        # PhishTank
        pt = self._cached("phishtank", url, lambda: self.phishtank.lookup(url))
        if pt and pt.get("in_database") and pt.get("valid"):
            verdicts.append(("PhishTank", True, "verified phish"))

        # VirusTotal (only if configured)
        if self.vt:
            vt_attrs = self._cached("vt_url", url, lambda: self.vt.lookup_url(url))
            if vt_attrs and not vt_attrs.get("_unseen"):
                mal = self.vt.malicious_count(vt_attrs)
                if mal >= 1:
                    verdicts.append(("VirusTotal", mal >= 3,
                                     f"{mal} engines flag URL"))

        if not verdicts:
            return

        malicious = any(m for _, m, _ in verdicts)
        rule = "ti_url_malicious" if malicious else "ti_url_suspicious"
        weight = self.weights.get(rule, 0.4 if malicious else 0.2)
        detail = "; ".join(f"{v}: {d}" for v, _, d in verdicts)

        findings.append(DetectionFinding(
            detector="threat_intel",
            rule=rule, weight=weight,
            detail=f"URL flagged by threat intel ({detail})",
        ))
        iocs.append(IOC(
            type=IOCType.URL, value=url,
            source_detector="threat_intel",
            tags=[v for v, _, _ in verdicts],
        ))

    def _enrich_domain(self, domain: str,
                       findings: List[DetectionFinding],
                       iocs: List[IOC]) -> None:
        verdicts = []

        uh = self._cached("urlhaus_host", domain,
                          lambda: self.urlhaus.lookup_host(domain))
        if uh and uh.get("url_count") and int(uh.get("url_count", 0)) >= 1:
            verdicts.append(("URLhaus", True,
                             f"{uh.get('url_count')} malware URLs on host"))

        if self.vt:
            vt_attrs = self._cached("vt_domain", domain,
                                    lambda: self.vt.lookup_domain(domain))
            if vt_attrs:
                mal = self.vt.malicious_count(vt_attrs)
                if mal >= 2:
                    verdicts.append(("VirusTotal", True,
                                     f"{mal} engines flag domain"))

        if not verdicts:
            return

        rule = "ti_domain_malicious"
        weight = self.weights.get(rule, 0.35)
        detail = "; ".join(f"{v}: {d}" for v, _, d in verdicts)
        findings.append(DetectionFinding(
            detector="threat_intel",
            rule=rule, weight=weight,
            detail=f"Domain '{domain}' has TI hits ({detail})",
        ))
        iocs.append(IOC(
            type=IOCType.DOMAIN, value=domain,
            source_detector="threat_intel",
            tags=[v for v, _, _ in verdicts],
        ))

    def _enrich_filehash(self, sha256: str, filename: str,
                         findings: List[DetectionFinding],
                         iocs: List[IOC]) -> None:
        if not self.vt:
            return
        attrs = self._cached("vt_file", sha256,
                             lambda: self.vt.lookup_filehash(sha256))
        if not attrs or attrs.get("_unseen"):
            return
        mal = self.vt.malicious_count(attrs)
        if mal < 3:
            return
        rule = "ti_filehash_known_malicious"
        weight = self.weights.get(rule, 0.45)
        findings.append(DetectionFinding(
            detector="threat_intel",
            rule=rule, weight=weight,
            detail=f"Attachment '{filename}' flagged malicious by {mal} engines",
        ))
        iocs.append(IOC(
            type=IOCType.FILE_HASH, value=sha256,
            source_detector="threat_intel",
            tags=["VirusTotal", filename],
        ))

    # ------------------------------------------------------------ IP helper
    def check_ip(self, ip: str) -> Optional[DetectionFinding]:
        """Standalone IP lookup — useful for sender-IP forensics."""
        if not _is_enabled() or not self.aip:
            return None
        data = self._cached("abuseipdb", ip, lambda: self.aip.check(ip))
        if not data:
            return None
        score = int(data.get("abuseConfidenceScore", 0) or 0)
        if score < 75:
            return None
        return DetectionFinding(
            detector="threat_intel",
            rule="ti_ip_abuse",
            weight=self.weights.get("ti_ip_abuse", 0.25),
            detail=f"AbuseIPDB confidence={score}% reports={data.get('totalReports', 0)}",
        )
