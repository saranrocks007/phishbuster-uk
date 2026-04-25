"""Domain age detection via WHOIS.

Newly-registered domains (≤ N days) are a strong phishing signal: the
overwhelming majority of legitimate brand domains are years old, while
phishing infrastructure churns weekly.

Uses python-whois with aggressive caching. Failures are silent — WHOIS
servers throttle aggressively and many TLDs (.uk in particular) return
inconsistent formats.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Set

import tldextract

from src.models import DetectionFinding, ParsedEmail
from src.utils import get_logger
from src.utils.cache import cache_get, cache_put

log = get_logger(__name__)

# Long TTL — domain creation dates don't change.
_AGE_CACHE_NAMESPACE = "domain_age"
_AGE_CACHE_TTL = 30 * 86400          # 30 days


def _is_enabled() -> bool:
    return os.getenv("ENABLE_DOMAIN_AGE_CHECK", "true").lower() == "true"


def _registered_domain(host: str) -> Optional[str]:
    if not host:
        return None
    parts = tldextract.extract(host)
    return parts.registered_domain.lower() if parts.registered_domain else None


def _to_datetime(value) -> Optional[datetime]:
    """Normalise WHOIS creation_date — can be datetime, list, or None."""
    if value is None:
        return None
    if isinstance(value, list):
        # Multiple entries — take the earliest
        candidates = [_to_datetime(v) for v in value]
        candidates = [c for c in candidates if c]
        return min(candidates) if candidates else None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


class DomainAgeDetector:
    """Flags URLs whose registered domain was created very recently."""

    def __init__(self, weights: dict, recent_days: Optional[int] = None):
        self.weights = weights
        self.recent_days = int(recent_days or os.getenv("DOMAIN_AGE_RECENT_DAYS", "30"))

    # ------------------------------------------------------------------ public
    def analyse(self, email: ParsedEmail) -> Tuple[List[DetectionFinding], List]:
        if not _is_enabled():
            return [], []
        findings: List[DetectionFinding] = []
        seen: Set[str] = set()

        # Sender domain first
        if email.header.from_address and "@" in email.header.from_address:
            sender_host = email.header.from_address.split("@", 1)[1]
            domain = _registered_domain(sender_host)
            if domain and domain not in seen:
                seen.add(domain)
                f = self._check_domain(domain, source="sender")
                if f:
                    findings.append(f)

        # URL domains
        for url in email.urls[:25]:
            from urllib.parse import urlparse
            try:
                host = urlparse(url).hostname
            except Exception:
                continue
            domain = _registered_domain(host) if host else None
            if not domain or domain in seen:
                continue
            seen.add(domain)
            f = self._check_domain(domain, source="url")
            if f:
                findings.append(f)

        return findings, []

    # ------------------------------------------------------------------ helpers
    def _check_domain(self, domain: str, source: str) -> Optional[DetectionFinding]:
        creation = self._lookup_creation_date(domain)
        if not creation:
            return None
        age_days = (datetime.now(timezone.utc) - creation).days
        if age_days < 0 or age_days > self.recent_days:
            return None
        weight = self.weights.get("newly_registered", 0.15)
        return DetectionFinding(
            detector="domain_age",
            rule="newly_registered",
            weight=weight,
            detail=f"Domain '{domain}' ({source}) registered {age_days}d ago "
                   f"(threshold {self.recent_days}d).",
        )

    def _lookup_creation_date(self, domain: str) -> Optional[datetime]:
        cached = cache_get(_AGE_CACHE_NAMESPACE, domain, ttl=_AGE_CACHE_TTL)
        if cached is not None:
            try:
                return datetime.fromisoformat(cached) if cached else None
            except (TypeError, ValueError):
                return None

        # Lazy import to keep startup fast and the dep optional
        try:
            import whois
        except ImportError:
            log.warning("python-whois not installed; domain age check disabled.")
            return None

        try:
            data = whois.whois(domain)
            created = _to_datetime(getattr(data, "creation_date", None))
            cache_put(_AGE_CACHE_NAMESPACE, domain,
                      created.isoformat() if created else "")
            return created
        except Exception as exc:
            # WHOIS frequently throws on rate-limit, parser errors, .uk quirks.
            log.debug("whois.lookup_failed domain=%s err=%s", domain, exc)
            cache_put(_AGE_CACHE_NAMESPACE, domain, "")  # negative cache short-term
            return None
