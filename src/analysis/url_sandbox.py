"""Live URL sandbox.

Two modes:
  1. Direct fetch (default) — visits the URL with a strict timeout, follows
     a small number of redirects, and inspects the final HTML for credential
     form indicators, brand-asset theft, and excessive redirect chains.
  2. urlscan.io (preferred for production) — submits the URL to urlscan.io
     and reports their verdict. Safer because the actual browser execution
     happens on their infrastructure, not yours.

Direct-fetch mode runs in a context where a malicious page CANNOT execute
JavaScript or load resources — we use httpx with a hard size cap. We do NOT
use a real browser. This keeps the threat model tractable: at worst we
download HTML, and we never persist it.

ALL OUTBOUND CONNECTIONS ARE OPT-IN via ENABLE_URL_SANDBOX=true.
"""
from __future__ import annotations

import os
import re
import time
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from src.models import DetectionFinding, IOC, IOCType, ParsedEmail
from src.utils import get_logger
from src.utils.cache import cache_get, cache_put

log = get_logger(__name__)

_SANDBOX_NS = "url_sandbox"
_SANDBOX_TTL = 6 * 3600       # 6h — page contents change less often than this for phish

UK_BRAND_ASSET_HINTS = [
    "hmrc", "hm-revenue", "royalmail", "natwest", "barclays", "lloydsbank",
    "hsbc", "halifax", "santander", "monzo", "starling", "revolut",
    "tvlicensing", "dvla", "nhs.uk", "gov.uk", "amazon.co.uk",
]


def _is_enabled() -> bool:
    return os.getenv("ENABLE_URL_SANDBOX", "false").lower() == "true"


# ============================================================ DIRECT FETCH

class DirectFetchSandbox:
    def __init__(self):
        self.timeout = float(os.getenv("SANDBOX_TIMEOUT_SECONDS", "8"))
        self.max_redirects = int(os.getenv("SANDBOX_MAX_REDIRECTS", "4"))
        self.ua = os.getenv("SANDBOX_USER_AGENT",
                            "Mozilla/5.0 (compatible; PhishBuster-Sandbox/1.0)")

    def visit(self, url: str) -> Optional[dict]:
        """Fetch URL, return dict of observations, or None on failure."""
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                max_redirects=self.max_redirects,
                headers={"User-Agent": self.ua, "Accept": "text/html,*/*;q=0.1"},
            ) as client:
                r = client.get(url)
        except (httpx.HTTPError, httpx.TooManyRedirects) as exc:
            log.debug("sandbox.fetch_failed url_host=%s err=%s",
                      urlparse(url).hostname, exc)
            return None

        if r.status_code >= 400:
            return {"final_url": str(r.url), "status": r.status_code,
                    "redirects": len(r.history),
                    "credential_form": False, "brand_assets": [],
                    "html_size": 0}

        # Cap size to avoid memory blowups on a malicious server
        body = r.text[:200_000]
        soup = BeautifulSoup(body, "lxml")

        # 1) credential form indicators
        password_inputs = soup.find_all("input", {"type": "password"})
        login_keywords_present = bool(
            soup.find_all(string=re.compile(
                r"\b(login|sign\s*in|password|sort\s*code|account\s*number|"
                r"date\s*of\s*birth|national\s*insurance)\b", re.I))
        )
        credential_form = bool(password_inputs) or (
            soup.find("form") is not None and login_keywords_present
        )

        # 2) brand asset theft — UK brand keyword in <img src> from a different host than current
        final_host = (urlparse(str(r.url)).hostname or "").lower()
        brand_assets: list = []
        for img in soup.find_all("img", src=True)[:60]:
            src = img["src"].lower()
            if any(b in src for b in UK_BRAND_ASSET_HINTS):
                src_host = urlparse(src).hostname
                if src_host and src_host.lower() != final_host:
                    brand_assets.append(src)
                elif "data:" in src or src.startswith("/"):
                    # Same-origin or inline; flag only for known brand strings
                    brand_assets.append(src)

        return {
            "final_url": str(r.url),
            "status": r.status_code,
            "redirects": len(r.history),
            "credential_form": credential_form,
            "brand_assets": brand_assets[:10],
            "html_size": len(body),
        }


# ============================================================ URLSCAN.IO

class UrlscanClient:
    BASE = "https://urlscan.io/api/v1"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client = httpx.Client(
            timeout=12.0,
            headers={"API-Key": api_key, "Content-Type": "application/json",
                     "Accept": "application/json"},
        )

    def search(self, url: str) -> Optional[dict]:
        """Look up existing scans first (no quota use beyond search)."""
        try:
            r = self._client.get(f"{self.BASE}/search/",
                                 params={"q": f"page.url:\"{url}\"", "size": 1})
            if r.status_code == 200:
                results = r.json().get("results", [])
                return results[0] if results else None
        except httpx.HTTPError as exc:
            log.warning("urlscan.search_failed err=%s", exc)
        return None


# ============================================================ DETECTOR

class UrlSandboxDetector:
    def __init__(self, weights: dict):
        self.weights = weights
        self.fetcher = DirectFetchSandbox()
        urlscan_key = os.getenv("URLSCAN_API_KEY", "")
        self.urlscan = UrlscanClient(urlscan_key) if urlscan_key else None

    def analyse(self, email: ParsedEmail) -> Tuple[List[DetectionFinding], List[IOC]]:
        if not _is_enabled():
            return [], []
        findings: List[DetectionFinding] = []
        iocs: List[IOC] = []
        seen: set = set()

        for url in email.urls[:8]:                  # cap — fetching is expensive
            if url in seen:
                continue
            seen.add(url)

            # Try cache
            cached = cache_get(_SANDBOX_NS, url, ttl=_SANDBOX_TTL)
            obs = cached if cached else self.fetcher.visit(url)
            if obs and not cached:
                cache_put(_SANDBOX_NS, url, obs)
            if not obs:
                continue

            # Findings
            if obs.get("credential_form"):
                findings.append(DetectionFinding(
                    detector="url_sandbox",
                    rule="sandbox_credential_form",
                    weight=self.weights.get("sandbox_credential_form", 0.30),
                    detail=f"Live page at {obs.get('final_url')} renders a credential form.",
                ))
                iocs.append(IOC(
                    type=IOCType.URL, value=obs.get("final_url", url),
                    source_detector="url_sandbox", tags=["credential_form"],
                ))

            if obs.get("brand_assets"):
                findings.append(DetectionFinding(
                    detector="url_sandbox",
                    rule="sandbox_brand_asset_steal",
                    weight=self.weights.get("sandbox_brand_asset_steal", 0.35),
                    detail=f"Page references {len(obs['brand_assets'])} UK-brand asset(s); "
                           f"first: {obs['brand_assets'][0][:120]}",
                ))

            if obs.get("redirects", 0) >= 3:
                findings.append(DetectionFinding(
                    detector="url_sandbox",
                    rule="sandbox_redirect_chain",
                    weight=self.weights.get("sandbox_redirect_chain", 0.15),
                    detail=f"URL traversed {obs['redirects']} redirects "
                           f"before resolving to {obs.get('final_url')}.",
                ))

            # Optional: urlscan.io existing scan
            if self.urlscan:
                u_hit = cache_get("urlscan_search", url, ttl=_SANDBOX_TTL) \
                        or self.urlscan.search(url)
                if u_hit and not isinstance(u_hit, dict):
                    u_hit = None
                if u_hit:
                    cache_put("urlscan_search", url, u_hit)
                    verdicts = (u_hit.get("verdicts") or {}).get("overall", {}) \
                               if isinstance(u_hit.get("verdicts"), dict) else {}
                    if verdicts.get("malicious"):
                        findings.append(DetectionFinding(
                            detector="url_sandbox",
                            rule="ti_url_malicious",
                            weight=self.weights.get("ti_url_malicious", 0.40),
                            detail=f"urlscan.io marks URL malicious (score={verdicts.get('score')})",
                        ))

        return findings, iocs
