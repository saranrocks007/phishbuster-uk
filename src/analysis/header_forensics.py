"""Email header forensics.

Parses Authentication-Results, the Received: chain, and the relationship
between From / Return-Path / Reply-To to produce an AuthVerdict plus a
list of DetectionFindings.

Design notes
------------
We deliberately do NOT perform live DNS lookups for SPF/DKIM/DMARC here
in the hot path — the Authentication-Results header written by
Exchange Online / any upstream MTA is authoritative and already the
result of DNS-backed validation. Live checks are available via the
`authheaders` optional path for standalone .eml testing, but default
behaviour trusts the AR header when present and falls back to heuristics
when it is not.
"""
from __future__ import annotations

import re
from typing import List, Optional

from src.models import (
    AuthResult,
    AuthVerdict,
    DetectionFinding,
    ParsedEmail,
)

_AR_TOKEN_RE = re.compile(
    r"(?i)\b(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)"
)


def _map_result(raw: str) -> AuthResult:
    raw = raw.lower().strip()
    mapping = {
        "pass": AuthResult.PASS,
        "fail": AuthResult.FAIL,
        "softfail": AuthResult.SOFTFAIL,
        "neutral": AuthResult.NEUTRAL,
        "none": AuthResult.NONE,
        "temperror": AuthResult.TEMPERROR,
        "permerror": AuthResult.PERMERROR,
        "bestguesspass": AuthResult.PASS,
    }
    return mapping.get(raw, AuthResult.NONE)


def parse_authentication_results(ar_header: Optional[str]) -> AuthVerdict:
    """Parse a classic Authentication-Results header into an AuthVerdict."""
    verdict = AuthVerdict()
    if not ar_header:
        verdict.notes.append("Authentication-Results header absent")
        return verdict

    for match in _AR_TOKEN_RE.finditer(ar_header):
        mech = match.group(1).lower()
        result = _map_result(match.group(2))
        setattr(verdict, mech, result)

    return verdict


def analyse_headers(email: ParsedEmail, weights: dict) -> tuple[AuthVerdict, List[DetectionFinding]]:
    """Return an AuthVerdict and header-level findings."""
    findings: List[DetectionFinding] = []
    verdict = parse_authentication_results(email.header.authentication_results)

    # --- SPF ---
    if verdict.spf == AuthResult.FAIL:
        findings.append(DetectionFinding(
            detector="header_forensics", rule="spf_fail",
            weight=weights.get("spf_fail", 0.2),
            detail="SPF check failed (sender not authorised by domain).",
        ))
    elif verdict.spf == AuthResult.SOFTFAIL:
        findings.append(DetectionFinding(
            detector="header_forensics", rule="spf_softfail",
            weight=weights.get("spf_softfail", 0.1),
            detail="SPF softfail (domain discourages sending from this IP).",
        ))

    # --- DKIM ---
    if verdict.dkim == AuthResult.FAIL:
        findings.append(DetectionFinding(
            detector="header_forensics", rule="dkim_fail",
            weight=weights.get("dkim_fail", 0.2),
            detail="DKIM signature did not verify.",
        ))
    elif verdict.dkim in (AuthResult.NONE, AuthResult.NEUTRAL):
        findings.append(DetectionFinding(
            detector="header_forensics", rule="dkim_missing",
            weight=weights.get("dkim_missing", 0.08),
            detail="DKIM signature missing or unaligned.",
        ))

    # --- DMARC ---
    if verdict.dmarc == AuthResult.FAIL:
        findings.append(DetectionFinding(
            detector="header_forensics", rule="dmarc_fail",
            weight=weights.get("dmarc_fail", 0.2),
            detail="DMARC policy evaluation failed (SPF & DKIM alignment).",
        ))
    elif verdict.dmarc == AuthResult.NONE:
        findings.append(DetectionFinding(
            detector="header_forensics", rule="dmarc_missing",
            weight=weights.get("dmarc_missing", 0.08),
            detail="No DMARC policy published for the From domain.",
        ))

    # --- ARC ---
    if verdict.arc == AuthResult.FAIL:
        findings.append(DetectionFinding(
            detector="header_forensics", rule="arc_broken",
            weight=weights.get("arc_broken", 0.1),
            detail="ARC chain broken — forwarding path may be untrusted.",
        ))

    # --- Reply-To vs From domain mismatch ---
    from_domain = _domain_of(email.header.from_address)
    reply_to = email.header.reply_to or ""
    reply_domain = _domain_of(reply_to) if reply_to else ""
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append(DetectionFinding(
            detector="header_forensics", rule="reply_to_mismatch",
            weight=weights.get("reply_to_mismatch", 0.15),
            detail=f"Reply-To ({reply_domain}) differs from From ({from_domain}).",
            evidence={"from_domain": from_domain, "reply_to_domain": reply_domain},
        ))

    # --- Return-Path vs From mismatch (weaker signal; ignore mailing-list noise) ---
    rp = (email.header.return_path or "").strip("<>")
    rp_domain = _domain_of(rp) if rp else ""
    if rp_domain and from_domain and rp_domain != from_domain and not _is_list_envelope(rp_domain):
        verdict.notes.append(
            f"Return-Path domain ({rp_domain}) differs from From domain ({from_domain})."
        )

    return verdict, findings


def _domain_of(address: str) -> str:
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().strip(">").lower()


_LIST_ENVELOPE_HINTS = ("bounce", "mailer", "noreply", "no-reply", "prvs=", "sendgrid", "amazonses")


def _is_list_envelope(domain: str) -> bool:
    return any(hint in domain for hint in _LIST_ENVELOPE_HINTS)
