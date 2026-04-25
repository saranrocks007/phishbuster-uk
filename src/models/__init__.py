"""Pydantic data models used across PhishBuster UK."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AuthResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"


class IOCType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    FILE_HASH = "file_hash"
    ATTACHMENT_NAME = "attachment_name"


# ------------------------------------------------------------------
# Email
# ------------------------------------------------------------------
class EmailHeader(BaseModel):
    """Parsed subset of an email's headers relevant to phishing analysis."""

    message_id: str
    subject: str = ""
    from_address: str = ""
    from_name: str = ""
    to_addresses: List[str] = Field(default_factory=list)
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    received_chain: List[str] = Field(default_factory=list)
    authentication_results: Optional[str] = None
    date: Optional[datetime] = None
    raw_headers: Dict[str, str] = Field(default_factory=dict)


class EmailAttachment(BaseModel):
    """Email attachment metadata.

    The raw bytes of the attachment are NOT stored on the model itself
    (Pydantic doesn't love arbitrary bytes), but downstream detectors that
    need them (YARA, ClamAV) can attach `_data` via object.__setattr__.
    The ingestion layer always populates this private attribute.
    """
    model_config = {"arbitrary_types_allowed": True, "extra": "allow"}

    filename: str
    content_type: str
    size: int
    sha256: Optional[str] = None
    is_image: bool = False
    is_pdf: bool = False


class ParsedEmail(BaseModel):
    """Normalised representation of an email ready for analysis."""

    header: EmailHeader
    text_body: str = ""
    html_body: str = ""
    urls: List[str] = Field(default_factory=list)
    attachments: List[EmailAttachment] = Field(default_factory=list)
    raw_bytes_size: int = 0
    source: str = "m365"  # m365 | eml_file | test

    # Runtime scratchpad for detectors (images decoded from attachments, etc.)
    images: List[bytes] = Field(default_factory=list, exclude=True)


# ------------------------------------------------------------------
# Detection output
# ------------------------------------------------------------------
class DetectionFinding(BaseModel):
    """A single detector contribution to the verdict."""

    detector: str
    rule: str
    weight: float
    detail: str
    evidence: Optional[Dict[str, Any]] = None


class AuthVerdict(BaseModel):
    spf: AuthResult = AuthResult.NONE
    dkim: AuthResult = AuthResult.NONE
    dmarc: AuthResult = AuthResult.NONE
    arc: AuthResult = AuthResult.NONE
    notes: List[str] = Field(default_factory=list)


class IOC(BaseModel):
    type: IOCType
    value: str
    source_detector: str = ""
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    """Full per-email analysis output."""

    message_id: str
    received_at: datetime = Field(default_factory=datetime.utcnow)
    verdict: Verdict = Verdict.BENIGN
    severity: Severity = Severity.INFORMATIONAL
    score: float = 0.0
    sla_minutes: int = 1440
    findings: List[DetectionFinding] = Field(default_factory=list)
    auth: AuthVerdict = Field(default_factory=AuthVerdict)
    iocs: List[IOC] = Field(default_factory=list)
    brand_impersonated: Optional[str] = None
    mitre_techniques: List[str] = Field(default_factory=list)
    summary: str = ""

    # Response tracking
    quarantined: bool = False
    ticket_id: Optional[str] = None
    detected_at: Optional[datetime] = None
    responded_at: Optional[datetime] = None

    # Derived KPI helpers
    def mttd_seconds(self) -> Optional[float]:
        if self.detected_at and self.header_date():
            delta = (self.detected_at - self.header_date()).total_seconds()
            return max(delta, 0.0)
        return None

    def mttr_seconds(self) -> Optional[float]:
        if self.responded_at and self.detected_at:
            return max((self.responded_at - self.detected_at).total_seconds(), 0.0)
        return None

    def header_date(self) -> Optional[datetime]:
        # Filled by orchestrator; placeholder to keep the contract clear.
        return None
