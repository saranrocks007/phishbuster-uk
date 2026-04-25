"""Attachment scanning: YARA rules, Office-macro detection, PDF JS,
and optional ClamAV.

YARA rules live in `config/yara/` — a starter ruleset is shipped that
covers UK-relevant phishing payloads (HTML credential harvesters, ISO/LNK
loaders, double-extension files, encrypted-zip with HTML inside).

Macro detection works on the raw bytes — we look for VBA-typical markers
(`vbaProject.bin`, `Auto_Open`, `Document_Open`, `Workbook_Open`) without
requiring oletools. PDF JS is detected via /JS or /JavaScript markers.
"""
from __future__ import annotations

import os
import re
import zipfile
from io import BytesIO
from pathlib import Path
from typing import List, Optional, Tuple

from src.models import DetectionFinding, IOC, IOCType, ParsedEmail, EmailAttachment
from src.utils import get_logger

log = get_logger(__name__)

_DEFAULT_YARA_DIR = Path(os.getenv("YARA_RULES_DIR", "./config/yara"))


def _yara_enabled() -> bool:
    return os.getenv("ENABLE_YARA_SCANNING", "true").lower() == "true"


def _clamav_enabled() -> bool:
    return os.getenv("ENABLE_CLAMAV", "false").lower() == "true"


# ============================================================ YARA

class YaraScanner:
    def __init__(self, rules_dir: Path = _DEFAULT_YARA_DIR):
        self.rules = None
        self.rules_dir = rules_dir
        try:
            import yara
        except ImportError:
            log.warning("yara-python not installed; YARA scanning disabled.")
            return

        if not rules_dir.exists():
            log.warning("yara.rules_dir_missing path=%s", rules_dir)
            return

        rule_files = {p.stem: str(p) for p in rules_dir.glob("*.yar")}
        if not rule_files:
            log.warning("yara.no_rules_found in=%s", rules_dir)
            return

        try:
            self.rules = yara.compile(filepaths=rule_files)
            log.info("yara.compiled count=%d", len(rule_files))
        except Exception as exc:
            log.error("yara.compile_failed err=%s", exc)

    def scan(self, data: bytes) -> List[dict]:
        if not self.rules:
            return []
        try:
            matches = self.rules.match(data=data, timeout=5)
        except Exception as exc:
            log.warning("yara.scan_failed err=%s", exc)
            return []
        return [{
            "rule": m.rule,
            "tags": list(m.tags),
            "meta": dict(m.meta or {}),
            "severity": (m.meta or {}).get("severity", "medium"),
        } for m in matches]


# ============================================================ MACRO / PDF

_VBA_AUTO_MARKERS = (b"Auto_Open", b"AutoOpen", b"Document_Open",
                     b"Workbook_Open", b"AutoClose", b"AutoExec",
                     b"Workbook_Activate", b"Document_New")


def _office_has_macros(blob: bytes) -> tuple[bool, bool]:
    """Returns (has_macros, has_autoexec)."""
    if not blob.startswith(b"PK\x03\x04"):       # not a zip-based OOXML
        # Could be legacy OLE Compound — quickly check magic
        if blob[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            has_macros = b"vbaProject" in blob
            has_auto = any(m in blob for m in _VBA_AUTO_MARKERS)
            return has_macros, has_auto
        return False, False
    try:
        zf = zipfile.ZipFile(BytesIO(blob))
        names = zf.namelist()
    except Exception:
        return False, False
    has_macros = any(n.endswith("vbaProject.bin") or "macros" in n for n in names)
    has_auto = False
    if has_macros:
        for n in names:
            if "vbaProject" in n:
                try:
                    raw = zf.read(n)
                    if any(m in raw for m in _VBA_AUTO_MARKERS):
                        has_auto = True
                        break
                except Exception:
                    pass
    return has_macros, has_auto


def _pdf_has_javascript(blob: bytes) -> bool:
    if not blob.startswith(b"%PDF"):
        return False
    head = blob[:512_000]                            # 500KB head is enough
    # /JS, /JavaScript, /OpenAction (case-insensitive in PDF lexer)
    return bool(re.search(rb"/(JS|JavaScript|OpenAction)\b", head))


# ============================================================ DETECTOR

class AttachmentScanner:
    def __init__(self, weights: dict):
        self.weights = weights
        self.yara = YaraScanner() if _yara_enabled() else None
        self.clamav = None
        if _clamav_enabled():
            try:
                import pyclamd                       # type: ignore
                self.clamav = pyclamd.ClamdNetworkSocket(
                    host=os.getenv("CLAMAV_HOST", "127.0.0.1"),
                    port=int(os.getenv("CLAMAV_PORT", "3310")),
                )
                self.clamav.ping()
            except Exception as exc:
                log.warning("clamav.unavailable err=%s", exc)
                self.clamav = None

    def analyse(self, email: ParsedEmail) -> Tuple[List[DetectionFinding], List[IOC]]:
        findings: List[DetectionFinding] = []
        iocs: List[IOC] = []
        for att in (email.attachments or []):
            blob = getattr(att, "_data", None)
            if not blob:
                continue
            self._scan_one(att, blob, findings, iocs)
        return findings, iocs

    def _scan_one(self, att: EmailAttachment, blob: bytes,
                  findings: List[DetectionFinding], iocs: List[IOC]) -> None:
        name = att.filename or "attachment"
        ext = (name.rsplit(".", 1)[-1] if "." in name else "").lower()

        # YARA
        if self.yara:
            for m in self.yara.scan(blob):
                sev = (m.get("severity") or "medium").lower()
                rule = "yara_match_malicious" if sev == "high" else "yara_match_suspicious"
                findings.append(DetectionFinding(
                    detector="attachment_scanner",
                    rule=rule,
                    weight=self.weights.get(rule, 0.45 if rule == "yara_match_malicious" else 0.25),
                    detail=f"YARA rule '{m['rule']}' matched on '{name}' "
                           f"(tags={','.join(m['tags']) or 'none'})",
                ))
                iocs.append(IOC(
                    type=IOCType.ATTACHMENT_NAME, value=name,
                    source_detector="attachment_scanner",
                    tags=[m["rule"], sev],
                ))

        # Office macros
        if ext in {"doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm"}:
            has_macros, has_auto = _office_has_macros(blob)
            if has_macros and has_auto:
                findings.append(DetectionFinding(
                    detector="attachment_scanner",
                    rule="macro_office_with_autoexec",
                    weight=self.weights.get("macro_office_with_autoexec", 0.30),
                    detail=f"'{name}' contains VBA macros with auto-execute hooks "
                           f"(Auto_Open / Document_Open / Workbook_Open).",
                ))
            elif has_macros:
                findings.append(DetectionFinding(
                    detector="attachment_scanner",
                    rule="macro_office_doc",
                    weight=self.weights.get("macro_office_doc", 0.20),
                    detail=f"'{name}' contains VBA macros.",
                ))

        # PDF JS
        if ext == "pdf" and _pdf_has_javascript(blob):
            findings.append(DetectionFinding(
                detector="attachment_scanner",
                rule="pdf_with_javascript",
                weight=self.weights.get("pdf_with_javascript", 0.20),
                detail=f"'{name}' contains JavaScript or auto-action.",
            ))

        # ClamAV
        if self.clamav:
            try:
                result = self.clamav.scan_stream(blob)
                if result and "stream" in result and result["stream"][0] == "FOUND":
                    sig = result["stream"][1]
                    findings.append(DetectionFinding(
                        detector="attachment_scanner",
                        rule="ti_filehash_known_malicious",
                        weight=self.weights.get("ti_filehash_known_malicious", 0.45),
                        detail=f"ClamAV signature: {sig} on '{name}'",
                    ))
            except Exception as exc:
                log.warning("clamav.scan_failed err=%s", exc)
