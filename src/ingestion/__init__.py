"""Email parsing utilities.

Accepts:
  * Raw RFC-822 .eml bytes (local testing, NCSC SERS, user-reported phish)
  * Microsoft Graph /messages JSON payloads (production)

Outputs a unified `ParsedEmail` used by the rest of the pipeline.
"""
from __future__ import annotations

import email
import hashlib
import re
import uuid
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Dict, List, Optional, Tuple

from bs4 import BeautifulSoup

from src.models import (
    EmailAttachment,
    EmailHeader,
    ParsedEmail,
)


# Liberal URL regex — we post-filter with tldextract later.
_URL_RE = re.compile(
    r"(?i)\b((?:https?://|www\d{0,3}\.)"
    r"[^\s<>\"'()]+)",
)


def _decode(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _split_addr(raw: str) -> Tuple[str, str]:
    """Return (display_name, address) from a From: header value."""
    if not raw:
        return "", ""
    parsed = getaddresses([raw])
    if not parsed:
        return "", raw
    name, addr = parsed[0]
    return _decode(name).strip(), (addr or "").strip()


def _extract_urls(text: str) -> List[str]:
    if not text:
        return []
    urls = _URL_RE.findall(text)
    # Deduplicate preserving order.
    seen: set[str] = set()
    out: List[str] = []
    for u in urls:
        u = u.rstrip(".,);]\"'")
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _extract_html_urls(html: str) -> List[str]:
    if not html:
        return []
    soup = BeautifulSoup(html, "lxml")
    urls: List[str] = []
    for a in soup.find_all("a", href=True):
        urls.append(a["href"])
    # Also scan raw text for bare URLs.
    urls.extend(_extract_urls(soup.get_text(" ", strip=True)))
    seen: set[str] = set()
    out: List[str] = []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


# ------------------------------------------------------------------
# Raw .eml path
# ------------------------------------------------------------------
def parse_eml_bytes(raw: bytes, source: str = "eml_file") -> ParsedEmail:
    msg: Message = email.message_from_bytes(raw)
    return _parse_message(msg, source=source, raw_size=len(raw))


def _parse_message(msg: Message, source: str, raw_size: int) -> ParsedEmail:
    subject = _decode(msg.get("Subject", ""))
    from_name, from_addr = _split_addr(msg.get("From", ""))
    to_addrs = [addr for _, addr in getaddresses(msg.get_all("To", []) or [])]
    reply_to = _decode(msg.get("Reply-To") or "") or None
    return_path = _decode(msg.get("Return-Path") or "") or None
    received = [_decode(r) for r in (msg.get_all("Received") or [])]
    auth_results = _decode(msg.get("Authentication-Results") or "") or None

    date_val = None
    if msg.get("Date"):
        try:
            date_val = parsedate_to_datetime(msg["Date"])
        except Exception:
            date_val = None

    raw_headers: Dict[str, str] = {k: _decode(v) for k, v in msg.items()}

    header = EmailHeader(
        message_id=_decode(msg.get("Message-ID") or "") or f"<no-id-{uuid.uuid4().hex}@phishbuster>",
        subject=subject,
        from_address=from_addr,
        from_name=from_name,
        to_addresses=[a for a in to_addrs if a],
        reply_to=reply_to,
        return_path=return_path,
        received_chain=received,
        authentication_results=auth_results,
        date=date_val,
        raw_headers=raw_headers,
    )

    text_body, html_body, attachments, images = _walk_parts(msg)
    urls = list(dict.fromkeys(_extract_urls(text_body) + _extract_html_urls(html_body)))

    return ParsedEmail(
        header=header,
        text_body=text_body,
        html_body=html_body,
        urls=urls,
        attachments=attachments,
        raw_bytes_size=raw_size,
        source=source,
        images=images,
    )


def _walk_parts(msg: Message) -> Tuple[str, str, List[EmailAttachment], List[bytes]]:
    text_body: List[str] = []
    html_body: List[str] = []
    attachments: List[EmailAttachment] = []
    images: List[bytes] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type() or "application/octet-stream"
        disposition = (part.get("Content-Disposition") or "").lower()

        if ctype == "text/plain" and "attachment" not in disposition:
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            try:
                text_body.append(payload.decode(charset, errors="replace"))
            except LookupError:
                text_body.append(payload.decode("utf-8", errors="replace"))
        elif ctype == "text/html" and "attachment" not in disposition:
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            try:
                html_body.append(payload.decode(charset, errors="replace"))
            except LookupError:
                html_body.append(payload.decode("utf-8", errors="replace"))
        else:
            payload = part.get_payload(decode=True) or b""
            fname = _decode(part.get_filename() or "") or f"unnamed.{ctype.split('/')[-1]}"
            sha = hashlib.sha256(payload).hexdigest() if payload else None
            is_image = ctype.startswith("image/")
            is_pdf = ctype == "application/pdf"
            attachment = EmailAttachment(
                filename=fname,
                content_type=ctype,
                size=len(payload),
                sha256=sha,
                is_image=is_image,
                is_pdf=is_pdf,
            )
            # Stash raw bytes for YARA / ClamAV. Not serialised.
            object.__setattr__(attachment, "_data", payload)
            attachments.append(attachment)
            if is_image and payload:
                images.append(payload)

    return "\n".join(text_body), "\n".join(html_body), attachments, images


# ------------------------------------------------------------------
# Microsoft Graph /messages payload path
# ------------------------------------------------------------------
def parse_graph_message(
    graph_msg: Dict[str, Any],
    attachments: Optional[List[Dict[str, Any]]] = None,
) -> ParsedEmail:
    """Parse a message returned by GET /me/messages or /users/{id}/messages.

    Graph returns body in `.body.content` (+`.contentType`) and headers via
    `internetMessageHeaders` (only if explicitly requested with $select).
    """
    headers_list = graph_msg.get("internetMessageHeaders") or []
    raw_headers: Dict[str, str] = {h.get("name", ""): h.get("value", "") for h in headers_list}

    from_obj = (graph_msg.get("from") or {}).get("emailAddress") or {}
    from_name = from_obj.get("name") or ""
    from_addr = from_obj.get("address") or ""

    reply_to_list = graph_msg.get("replyTo") or []
    reply_to = None
    if reply_to_list:
        reply_to = (reply_to_list[0].get("emailAddress") or {}).get("address")

    to_addrs = [
        (r.get("emailAddress") or {}).get("address", "")
        for r in (graph_msg.get("toRecipients") or [])
    ]

    subject = graph_msg.get("subject", "") or ""
    msg_id = raw_headers.get("Message-ID") or graph_msg.get("internetMessageId") \
        or f"<graph-{graph_msg.get('id', uuid.uuid4().hex)}>"

    date_val = None
    received_dt = graph_msg.get("receivedDateTime")
    if received_dt:
        try:
            date_val = parsedate_to_datetime(received_dt)
        except Exception:
            date_val = None

    received_chain: List[str] = [
        h.get("value", "")
        for h in headers_list
        if h.get("name", "").lower() == "received"
    ]
    auth_results = raw_headers.get("Authentication-Results")

    header = EmailHeader(
        message_id=msg_id,
        subject=subject,
        from_address=from_addr,
        from_name=from_name,
        to_addresses=[a for a in to_addrs if a],
        reply_to=reply_to,
        return_path=raw_headers.get("Return-Path"),
        received_chain=received_chain,
        authentication_results=auth_results,
        date=date_val,
        raw_headers=raw_headers,
    )

    body_obj = graph_msg.get("body") or {}
    body_type = (body_obj.get("contentType") or "text").lower()
    body_content = body_obj.get("content") or ""
    if body_type == "html":
        html_body = body_content
        text_body = BeautifulSoup(body_content, "lxml").get_text(" ", strip=True)
    else:
        html_body = ""
        text_body = body_content

    urls = list(dict.fromkeys(_extract_urls(text_body) + _extract_html_urls(html_body)))

    parsed_attachments: List[EmailAttachment] = []
    images: List[bytes] = []
    for att in attachments or []:
        ctype = att.get("contentType", "application/octet-stream")
        size = int(att.get("size", 0) or 0)
        content_b64 = att.get("contentBytes") or ""
        data = b""
        if content_b64:
            import base64
            try:
                data = base64.b64decode(content_b64)
            except Exception:
                data = b""
        sha = hashlib.sha256(data).hexdigest() if data else None
        is_image = ctype.startswith("image/")
        is_pdf = ctype == "application/pdf"
        attachment = EmailAttachment(
            filename=att.get("name", "unnamed"),
            content_type=ctype,
            size=size,
            sha256=sha,
            is_image=is_image,
            is_pdf=is_pdf,
        )
        object.__setattr__(attachment, "_data", data)
        parsed_attachments.append(attachment)
        if is_image and data:
            images.append(data)

    return ParsedEmail(
        header=header,
        text_body=text_body,
        html_body=html_body,
        urls=urls,
        attachments=parsed_attachments,
        raw_bytes_size=len(body_content.encode("utf-8", errors="ignore")),
        source="m365",
        images=images,
    )
