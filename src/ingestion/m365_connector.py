"""Microsoft 365 Graph API connector.

Auth: Client-credentials flow via MSAL (application permissions).
Scopes required on the Entra ID app registration:
  - Mail.Read                 (application)
  - Mail.ReadWrite            (application) - for move/quarantine
  - MailboxSettings.Read      (application)

Usage:
    client = GraphClient()
    client.authenticate()
    for msg in client.iter_messages(mailbox="soc-inbox@corp.co.uk", top=25):
        ...
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, Iterator, List, Optional

import httpx
import msal

from src.utils import get_logger

log = get_logger("phishbuster.m365")

GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
SCOPE = ["https://graph.microsoft.com/.default"]


class GraphAuthError(RuntimeError):
    pass


class GraphClient:
    """Thin, focused Graph client for mailbox read + message move."""

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.tenant_id = tenant_id or os.getenv("M365_TENANT_ID", "")
        self.client_id = client_id or os.getenv("M365_CLIENT_ID", "")
        self.client_secret = client_secret or os.getenv("M365_CLIENT_SECRET", "")
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0
        self._client = httpx.Client(timeout=timeout)

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------
    def authenticate(self) -> str:
        if not (self.tenant_id and self.client_id and self.client_secret):
            raise GraphAuthError(
                "Missing M365 credentials. Set M365_TENANT_ID, M365_CLIENT_ID, "
                "M365_CLIENT_SECRET in the environment."
            )
        authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        app = msal.ConfidentialClientApplication(
            self.client_id,
            authority=authority,
            client_credential=self.client_secret,
        )
        result = app.acquire_token_for_client(scopes=SCOPE)
        if "access_token" not in result:
            raise GraphAuthError(
                f"Token acquisition failed: {result.get('error_description', result)}"
            )
        self._token = result["access_token"]
        self._token_expiry = time.time() + int(result.get("expires_in", 3300)) - 60
        log.info("Graph authentication successful")
        return self._token

    def _headers(self) -> Dict[str, str]:
        if not self._token or time.time() >= self._token_expiry:
            self.authenticate()
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # Message listing
    # ------------------------------------------------------------------
    def iter_messages(
        self,
        mailbox: str,
        folder: str = "Inbox",
        top: int = 50,
        since: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Yield messages from a mailbox folder, newest first."""
        select = ",".join([
            "id", "subject", "from", "toRecipients", "replyTo",
            "receivedDateTime", "sentDateTime", "internetMessageId",
            "hasAttachments", "body", "bodyPreview",
            "internetMessageHeaders",
        ])
        filter_parts: List[str] = []
        if since:
            filter_parts.append(f"receivedDateTime ge {since}")

        params: Dict[str, Any] = {
            "$select": select,
            "$top": top,
            "$orderby": "receivedDateTime desc",
        }
        if filter_parts:
            params["$filter"] = " and ".join(filter_parts)

        url = f"{GRAPH_ROOT}/users/{mailbox}/mailFolders/{folder}/messages"
        while url:
            resp = self._client.get(url, headers=self._headers(), params=params if url.endswith('/messages') else None)
            if resp.status_code >= 400:
                log.error("Graph list error %s: %s", resp.status_code, resp.text[:300])
                resp.raise_for_status()
            data = resp.json()
            for item in data.get("value", []):
                yield item
            url = data.get("@odata.nextLink") or None
            params = None  # nextLink already encodes params

    def get_attachments(self, mailbox: str, message_id: str) -> List[Dict[str, Any]]:
        """Return attachment metadata + contentBytes (Graph fileAttachment)."""
        url = f"{GRAPH_ROOT}/users/{mailbox}/messages/{message_id}/attachments"
        resp = self._client.get(url, headers=self._headers())
        if resp.status_code >= 400:
            log.warning("Graph attachments fetch failed %s: %s",
                        resp.status_code, resp.text[:200])
            return []
        return resp.json().get("value", [])

    # ------------------------------------------------------------------
    # Quarantine actions
    # ------------------------------------------------------------------
    def ensure_folder(self, mailbox: str, display_name: str) -> str:
        """Return folder id, creating the folder if it does not exist."""
        url = f"{GRAPH_ROOT}/users/{mailbox}/mailFolders"
        resp = self._client.get(
            url,
            headers=self._headers(),
            params={"$filter": f"displayName eq '{display_name}'"},
        )
        resp.raise_for_status()
        for f in resp.json().get("value", []):
            return f["id"]
        # Create it.
        log.info("Creating quarantine folder '%s' in %s", display_name, mailbox)
        resp = self._client.post(
            url,
            headers={**self._headers(), "Content-Type": "application/json"},
            json={"displayName": display_name},
        )
        resp.raise_for_status()
        return resp.json()["id"]

    def move_message(self, mailbox: str, message_id: str, destination_id: str) -> Dict[str, Any]:
        url = f"{GRAPH_ROOT}/users/{mailbox}/messages/{message_id}/move"
        resp = self._client.post(
            url,
            headers={**self._headers(), "Content-Type": "application/json"},
            json={"destinationId": destination_id},
        )
        if resp.status_code >= 400:
            log.error("Graph move error %s: %s", resp.status_code, resp.text[:300])
            resp.raise_for_status()
        return resp.json()

    def forward_message(
        self,
        mailbox: str,
        message_id: str,
        to_addresses: List[str],
        comment: str = "",
    ) -> None:
        url = f"{GRAPH_ROOT}/users/{mailbox}/messages/{message_id}/forward"
        payload = {
            "comment": comment,
            "toRecipients": [
                {"emailAddress": {"address": a}} for a in to_addresses
            ],
        }
        resp = self._client.post(
            url,
            headers={**self._headers(), "Content-Type": "application/json"},
            json=payload,
        )
        if resp.status_code >= 400:
            log.error("Graph forward error %s: %s", resp.status_code, resp.text[:300])
            resp.raise_for_status()
