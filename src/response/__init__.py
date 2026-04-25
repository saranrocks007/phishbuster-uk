"""Response automation.

Responsibilities:
  * Quarantine phishing messages in M365 (move to a named folder).
  * Create a ticket in Jira / ServiceNow for L1 analyst triage.
  * Emit Slack / Teams alerts.
  * Optionally forward the original message to the NCSC SERS address.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from src.models import AnalysisReport, Severity, Verdict
from src.utils import get_logger

log = get_logger("phishbuster.response")


# ------------------------------------------------------------------
# Quarantine
# ------------------------------------------------------------------
class Quarantiner:
    """Moves phishing messages to a dedicated folder via Graph."""

    def __init__(self, graph_client, mailbox: str,
                 folder_name: Optional[str] = None):
        self.graph = graph_client
        self.mailbox = mailbox
        self.folder_name = folder_name or os.getenv(
            "QUARANTINE_FOLDER", "PhishBusterQuarantine"
        )
        self._folder_id: Optional[str] = None

    def ensure_ready(self) -> str:
        if not self._folder_id:
            self._folder_id = self.graph.ensure_folder(self.mailbox, self.folder_name)
        return self._folder_id

    def quarantine(self, graph_message_id: str) -> bool:
        folder_id = self.ensure_ready()
        try:
            self.graph.move_message(self.mailbox, graph_message_id, folder_id)
            log.info("Quarantined message %s to folder %s",
                     graph_message_id, self.folder_name)
            return True
        except Exception as e:
            log.error("Quarantine failed for %s: %s", graph_message_id, e)
            return False


# ------------------------------------------------------------------
# Ticketing
# ------------------------------------------------------------------
class TicketingBackend:
    """Strategy object for incident ticket creation.

    Backends supported: jira | servicenow | stdout
    """

    def __init__(self):
        self.backend = os.getenv("TICKETING_BACKEND", "stdout").lower()
        self._client = httpx.Client(timeout=30.0)

    # --------------------------------------------------------------
    def create_ticket(self, report: AnalysisReport) -> Optional[str]:
        if self.backend == "jira":
            return self._jira_ticket(report)
        if self.backend == "servicenow":
            return self._servicenow_ticket(report)
        return self._stdout_ticket(report)

    # --------------------------------------------------------------
    def _stdout_ticket(self, report: AnalysisReport) -> str:
        tid = f"STDOUT-{report.message_id[-12:]}"
        payload = {
            "id": tid,
            "summary": report.summary,
            "severity": report.severity.value,
            "verdict": report.verdict.value,
            "score": report.score,
            "brand": report.brand_impersonated,
            "iocs": [i.value for i in report.iocs],
        }
        log.info("Ticket (stdout): %s", json.dumps(payload, default=str)[:600])
        return tid

    # --------------------------------------------------------------
    def _jira_ticket(self, report: AnalysisReport) -> Optional[str]:
        url = os.getenv("JIRA_URL", "").rstrip("/")
        user = os.getenv("JIRA_USER", "")
        token = os.getenv("JIRA_API_TOKEN", "")
        project = os.getenv("JIRA_PROJECT_KEY", "SOC")
        if not (url and user and token):
            log.warning("Jira credentials missing; falling back to stdout.")
            return self._stdout_ticket(report)

        sev_to_priority = {
            Severity.CRITICAL: "Highest",
            Severity.HIGH: "High",
            Severity.MEDIUM: "Medium",
            Severity.LOW: "Low",
            Severity.INFORMATIONAL: "Lowest",
        }

        fields: Dict[str, Any] = {
            "project": {"key": project},
            "summary": f"[PhishBuster UK] {report.severity.value.upper()} — {report.brand_impersonated or 'phishing'}",
            "description": _jira_description(report),
            "issuetype": {"name": "Incident"},
            "priority": {"name": sev_to_priority.get(report.severity, "Medium")},
            "labels": ["phishing", "phishbuster-uk",
                       report.brand_impersonated or "generic"],
        }
        try:
            resp = self._client.post(
                f"{url}/rest/api/3/issue",
                auth=(user, token),
                headers={"Content-Type": "application/json"},
                json={"fields": fields},
            )
            if resp.status_code >= 400:
                log.error("Jira ticket create failed %s: %s",
                          resp.status_code, resp.text[:300])
                return None
            return resp.json().get("key")
        except Exception as e:
            log.error("Jira ticket create exception: %s", e)
            return None

    # --------------------------------------------------------------
    def _servicenow_ticket(self, report: AnalysisReport) -> Optional[str]:
        instance = os.getenv("SNOW_INSTANCE", "")
        user = os.getenv("SNOW_USER", "")
        pw = os.getenv("SNOW_PASSWORD", "")
        if not (instance and user and pw):
            log.warning("ServiceNow credentials missing; falling back to stdout.")
            return self._stdout_ticket(report)
        url = f"https://{instance}.service-now.com/api/now/table/incident"
        impact = {"critical": 1, "high": 2, "medium": 3, "low": 4, "informational": 5}.get(
            report.severity.value, 3
        )
        payload = {
            "short_description": f"[PhishBuster UK] {report.severity.value.upper()} — "
                                 f"{report.brand_impersonated or 'phishing'}",
            "description": _snow_description(report),
            "category": "security",
            "subcategory": "phishing",
            "impact": impact,
            "urgency": impact,
        }
        try:
            resp = self._client.post(
                url, auth=(user, pw),
                headers={"Content-Type": "application/json",
                         "Accept": "application/json"},
                json=payload,
            )
            if resp.status_code >= 400:
                log.error("SNOW ticket failed %s: %s",
                          resp.status_code, resp.text[:300])
                return None
            return resp.json().get("result", {}).get("number")
        except Exception as e:
            log.error("SNOW ticket exception: %s", e)
            return None


def _jira_description(r: AnalysisReport) -> str:
    lines = [
        f"h3. PhishBuster UK — {r.verdict.value.upper()} (score {r.score:.2f})",
        "",
        f"*Message-ID:* {r.message_id}",
        f"*Severity:* {r.severity.value}   *SLA:* {r.sla_minutes} minutes",
        f"*Brand impersonated:* {r.brand_impersonated or '—'}",
        f"*Summary:* {r.summary}",
        "",
        "h4. Detections",
    ]
    for f in sorted(r.findings, key=lambda x: x.weight, reverse=True):
        lines.append(f"* *{f.rule}* ({f.weight:.2f}) — {f.detail}")
    lines.append("")
    lines.append("h4. Auth results")
    lines.append(f"SPF={r.auth.spf.value} DKIM={r.auth.dkim.value} "
                 f"DMARC={r.auth.dmarc.value} ARC={r.auth.arc.value}")
    lines.append("")
    if r.mitre_techniques:
        lines.append("h4. MITRE ATT&CK")
        lines.append(", ".join(r.mitre_techniques))
    lines.append("")
    lines.append("h4. IOCs")
    for ioc in r.iocs[:30]:
        lines.append(f"* {ioc.type.value}: {{noformat}}{ioc.value}{{noformat}}")
    return "\n".join(lines)


def _snow_description(r: AnalysisReport) -> str:
    return _jira_description(r).replace("h3.", "").replace("h4.", "")


# ------------------------------------------------------------------
# Alerting
# ------------------------------------------------------------------
class Alerter:
    def __init__(self):
        self.slack = os.getenv("SLACK_WEBHOOK_URL", "")
        self.teams = os.getenv("TEAMS_WEBHOOK_URL", "")
        self._client = httpx.Client(timeout=15.0)

    def alert(self, report: AnalysisReport, ticket_id: Optional[str]) -> None:
        if not (self.slack or self.teams):
            return
        title = f"PhishBuster UK — {report.severity.value.upper()}"
        body = (
            f"*Verdict:* {report.verdict.value} (score {report.score:.2f})\n"
            f"*Brand:* {report.brand_impersonated or '—'}\n"
            f"*Subject/Summary:* {report.summary}\n"
            f"*Ticket:* {ticket_id or 'n/a'}"
        )
        if self.slack:
            try:
                self._client.post(
                    self.slack,
                    json={"text": f"*{title}*\n{body}"},
                )
            except Exception as e:
                log.warning("Slack alert failed: %s", e)
        if self.teams:
            try:
                self._client.post(
                    self.teams,
                    json={"title": title, "text": body.replace("*", "**")},
                )
            except Exception as e:
                log.warning("Teams alert failed: %s", e)


# ------------------------------------------------------------------
# NCSC SERS bridge
# ------------------------------------------------------------------
class NcscForwarder:
    """Optional bridge to report confirmed phishing to the NCSC
    Suspicious Email Reporting Service.

    NCSC accept messages as standard RFC-822 attachments. This uses
    Graph's forward endpoint.
    """

    def __init__(self, graph_client, mailbox: str):
        self.graph = graph_client
        self.mailbox = mailbox
        self.enabled = os.getenv("ENABLE_NCSC_SERS_FORWARDING", "false").lower() == "true"
        self.target = os.getenv("NCSC_SERS_ADDRESS", "report@phishing.gov.uk")

    def forward(self, graph_message_id: str, report: AnalysisReport) -> bool:
        if not self.enabled:
            return False
        if report.verdict != Verdict.PHISHING:
            return False
        try:
            comment = (
                f"PhishBuster UK verdict: {report.verdict.value} "
                f"(score {report.score:.2f}, brand {report.brand_impersonated or 'unknown'}). "
                f"Reported automatically."
            )
            self.graph.forward_message(
                self.mailbox, graph_message_id, [self.target], comment=comment
            )
            log.info("Forwarded %s to NCSC SERS (%s)", graph_message_id, self.target)
            return True
        except Exception as e:
            log.warning("NCSC SERS forward failed: %s", e)
            return False


# ------------------------------------------------------------------
# IOC reporter
# ------------------------------------------------------------------
class IocReporter:
    """Write IOCs to disk in multiple formats (JSON, CSV, STIX 2.1)."""

    def __init__(self, out_dir: Optional[str] = None):
        from pathlib import Path
        self.out_dir = Path(out_dir or os.getenv("PB_DATA_DIR", "./data")) / "iocs"
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def write_all(self, report: AnalysisReport) -> Dict[str, str]:
        base = f"{self.out_dir}/{_safe_id(report.message_id)}"
        paths = {
            "json": f"{base}.json",
            "csv": f"{base}.csv",
            "stix": f"{base}.stix.json",
        }
        self._write_json(report, paths["json"])
        self._write_csv(report, paths["csv"])
        self._write_stix(report, paths["stix"])
        return paths

    def _write_json(self, report: AnalysisReport, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report.model_dump(mode="json"), f, indent=2, default=str)

    def _write_csv(self, report: AnalysisReport, path: str) -> None:
        import csv
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["type", "value", "detector", "tags"])
            for i in report.iocs:
                w.writerow([i.type.value, i.value, i.source_detector, "|".join(i.tags)])

    def _write_stix(self, report: AnalysisReport, path: str) -> None:
        try:
            from stix2 import Bundle, Indicator, Identity
        except Exception:
            log.warning("stix2 not installed; skipping STIX export.")
            return
        identity = Identity(
            name="PhishBuster UK",
            identity_class="system",
        )
        indicators: List[Indicator] = []
        for ioc in report.iocs:
            if ioc.type.value == "url":
                pattern = f"[url:value = '{ioc.value}']"
            elif ioc.type.value == "domain":
                pattern = f"[domain-name:value = '{ioc.value}']"
            elif ioc.type.value == "ip":
                pattern = f"[ipv4-addr:value = '{ioc.value}']"
            elif ioc.type.value == "email":
                pattern = f"[email-addr:value = '{ioc.value}']"
            elif ioc.type.value == "file_hash":
                pattern = f"[file:hashes.'SHA-256' = '{ioc.value}']"
            else:
                continue
            indicators.append(Indicator(
                pattern=pattern,
                pattern_type="stix",
                created_by_ref=identity.id,
                labels=["malicious-activity"],
                valid_from=datetime.now(timezone.utc),
            ))
        bundle = Bundle(objects=[identity] + indicators, allow_custom=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(bundle.serialize(pretty=True))


def _safe_id(msg_id: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in msg_id)[:80]
