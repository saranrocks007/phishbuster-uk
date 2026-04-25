"""PhishBuster UK — main orchestrator.

Usage
-----
Scan a single .eml file:
    python -m src.main --scan-file tests/samples/hmrc_refund.eml

Run the M365 polling daemon:
    python -m src.main --daemon

Run a one-shot M365 scan (useful for cron):
    python -m src.main --once
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

from src.analysis import AnalysisEngine
from src.database import init_db, persist_report
from src.ingestion import parse_eml_bytes, parse_graph_message
from src.models import AnalysisReport, ParsedEmail, Verdict
from src.response import (
    Alerter,
    IocReporter,
    NcscForwarder,
    Quarantiner,
    TicketingBackend,
)
from src.utils import get_logger

log = get_logger("phishbuster.main")


# ------------------------------------------------------------------
def _run_response(
    email: ParsedEmail,
    report: AnalysisReport,
    *,
    graph_client=None,
    mailbox: Optional[str] = None,
    graph_message_id: Optional[str] = None,
) -> AnalysisReport:
    """Apply quarantine + ticketing + alerting. Mutates report in-place."""
    ticketing = TicketingBackend()
    alerter = Alerter()
    reporter = IocReporter()

    # IOC export always runs — analyst-ready evidence regardless of verdict.
    paths = reporter.write_all(report)
    log.info("IOC artefacts written: %s", paths)

    if report.verdict == Verdict.PHISHING:
        # Quarantine (M365 only).
        if (
            os.getenv("ENABLE_AUTO_QUARANTINE", "true").lower() == "true"
            and graph_client and mailbox and graph_message_id
        ):
            q = Quarantiner(graph_client, mailbox)
            report.quarantined = q.quarantine(graph_message_id)

        # Ticket.
        if os.getenv("ENABLE_TICKETING", "true").lower() == "true":
            report.ticket_id = ticketing.create_ticket(report)

        # Alert fan-out.
        alerter.alert(report, report.ticket_id)

        # NCSC SERS bridge (optional).
        if graph_client and mailbox and graph_message_id:
            ncsc = NcscForwarder(graph_client, mailbox)
            ncsc.forward(graph_message_id, report)

        report.responded_at = datetime.now(timezone.utc)

    return report


# ------------------------------------------------------------------
def scan_file(path: str, engine: AnalysisEngine) -> AnalysisReport:
    data = Path(path).read_bytes()
    email = parse_eml_bytes(data, source="eml_file")
    report = engine.analyse(email)
    report = _run_response(email, report)
    persist_report(report, email.header.from_address, email.header.subject)
    _print_report(report)
    return report


# ------------------------------------------------------------------
def run_m365_scan(engine: AnalysisEngine, *, once: bool) -> None:
    from src.ingestion.m365_connector import GraphClient
    mailbox = os.getenv("M365_TARGET_MAILBOX")
    if not mailbox:
        log.error("M365_TARGET_MAILBOX not set. Aborting.")
        sys.exit(2)

    graph = GraphClient()
    graph.authenticate()
    interval = int(os.getenv("M365_POLL_INTERVAL_SECONDS", "60"))
    last_seen: set[str] = set()

    while True:
        try:
            for msg in graph.iter_messages(mailbox=mailbox, top=50):
                mid = msg.get("id")
                if not mid or mid in last_seen:
                    continue
                last_seen.add(mid)
                attachments = graph.get_attachments(mailbox, mid) \
                    if msg.get("hasAttachments") else []
                email = parse_graph_message(msg, attachments=attachments)
                report = engine.analyse(email)
                report = _run_response(
                    email, report,
                    graph_client=graph, mailbox=mailbox,
                    graph_message_id=mid,
                )
                persist_report(report, email.header.from_address, email.header.subject)
                _print_report(report)
        except Exception as e:
            log.exception("Scan cycle error: %s", e)

        if once:
            return
        time.sleep(interval)


# ------------------------------------------------------------------
def _print_report(report: AnalysisReport) -> None:
    from rich.console import Console
    from rich.table import Table
    console = Console()

    colour = {
        "benign": "green",
        "suspicious": "yellow",
        "phishing": "red",
    }.get(report.verdict.value, "white")

    console.print(
        f"\n[bold {colour}]═══ {report.verdict.value.upper()} ═══[/] "
        f"score=[bold]{report.score:.2f}[/]   "
        f"sev=[bold]{report.severity.value}[/]   "
        f"SLA=[bold]{report.sla_minutes}m[/]   "
        f"brand=[bold]{report.brand_impersonated or '—'}[/]"
    )
    console.print(f"[dim]{report.summary}[/dim]\n")

    if report.findings:
        tbl = Table(title="Detections", show_lines=False, header_style="bold cyan")
        tbl.add_column("Detector")
        tbl.add_column("Rule")
        tbl.add_column("Weight", justify="right")
        tbl.add_column("Detail")
        for f in sorted(report.findings, key=lambda x: x.weight, reverse=True):
            tbl.add_row(f.detector, f.rule, f"{f.weight:.2f}", f.detail)
        console.print(tbl)

    if report.iocs:
        console.print(f"\n[bold]IOCs[/] ({len(report.iocs)}):")
        for i in report.iocs[:12]:
            console.print(f"  • [cyan]{i.type.value}[/] {i.value}")
        if len(report.iocs) > 12:
            console.print(f"  … and {len(report.iocs) - 12} more")

    if report.mitre_techniques:
        console.print(f"\n[bold]MITRE ATT&CK:[/] {', '.join(report.mitre_techniques)}")

    console.print()


# ------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="PhishBuster UK orchestrator")
    parser.add_argument("--scan-file", help="Path to a .eml file to analyse")
    parser.add_argument("--daemon", action="store_true",
                        help="Run as a long-running M365 polling daemon")
    parser.add_argument("--once", action="store_true",
                        help="Run one M365 scan cycle and exit")
    args = parser.parse_args()

    init_db()
    engine = AnalysisEngine()

    if args.scan_file:
        scan_file(args.scan_file, engine)
    elif args.daemon or args.once:
        run_m365_scan(engine, once=args.once)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
