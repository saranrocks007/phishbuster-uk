"""PhishBuster UK — SOC Dashboard (FastAPI).

Serves KPI metrics, incident stream, verdict / brand / detector / MITRE
breakdowns, and per-incident drill-down. All queries run against the
SQLAlchemy store populated by the analysis pipeline.

KPIs implemented:
  * MTTD  — mean time to detect  (received_at → detected_at)
  * MTTR  — mean time to respond (detected_at → responded_at)
  * Dwell time — oldest unhandled phishing incident
  * FP rate — analyst-flagged false positives / confirmed phishing
  * SLA adherence — % of incidents responded within severity SLA window
  * Volume — total scanned, confirmed phishing, quarantined
  * Brand heatmap — UK brand impersonation frequency
  * Detector yield — which rules are earning their weight
  * MITRE coverage — ATT&CK techniques detected over time
  * IOC velocity — hourly IOC emission for the past 24h
"""
from __future__ import annotations

import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from src.database import FindingRow, IncidentRow, IocRow, init_db, session_scope
from src.models import Severity, Verdict
from src.utils import get_logger

log = get_logger(__name__)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(
    title="PhishBuster UK — SOC Console",
    description="AI-augmented phishing detection & response for Microsoft 365 (UK threat landscape).",
    version="1.0.0",
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# Severity → SLA minutes (mirrors detection_rules.yaml severity bands)
SLA_WINDOW = {
    Severity.CRITICAL.value: 15,
    Severity.HIGH.value: 60,
    Severity.MEDIUM.value: 240,
    Severity.LOW.value: 480,
    Severity.INFORMATIONAL.value: 1440,
}


# ---------------------------------------------------------------- lifecycle
@app.on_event("startup")
def _startup() -> None:
    init_db()
    log.info("dashboard.ready host=%s port=%s",
             os.getenv("DASHBOARD_HOST", "0.0.0.0"),
             os.getenv("DASHBOARD_PORT", "8080"))


# ---------------------------------------------------------------- helpers
def _window_start(hours: int) -> datetime:
    return datetime.utcnow() - timedelta(hours=hours)


def _mean_seconds(pairs: List[tuple]) -> Optional[float]:
    deltas = [(b - a).total_seconds() for a, b in pairs if a and b and b >= a]
    if not deltas:
        return None
    return sum(deltas) / len(deltas)


def _fmt_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds/60:.1f}m"
    if seconds < 86_400:
        return f"{seconds/3600:.1f}h"
    return f"{seconds/86_400:.1f}d"


# ---------------------------------------------------------------- UI routes
@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return TEMPLATES.TemplateResponse(request, "dashboard.html")


@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_detail(request: Request, incident_id: int) -> HTMLResponse:
    with session_scope() as s:
        row = s.get(IncidentRow, incident_id)
        if not row:
            raise HTTPException(404, "incident not found")
        findings = [
            {"detector": f.detector, "rule": f.rule,
             "weight": f.weight, "detail": f.detail}
            for f in row.findings
        ]
        iocs = [
            {"type": i.type, "value": i.value,
             "source": i.source_detector, "tags": i.tags}
            for i in row.iocs
        ]
        ctx = {
            "incident": {
                "id": row.id, "message_id": row.message_id,
                "received_at": row.received_at, "detected_at": row.detected_at,
                "responded_at": row.responded_at, "verdict": row.verdict,
                "severity": row.severity, "score": row.score,
                "sla_minutes": row.sla_minutes,
                "brand": row.brand_impersonated, "from_address": row.from_address,
                "subject": row.subject, "summary": row.summary,
                "quarantined": row.quarantined, "ticket_id": row.ticket_id,
                "mitre": [t for t in row.mitre_techniques.split(",") if t],
                "is_fp": row.is_false_positive,
            },
            "findings": findings,
            "iocs": iocs,
        }
    return TEMPLATES.TemplateResponse(request, "incident.html", ctx)


# ---------------------------------------------------------------- API
@app.get("/api/kpis")
def api_kpis(hours: int = Query(24, ge=1, le=720)) -> JSONResponse:
    since = _window_start(hours)
    with session_scope() as s:
        total = s.scalar(select(func.count(IncidentRow.id))
                         .where(IncidentRow.received_at >= since)) or 0
        phishing = s.scalar(select(func.count(IncidentRow.id)).where(
            IncidentRow.received_at >= since,
            IncidentRow.verdict == Verdict.PHISHING.value)) or 0
        suspicious = s.scalar(select(func.count(IncidentRow.id)).where(
            IncidentRow.received_at >= since,
            IncidentRow.verdict == Verdict.SUSPICIOUS.value)) or 0
        quarantined = s.scalar(select(func.count(IncidentRow.id)).where(
            IncidentRow.received_at >= since,
            IncidentRow.quarantined.is_(True))) or 0
        fps = s.scalar(select(func.count(IncidentRow.id)).where(
            IncidentRow.received_at >= since,
            IncidentRow.is_false_positive.is_(True))) or 0

        # Time-series pairs for MTTD/MTTR
        rows = s.execute(select(
            IncidentRow.received_at, IncidentRow.detected_at,
            IncidentRow.responded_at, IncidentRow.severity,
        ).where(IncidentRow.received_at >= since)).all()

        mttd = _mean_seconds([(r.received_at, r.detected_at) for r in rows])
        mttr = _mean_seconds([(r.detected_at, r.responded_at) for r in rows])

        # SLA adherence = responded within severity window
        on_time = 0
        sla_eligible = 0
        for r in rows:
            if r.detected_at and r.responded_at:
                sla_eligible += 1
                window = SLA_WINDOW.get(r.severity, 1440) * 60
                if (r.responded_at - r.detected_at).total_seconds() <= window:
                    on_time += 1
        sla_pct = (on_time / sla_eligible * 100.0) if sla_eligible else None

        # Dwell: oldest unresponded confirmed phishing
        open_rows = s.execute(select(IncidentRow.received_at).where(
            IncidentRow.verdict == Verdict.PHISHING.value,
            IncidentRow.responded_at.is_(None),
        )).all()
        dwell = None
        if open_rows:
            oldest = min(r.received_at for r in open_rows)
            dwell = (datetime.utcnow() - oldest).total_seconds()

        fp_rate = (fps / phishing * 100.0) if phishing else None

    return JSONResponse({
        "window_hours": hours,
        "total_scanned": total,
        "confirmed_phishing": phishing,
        "suspicious": suspicious,
        "quarantined": quarantined,
        "false_positives": fps,
        "mttd_seconds": mttd, "mttd_label": _fmt_duration(mttd),
        "mttr_seconds": mttr, "mttr_label": _fmt_duration(mttr),
        "dwell_seconds": dwell, "dwell_label": _fmt_duration(dwell),
        "fp_rate_pct": fp_rate,
        "sla_adherence_pct": sla_pct,
        "detection_rate_pct": (phishing + suspicious) / total * 100.0 if total else 0.0,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })


@app.get("/api/incidents")
def api_incidents(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    verdict: Optional[str] = None,
    severity: Optional[str] = None,
    brand: Optional[str] = None,
) -> JSONResponse:
    with session_scope() as s:
        stmt = select(IncidentRow).order_by(IncidentRow.received_at.desc())
        if verdict:
            stmt = stmt.where(IncidentRow.verdict == verdict)
        if severity:
            stmt = stmt.where(IncidentRow.severity == severity)
        if brand:
            stmt = stmt.where(IncidentRow.brand_impersonated == brand)
        stmt = stmt.limit(limit).offset(offset)
        rows = s.scalars(stmt).all()
        out = [{
            "id": r.id, "received_at": r.received_at.isoformat(),
            "verdict": r.verdict, "severity": r.severity, "score": r.score,
            "brand": r.brand_impersonated, "from": r.from_address,
            "subject": (r.subject or "")[:140],
            "quarantined": r.quarantined,
            "ticket_id": r.ticket_id,
            "is_fp": r.is_false_positive,
        } for r in rows]
    return JSONResponse({"items": out, "count": len(out)})


@app.post("/api/incidents/{incident_id}/false-positive")
def mark_false_positive(incident_id: int) -> JSONResponse:
    with session_scope() as s:
        row = s.get(IncidentRow, incident_id)
        if not row:
            raise HTTPException(404, "incident not found")
        row.is_false_positive = not row.is_false_positive
        return JSONResponse({"id": row.id, "is_false_positive": row.is_false_positive})


# ---------------------------------------------------------------- Chart APIs
@app.get("/api/charts/verdicts")
def chart_verdicts(hours: int = Query(24, ge=1, le=720)) -> JSONResponse:
    since = _window_start(hours)
    with session_scope() as s:
        rows = s.execute(
            select(IncidentRow.verdict, func.count(IncidentRow.id))
            .where(IncidentRow.received_at >= since)
            .group_by(IncidentRow.verdict)
        ).all()
    counts = {v.value: 0 for v in Verdict}
    for verdict, count in rows:
        counts[verdict] = count
    return JSONResponse(counts)


@app.get("/api/charts/brands")
def chart_brands(hours: int = Query(168, ge=1, le=2160)) -> JSONResponse:
    """UK brand impersonation heatmap (default 7-day window)."""
    since = _window_start(hours)
    with session_scope() as s:
        rows = s.execute(
            select(IncidentRow.brand_impersonated, func.count(IncidentRow.id))
            .where(IncidentRow.received_at >= since,
                   IncidentRow.brand_impersonated.is_not(None))
            .group_by(IncidentRow.brand_impersonated)
            .order_by(func.count(IncidentRow.id).desc())
            .limit(15)
        ).all()
    return JSONResponse([{"brand": b, "count": c} for b, c in rows])


@app.get("/api/charts/detectors")
def chart_detectors(hours: int = Query(168, ge=1, le=2160)) -> JSONResponse:
    """Which detectors are earning their weight? Summed weight per detector."""
    since = _window_start(hours)
    with session_scope() as s:
        rows = s.execute(
            select(FindingRow.detector,
                   func.count(FindingRow.id),
                   func.sum(FindingRow.weight))
            .join(IncidentRow, IncidentRow.id == FindingRow.incident_id)
            .where(IncidentRow.received_at >= since)
            .group_by(FindingRow.detector)
            .order_by(func.sum(FindingRow.weight).desc())
        ).all()
    return JSONResponse([
        {"detector": d, "hits": int(h), "total_weight": round(float(w or 0), 3)}
        for d, h, w in rows
    ])


@app.get("/api/charts/timeline")
def chart_timeline(hours: int = Query(24, ge=1, le=168)) -> JSONResponse:
    """Hourly bucket: received / phishing / suspicious counts."""
    since = _window_start(hours)
    with session_scope() as s:
        rows = s.execute(
            select(IncidentRow.received_at, IncidentRow.verdict)
            .where(IncidentRow.received_at >= since)
        ).all()
    buckets: Dict[str, Dict[str, int]] = {}
    for i in range(hours):
        b = (since + timedelta(hours=i)).strftime("%Y-%m-%d %H:00")
        buckets[b] = {"total": 0, "phishing": 0, "suspicious": 0}
    for received, verdict in rows:
        key = received.strftime("%Y-%m-%d %H:00")
        if key in buckets:
            buckets[key]["total"] += 1
            if verdict == Verdict.PHISHING.value:
                buckets[key]["phishing"] += 1
            elif verdict == Verdict.SUSPICIOUS.value:
                buckets[key]["suspicious"] += 1
    return JSONResponse([
        {"bucket": k, **v} for k, v in sorted(buckets.items())
    ])


@app.get("/api/charts/mitre")
def chart_mitre(hours: int = Query(720, ge=1, le=2160)) -> JSONResponse:
    """ATT&CK technique coverage (30-day default)."""
    since = _window_start(hours)
    with session_scope() as s:
        rows = s.execute(
            select(IncidentRow.mitre_techniques)
            .where(IncidentRow.received_at >= since,
                   IncidentRow.mitre_techniques != "")
        ).all()
    counter: Counter = Counter()
    for (techniques,) in rows:
        for t in techniques.split(","):
            if t:
                counter[t] += 1
    descriptions = {
        "T1566.001": "Spearphishing Attachment",
        "T1566.002": "Spearphishing Link",
        "T1566.003": "Spearphishing via Service",
        "T1598.003": "Spearphishing for Information",
        "T1656":     "Impersonation",
        "T1204.002": "Malicious File (User Execution)",
        "T1534":     "Internal Spearphishing",
    }
    return JSONResponse([
        {"technique": t, "name": descriptions.get(t, "—"), "count": c}
        for t, c in counter.most_common(12)
    ])


@app.get("/api/charts/ioc-velocity")
def chart_ioc_velocity(hours: int = Query(24, ge=1, le=168)) -> JSONResponse:
    since = _window_start(hours)
    with session_scope() as s:
        rows = s.execute(
            select(IocRow.type, IncidentRow.received_at)
            .join(IncidentRow, IncidentRow.id == IocRow.incident_id)
            .where(IncidentRow.received_at >= since)
        ).all()
    by_type: Dict[str, int] = defaultdict(int)
    for t, _ in rows:
        by_type[t] += 1
    return JSONResponse([
        {"type": t, "count": c}
        for t, c in sorted(by_type.items(), key=lambda x: -x[1])
    ])


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


# ---------------------------------------------------------------- entrypoint
def serve() -> None:
    import uvicorn
    host = os.getenv("DASHBOARD_HOST", "0.0.0.0")
    port = int(os.getenv("DASHBOARD_PORT", "8080"))
    uvicorn.run("src.dashboard.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    serve()
