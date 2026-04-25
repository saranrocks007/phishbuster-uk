"""SQLAlchemy models and session management.

Design: denormalised-enough to power the dashboard quickly without
needing join-heavy queries. Incidents are the top-level record;
findings and iocs are child tables for analyst drill-down.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import datetime
from typing import Iterator, List, Optional

from sqlalchemy import (
    Column, DateTime, Float, ForeignKey, Integer, String, Text, Boolean,
    create_engine, event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from src.models import AnalysisReport


class Base(DeclarativeBase):
    pass


class IncidentRow(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    message_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    detected_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    responded_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    score: Mapped[float] = mapped_column(Float)
    sla_minutes: Mapped[int] = mapped_column(Integer)
    brand_impersonated: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    from_address: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    ticket_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    mitre_techniques: Mapped[str] = mapped_column(String(255), default="")
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)

    findings: Mapped[List["FindingRow"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    iocs: Mapped[List["IocRow"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    detector: Mapped[str] = mapped_column(String(64))
    rule: Mapped[str] = mapped_column(String(96))
    weight: Mapped[float] = mapped_column(Float)
    detail: Mapped[str] = mapped_column(Text)

    incident: Mapped[IncidentRow] = relationship(back_populates="findings")


class IocRow(Base):
    __tablename__ = "iocs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(String(1024), index=True)
    source_detector: Mapped[str] = mapped_column(String(64))
    tags: Mapped[str] = mapped_column(String(255), default="")

    incident: Mapped[IncidentRow] = relationship(back_populates="iocs")


class SenderProfile(Base):
    """Per-sender baseline used by the BEC detector.

    Tracks first-seen, message counts, hour-of-day histogram, recipients,
    and a TF-IDF-style style fingerprint of a sender's typical content.
    Updated on every BENIGN message; queried on every incoming message
    BEFORE the verdict is finalised.
    """
    __tablename__ = "sender_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sender_address: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    message_count: Mapped[int] = mapped_column(Integer, default=0)
    hour_histogram: Mapped[str] = mapped_column(String(255), default="")        # CSV "0,0,1,..." length 24
    recipients_seen: Mapped[str] = mapped_column(Text, default="")              # \n-separated list (capped)
    style_vocab: Mapped[str] = mapped_column(Text, default="")                  # JSON: top tokens + freq
    avg_subject_len: Mapped[float] = mapped_column(Float, default=0.0)
    avg_body_len: Mapped[float] = mapped_column(Float, default=0.0)


# ------------------------------------------------------------------
def _make_engine():
    url = os.getenv("DATABASE_URL", "sqlite:///./data/phishbuster.db")
    kwargs = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _pragma(dbapi_conn, _):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()
    return engine


_engine = None
_SessionLocal = None


def init_db() -> None:
    global _engine, _SessionLocal
    _engine = _make_engine()
    Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope() -> Iterator:
    global _SessionLocal
    if _SessionLocal is None:
        init_db()
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def persist_report(report: AnalysisReport,
                   from_address: Optional[str],
                   subject: Optional[str]) -> int:
    """Store a full report; returns the incident primary key."""
    with session_scope() as s:
        row = IncidentRow(
            message_id=report.message_id,
            received_at=report.received_at,
            detected_at=report.detected_at,
            responded_at=report.responded_at,
            verdict=report.verdict.value,
            severity=report.severity.value,
            score=report.score,
            sla_minutes=report.sla_minutes,
            brand_impersonated=report.brand_impersonated,
            from_address=from_address,
            subject=(subject or "")[:500],
            summary=report.summary,
            quarantined=report.quarantined,
            ticket_id=report.ticket_id,
            mitre_techniques=",".join(report.mitre_techniques),
        )
        for f in report.findings:
            row.findings.append(FindingRow(
                detector=f.detector, rule=f.rule,
                weight=f.weight, detail=f.detail,
            ))
        for i in report.iocs:
            row.iocs.append(IocRow(
                type=i.type.value, value=i.value[:1024],
                source_detector=i.source_detector,
                tags=",".join(i.tags),
            ))
        s.add(row)
        s.flush()
        return row.id
