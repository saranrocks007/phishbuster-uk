"""SQLite-backed TTL cache for external API lookups.

Threat-intel APIs have low free-tier quotas (VirusTotal: 4 req/min,
500/day). This cache short-circuits repeat lookups within the TTL.

Stores JSON-serialisable payloads against namespaced keys.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

_CACHE_PATH = Path(os.getenv("PB_CACHE_PATH", "data/ti_cache.sqlite"))
_DEFAULT_TTL = int(os.getenv("THREAT_INTEL_CACHE_TTL_HOURS", "24")) * 3600


def _ensure_db() -> None:
    _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(_CACHE_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ti_cache (
                namespace TEXT NOT NULL,
                key       TEXT NOT NULL,
                payload   TEXT NOT NULL,
                stored_at INTEGER NOT NULL,
                PRIMARY KEY (namespace, key)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ti_cache_stored ON ti_cache(stored_at)")


@contextmanager
def _conn() -> Iterator[sqlite3.Connection]:
    _ensure_db()
    c = sqlite3.connect(_CACHE_PATH, timeout=5)
    try:
        yield c
        c.commit()
    finally:
        c.close()


def cache_get(namespace: str, key: str, ttl: int = _DEFAULT_TTL) -> Optional[Any]:
    """Return cached payload or None if missing/expired."""
    with _conn() as c:
        row = c.execute(
            "SELECT payload, stored_at FROM ti_cache WHERE namespace=? AND key=?",
            (namespace, key),
        ).fetchone()
    if not row:
        return None
    payload, stored_at = row
    if time.time() - stored_at > ttl:
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return None


def cache_put(namespace: str, key: str, value: Any) -> None:
    payload = json.dumps(value, default=str)
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO ti_cache (namespace, key, payload, stored_at) "
            "VALUES (?, ?, ?, ?)",
            (namespace, key, payload, int(time.time())),
        )


def cache_purge_expired(ttl: int = _DEFAULT_TTL) -> int:
    """Drop entries older than TTL. Returns rows removed."""
    cutoff = int(time.time()) - ttl
    with _conn() as c:
        cur = c.execute("DELETE FROM ti_cache WHERE stored_at < ?", (cutoff,))
        return cur.rowcount


def cache_clear(namespace: Optional[str] = None) -> int:
    with _conn() as c:
        if namespace:
            cur = c.execute("DELETE FROM ti_cache WHERE namespace=?", (namespace,))
        else:
            cur = c.execute("DELETE FROM ti_cache")
        return cur.rowcount
