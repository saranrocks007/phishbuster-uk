"""Structured logging for PhishBuster UK.

UK GDPR-aware: PII in message bodies is hashed before logging.
"""
from __future__ import annotations

import hashlib
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


def _hash_pii(value: str) -> str:
    """Return a short, stable hash suitable for logs."""
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def get_logger(name: str = "phishbuster") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logger.setLevel(level)

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    logger.addHandler(stream)

    log_dir = Path(os.getenv("PB_DATA_DIR", "./data")) / "logs"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(
            log_dir / "phishbuster.log",
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError:
        # Degrade gracefully if log dir is not writable.
        pass

    logger.propagate = False
    return logger


# Re-export helper for callers
hash_pii = _hash_pii
