# ============================================================
# PhishBuster UK — production Dockerfile
# Two-stage: wheel builder → slim runtime
# Runs as non-root, fixed timezone to Europe/London
# ============================================================
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libzbar0 libxml2-dev libxslt-dev poppler-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /wheels
COPY requirements.txt .
RUN pip wheel --wheel-dir=/wheels -r requirements.txt

# ------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=Europe/London \
    PB_TIMEZONE=Europe/London

# Runtime deps: libzbar (QR decode), poppler (pdf images), tzdata
RUN apt-get update && apt-get install -y --no-install-recommends \
        libzbar0 poppler-utils tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd --system --gid 1001 phishbuster \
    && useradd  --system --uid 1001 --gid 1001 --home /app --shell /usr/sbin/nologin phishbuster

WORKDIR /app
COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

COPY --chown=phishbuster:phishbuster . /app

# Writable volume for DB, logs, IOCs, model
RUN mkdir -p /app/data/logs /app/data/iocs /app/data/feeds \
    && chown -R phishbuster:phishbuster /app/data

USER phishbuster
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3).status == 200 else 1)"

# Default to dashboard; compose overrides with daemon for the scanner service
CMD ["sh", "-c", "python scripts/setup_db.py && python scripts/seed_demo_data.py --count 80 --days 14 || true; python -m src.dashboard.app"]
