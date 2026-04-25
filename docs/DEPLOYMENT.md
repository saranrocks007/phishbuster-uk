# Deployment — PhishBuster UK

Two fully-supported deployment modes: **Docker Compose** (recommended) and **native Python**. A third **cloud-native** sketch is included for AKS/EKS.

---

## 1 · Prerequisites

- **Microsoft 365 tenant** with an app registration having these Graph application permissions (admin-consented):
  - `Mail.ReadWrite` — required to read and move messages
  - `Mail.Send` — required only if NCSC SERS forwarding is enabled
  - Recommended: restrict the app to a single mailbox via [Application Access Policy](https://learn.microsoft.com/en-us/graph/auth-limit-mailbox-access).
- **Python 3.12+** for native install (skip for Docker).
- **Docker 24+ & Compose v2** for containerised install.

---

## 2 · Configure

Copy the template and fill it in:

```bash
cp .env.example .env
```

Required variables:

| Variable | Purpose |
|----------|---------|
| `M365_TENANT_ID` / `M365_CLIENT_ID` / `M365_CLIENT_SECRET` | App-registration credentials |
| `M365_TARGET_MAILBOX` | Mailbox to poll (usually `phishing-report@yourcompany.co.uk`) |
| `DATABASE_URL` | `sqlite:///./data/phishbuster.db` by default, or `postgresql://user:pass@host/db` |
| `CLASSIFIER_THRESHOLD` | Default `0.65`; lower = more aggressive |
| `ENABLE_AUTO_QUARANTINE` | `true` to move phish to quarantine folder |
| `ENABLE_NCSC_SERS_FORWARDING` | `true` to forward confirmed phish to NCSC |
| `TICKETING_BACKEND` | `jira`, `servicenow`, or `stdout` |
| `JIRA_URL` / `JIRA_USER` / `JIRA_TOKEN` / `JIRA_PROJECT` | If using Jira |
| `SLACK_WEBHOOK_URL` / `TEAMS_WEBHOOK_URL` | Alert channels |
| `DASHBOARD_HOST` / `DASHBOARD_PORT` / `DASHBOARD_SECRET_KEY` | Console binding |

---

## 3 · Train the classifier

Ship with a baseline model before first run:

```bash
python scripts/train_model.py           # native
docker compose run --rm scanner python scripts/train_model.py   # docker
```

The curated UK corpus (HMRC / Royal Mail / NHS / NatWest lures + benign control) trains in seconds. A 5-fold cross-validated F1 score is printed; a healthy baseline is 0.90+.

---

## 4 · Initialise the database

```bash
python scripts/setup_db.py             # native
docker compose run --rm scanner python scripts/setup_db.py   # docker
```

---

## 5a · Run with Docker Compose (recommended)

```bash
docker compose build
docker compose up -d scanner dashboard
```

- Scanner polls the M365 mailbox every `M365_POLL_INTERVAL_SECONDS` (default 60s) and applies the full response pipeline.
- Dashboard is exposed on `http://localhost:8080`.
- Shared SQLite is held in the `pb-data` named volume.

For Postgres:

```bash
docker compose --profile postgres up -d
# Then set in .env:
DATABASE_URL=postgresql://phishbuster:changeme@postgres:5432/phishbuster
```

---

## 5b · Run natively

```bash
pip install -r requirements.txt

# One-shot scan of a .eml file
python -m src.main --scan-file tests/samples/hmrc_refund.eml

# Continuous daemon against M365
python -m src.main --daemon

# Single poll cycle (cron-friendly)
python -m src.main --once

# Dashboard
python -m src.dashboard.app
```

Cron example:

```
*/2 * * * * cd /opt/phishbuster-uk && /usr/bin/python3 -m src.main --once >> data/logs/cron.log 2>&1
```

---

## 6 · Reverse proxy + TLS

The built-in uvicorn server is intentionally plain HTTP on `:8080`. Front it with nginx / Traefik / Cloudflare Tunnel and terminate TLS there. Example nginx fragment:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

---

## 7 · Cloud-native sketch (AKS / EKS)

- Build and push the image to your registry.
- Use a `Deployment` per service (scanner, dashboard) with the same image.
- Persist the SQLite volume with a `PersistentVolumeClaim`, or prefer the managed Postgres path (Azure Database for PostgreSQL / RDS).
- Store M365 client secret in Azure Key Vault / AWS Secrets Manager; mount via CSI driver.
- Expose the dashboard via an `Ingress` with TLS; optionally restrict via Azure AD OAuth2 proxy.
- Emit logs to Log Analytics / CloudWatch and route critical incidents to PagerDuty.

---

## 8 · Upgrade path

1. Stop the scanner (`docker compose stop scanner`). Dashboard can keep running.
2. `git pull` / rebuild image.
3. Run any migrations (none required for now — schema is additive).
4. Restart: `docker compose up -d scanner dashboard`.

---

## 9 · Sanity checks post-deploy

```bash
curl -s http://localhost:8080/api/health                 # → {"status":"ok"}
curl -s http://localhost:8080/api/kpis?hours=24 | jq .   # KPI structure
python -m src.main --scan-file tests/samples/hmrc_refund.eml   # → PHISHING verdict
```

Then visit `http://localhost:8080/` and confirm the seeded incident appears in the stream.
