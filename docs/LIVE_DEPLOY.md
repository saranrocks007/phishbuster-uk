# Live URL Deployment Guide

For the portfolio / demo case: get a public URL up that recruiters and reviewers can click through. Three paths from cheapest to most permanent.

---

## Option 1 — Fly.io (recommended for portfolio)

**Why:** Free hobby tier with a London region, two free 256MB VMs (we use one for the dashboard, one for the scanner), persistent volumes, real `.fly.dev` URL with TLS.

### One-time setup

```bash
# 1. Install flyctl
curl -L https://fly.io/install.sh | sh

# 2. Sign up / log in
flyctl auth signup       # or: flyctl auth login

# 3. Launch (this is in the repo already as fly.toml)
flyctl launch --no-deploy --copy-config --name phishbuster-uk --region lhr

# 4. Create the persistent volume for SQLite + classifier model
flyctl volumes create pb_data --size 1 --region lhr

# 5. Set secrets (only what you actually use)
flyctl secrets set \
    DASHBOARD_SECRET_KEY=$(openssl rand -hex 32) \
    M365_TENANT_ID=disabled \
    M365_CLIENT_ID=disabled \
    M365_CLIENT_SECRET=disabled

# Optional: TI keys, urlscan, etc.
# flyctl secrets set VIRUSTOTAL_API_KEY=xxx ABUSEIPDB_API_KEY=xxx ENABLE_THREAT_INTEL=true

# 6. Deploy
flyctl deploy --strategy rolling
```

### Seed demo data on first deploy

```bash
flyctl ssh console --command "python scripts/seed_demo_data.py --count 80 --days 14"
```

### Get the URL

```bash
flyctl status
# → https://phishbuster-uk.fly.dev
```

### Auto-deploy on git push

Add a Fly API token to your GitHub repo (Settings → Secrets → Actions → `FLY_API_TOKEN`):

```bash
flyctl auth token | xargs -I{} echo "Add this as FLY_API_TOKEN: {}"
```

The included `.github/workflows/deploy.yml` will then deploy on every push to `main`.

---

## Option 2 — Render.com

**Why:** Even simpler than Fly — connect repo, Render auto-detects the Dockerfile. Free tier sleeps after 15 min idle (loads in ~10s on next visit).

1. Sign in at https://render.com with GitHub.
2. New → Web Service → Connect your `phishbuster-uk` repo.
3. Settings:
   - Environment: Docker
   - Region: Frankfurt (closest free EU)
   - Plan: Free
   - Health check path: `/api/health`
4. Add a free PostgreSQL database (Render → New → PostgreSQL → Free tier) if you want production-grade persistence; otherwise the SQLite-on-disk default works but resets on redeploy.
5. Set environment variables in the Render dashboard (same vars as `.env.example`).

To seed demo data: open the Render shell tab and run `python scripts/seed_demo_data.py`.

---

## Option 3 — Oracle Cloud Free Tier (24/7, no sleeping)

**Why:** Forever-free Ampere ARM VM (4 OCPU, 24GB RAM). Best for "always on" without weird cold-start behaviour.

```bash
# After provisioning your free Oracle VM (Ubuntu 22.04 ARM):
ssh ubuntu@<your-oracle-ip>

sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2 git
sudo usermod -aG docker ubuntu && newgrp docker

git clone https://github.com/saranrocks007/phishbuster-uk.git
cd phishbuster-uk

cp .env.example .env
# edit .env — at minimum set DASHBOARD_SECRET_KEY

docker compose build
docker compose up -d dashboard
docker compose run --rm dashboard python scripts/seed_demo_data.py --count 80 --days 14

# Open Oracle's security list to allow inbound TCP 8080 from 0.0.0.0/0
# (or 80/443 if you front it with nginx + Let's Encrypt)
```

For a real domain with TLS:

```bash
# Free domain via Cloudflare or Duck DNS
# Then:
sudo apt-get install -y nginx certbot python3-certbot-nginx
sudo certbot --nginx -d phishbuster.your-domain.com
# Edit /etc/nginx/sites-enabled/default to proxy_pass to localhost:8080
```

---

## Option 4 — Cloudflare Tunnel (instant, no server needed)

**Why:** When you just need a temporary URL for an interview demo. Runs from your own laptop.

```bash
# Install cloudflared
brew install cloudflared             # macOS
# or apt: https://pkg.cloudflare.com/

# Run PhishBuster locally
docker compose up -d

# Tunnel it
cloudflared tunnel --url http://localhost:8080
# → https://random-name.trycloudflare.com
```

That's it — no account, no DNS, just a temporary URL while the tunnel is open.

---

## Securing the public dashboard

The dashboard has **no built-in authentication** (a deliberate scope limitation — auth would couple it to a specific identity provider). For a public demo, that's fine — it's read-only public data. For anything real:

### Option A — HTTP basic auth via reverse proxy

```nginx
location / {
    auth_basic "PhishBuster UK";
    auth_basic_user_file /etc/nginx/.htpasswd;
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

Generate the password file:

```bash
sudo apt-get install -y apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd analyst
```

### Option B — Cloudflare Access (zero-trust, free for ≤50 users)

In Cloudflare Zero Trust → Access → Applications → Add an application → Self-hosted → enter your domain → set allowed identity providers (Google, GitHub, email OTP).

This is what you want for any real production deployment.

### Option C — Tailscale (private network, no public URL)

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
# Now reachable at http://<your-machine-name>.tail-scale.ts.net:8080
# Only authenticated users on your tailnet can reach it.
```

---

## Cost summary

| Path | Setup time | Monthly cost | Always-on |
|------|------------|--------------|-----------|
| Fly.io free | 5 min | £0 | Yes (with auto-stop) |
| Render free | 3 min | £0 | Sleeps after 15 min idle |
| Oracle Cloud free | 30 min | £0 | Yes |
| Cloudflare Tunnel | 30 sec | £0 | Only while terminal open |
| Fly.io paid (recommended for production) | 5 min | £4–8 | Yes |
| AWS / GCP managed | 60 min | £20+ | Yes |

For a CV / portfolio piece, Fly.io free tier is the right call.

---

## Demo-data hygiene

The seeded incidents all have `summary` starting with `[DEMO]`. To wipe them later:

```bash
# Local
python scripts/seed_demo_data.py --reset --count 0

# Fly.io
flyctl ssh console --command "python scripts/seed_demo_data.py --reset --count 0"
```

If you connect a real M365 mailbox afterward, real incidents will appear alongside the demo ones — they're filterable in the dashboard's stream and easily distinguishable by the summary prefix.
