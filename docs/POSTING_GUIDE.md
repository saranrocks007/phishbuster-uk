# 📋 Step-by-Step: Posting PhishBuster UK to GitHub

> Your complete checklist from "I have the files" to "live URL in my CV". No command line beyond the absolutely necessary.

This guide assumes you have:
- The `phishbuster-uk` folder on your computer
- A GitHub account (`saranrocks007`)
- 30–45 minutes

---

## 📍 Phase 1: Prepare on your computer (5 minutes)

### Step 1.1 — Show hidden files

GitHub upload won't include hidden files unless you can see them.

**Windows:**
1. Open File Explorer
2. Click **View** at the top → tick **Hidden items**

**Mac:**
1. Open Finder
2. Press **Cmd + Shift + . (period)**

You should now see files like `.dockerignore`, `.gitignore`, and the `.github` folder inside your `phishbuster-uk` directory.

### Step 1.2 — Verify you have all the key files

Open the `phishbuster-uk` folder. You should see (at minimum):

- ✅ `README.md`
- ✅ `LICENSE`
- ✅ `SECURITY.md`
- ✅ `CONTRIBUTING.md`
- ✅ `Dockerfile`
- ✅ `docker-compose.yml`
- ✅ `fly.toml`
- ✅ `requirements.txt`
- ✅ `.env.example`
- ✅ `.gitignore`
- ✅ `.dockerignore`
- ✅ `.github/` folder (with `workflows/` and `ISSUE_TEMPLATE/` inside)
- ✅ `src/` folder
- ✅ `config/` folder
- ✅ `tests/` folder
- ✅ `docs/` folder
- ✅ `scripts/` folder
- ✅ `data/` folder

If anything is missing, get it sorted before going further.

### Step 1.3 — Delete any local secrets

**Critical:** if there's a `.env` file (without the `.example` suffix) in the folder, **delete it now**. It might contain real API keys you don't want on GitHub.

The `.env.example` file should stay — it's the template, not the real config.

---

## 📍 Phase 2: Create the GitHub repository (5 minutes)

### Step 2.1 — Go to the new repo page

Open: **https://github.com/new**

Make sure you're logged in as `saranrocks007` (top-right corner shows your avatar).

### Step 2.2 — Fill in the form

| Field | Value |
|-------|-------|
| **Owner** | `saranrocks007` |
| **Repository name** | `phishbuster-uk` |
| **Description** | `🛡️ AI-augmented phishing detection & response automation for Microsoft 365 — tuned to the UK threat landscape (HMRC, Royal Mail, NHS, NatWest impersonation). 10-detector pipeline with auto-quarantine, ticketing, and SOC dashboard.` |
| **Public/Private** | **Public** ⭐ |
| **Add a README file** | ❌ DO NOT TICK |
| **Add .gitignore** | ❌ DO NOT TICK (we have our own) |
| **Choose a license** | ❌ DO NOT TICK (we have our own) |

Click the green **Create repository** button.

### Step 2.3 — Don't close this page yet

You'll see an empty repo page with instructions. Look for the link that says **"uploading an existing file"** (about halfway down). Don't click it yet — first we'll prepare the upload in the next phase.

---

## 📍 Phase 3: Upload all files (10 minutes)

### Step 3.1 — Upload the root files first

GitHub web upload works better in batches. Start with the root folder files.

1. On the empty GitHub repo page, click **"uploading an existing file"**.
2. Open your `phishbuster-uk` folder on your computer.
3. **Select these specific files** (Ctrl/Cmd-click to multi-select):
   - `README.md`
   - `LICENSE`
   - `SECURITY.md`
   - `CONTRIBUTING.md`
   - `Dockerfile`
   - `docker-compose.yml`
   - `fly.toml`
   - `requirements.txt`
   - `.env.example`
   - `.gitignore`
   - `.dockerignore`
4. **Drag them onto the GitHub upload area.**
5. Wait for them to upload (10–30 seconds).
6. Scroll to the bottom:
   - **Commit message:** `Initial commit — root files`
   - Select **"Commit directly to the main branch"**
   - Click **Commit changes**

### Step 3.2 — Upload the source code folder (`src/`)

1. On your repo page (now showing your initial files), click **Add file** → **Upload files**.
2. Drag your entire `src/` folder onto the upload area.
3. **Important:** GitHub preserves folder structure when you drag a folder.
4. Commit message: `Add source code — analysis engine, dashboard, ingestion`
5. Click **Commit changes**.

### Step 3.3 — Upload `config/`, `tests/`, `docs/`, `scripts/`

Repeat the same process for each folder. Use these commit messages:

| Folder | Commit message |
|--------|---------------|
| `config/` | `Add config — UK brands, detection rules, YARA starter set` |
| `tests/` | `Add test suite — 46 integration tests + EML fixtures` |
| `docs/` | `Add documentation — architecture, deployment, runbook, threat model` |
| `scripts/` | `Add operational scripts — DB setup, training, demo seeder, corpus loader` |

### Step 3.4 — Upload the `.github/` folder

This one is tricky because hidden folders sometimes don't drag properly.

**If dragging `.github/` works:** great, do it. Commit message: `Add CI/CD workflows — pytest, CodeQL, Fly deploy`

**If dragging doesn't work:** create the files manually:

1. On the repo page, click **Add file** → **Create new file**.
2. In the filename box, type: `.github/workflows/ci.yml` (the slashes create folders)
3. Open `.github/workflows/ci.yml` from your computer in Notepad (Windows) or TextEdit (Mac).
4. Copy all the content and paste it into GitHub.
5. Commit message: `Add CI workflow`
6. **Commit directly to main**

Repeat for:
- `.github/workflows/codeql.yml`
- `.github/workflows/deploy.yml`
- `.github/ISSUE_TEMPLATE/bug_report.yml`
- `.github/ISSUE_TEMPLATE/feature_request.yml`

### Step 3.5 — Upload the `data/` folder (just the empty subdirs)

The `data/` folder needs to exist but mostly empty (its contents are runtime-generated). Create a placeholder:

1. Click **Add file** → **Create new file**
2. Filename: `data/.gitkeep`
3. Leave content blank
4. Commit message: `Add data directory placeholder`

You can also upload `data/classifier.joblib` if you want the trained model bundled (it's only ~169KB).

### Step 3.6 — Verify everything uploaded

Go back to the main repo page. The file tree should look like this:

```
phishbuster-uk/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   └── workflows/
├── config/
├── data/
├── docs/
├── scripts/
├── src/
├── tests/
├── .dockerignore
├── .env.example
├── .gitignore
├── CONTRIBUTING.md
├── Dockerfile
├── LICENSE
├── README.md
├── SECURITY.md
├── docker-compose.yml
├── fly.toml
└── requirements.txt
```

If anything is missing, repeat the relevant step. The README should be displaying nicely below the file list, with badges, the live-demo link, and the detection table.

---

## 📍 Phase 4: Polish the repo (10 minutes)

### Step 4.1 — Add topics for discoverability

1. On the main repo page, click the **⚙️ gear icon** next to "About" (top right).
2. In the **Topics** field, paste this list:

```
phishing-detection
cybersecurity
soc
microsoft-365
nlp
threat-intelligence
yara
fastapi
python
detection-engineering
uk
email-security
bec-detection
mitre-attack
incident-response
quishing
```

3. **Description** field: paste the same description from Step 2.2 if it's not already there.
4. **Website**: leave blank for now (you'll add the live URL after Phase 5).
5. Tick **Releases** and **Packages**.
6. Click **Save changes**.

### Step 4.2 — Pin the repo to your profile

1. Go to your profile: **https://github.com/saranrocks007**
2. Click **Customize your pins** (button on the right side)
3. Tick `phishbuster-uk`
4. Save

Now `phishbuster-uk` appears at the top of your profile.

### Step 4.3 — Enable Dependabot

1. On your repo, click **Settings** tab
2. Scroll down to **Code security and analysis** in the left sidebar
3. Enable:
   - ✅ Dependabot alerts
   - ✅ Dependabot security updates
   - ✅ Dependabot version updates
4. Set up: it'll auto-create a `dependabot.yml` for you

### Step 4.4 — Verify GitHub Actions are running

1. Click the **Actions** tab.
2. You should see runs for "CI" and "CodeQL" appearing.
3. The first CI run might fail because the deploy workflow needs the `FLY_API_TOKEN` secret, which we'll add in Phase 5.
4. The CodeQL workflow should pass on the first try.

If CI fails: don't panic. Click into the failed run, screenshot the error message — many failures are environment-specific and easy to fix.

### Step 4.5 — Create the first release

This makes it easy for people to "Download v1.0" without cloning.

1. On the main repo page, click **Releases** in the right sidebar
2. Click **Create a new release**
3. **Tag:** `v1.0.0`
4. **Release title:** `v1.0 — UK phishing detection pipeline + SOC dashboard`
5. **Description:** paste this:

```markdown
## 🎉 First public release of PhishBuster UK

10-detector phishing analysis pipeline for Microsoft 365, tuned to UK threats.

### What's in this release

- ✅ 10 detectors (header forensics, URL analysis, UK lure detection, NLP classifier, quishing, AI-content heuristics, threat intelligence, domain age, URL sandbox, attachment scanner, BEC sender anomaly)
- ✅ FastAPI + Chart.js SOC dashboard with MTTD/MTTR/SLA/brand heatmap KPIs
- ✅ Docker deployment + GitHub Actions CI/CD
- ✅ NCSC SERS auto-forwarding bridge
- ✅ STIX 2.1 IOC export
- ✅ 46-test integration suite
- ✅ Honest threat model documentation

### Quick start

```bash
git clone https://github.com/saranrocks007/phishbuster-uk.git
cd phishbuster-uk
docker compose up -d
docker compose run --rm dashboard python scripts/seed_demo_data.py
open http://localhost:8080
```

### Live demo

🌐 https://saranrocks007-phishbuster-uk.hf.space

### Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Live Deploy](docs/LIVE_DEPLOY.md)
- [Runbook](docs/RUNBOOK.md)

### Acknowledgements

Built by [@saranrocks007](https://github.com/saranrocks007). Apache 2.0 licensed.
```

6. Click **Publish release**.

---

## 📍 Phase 5: Get a live URL (15 minutes)

I recommend **Hugging Face Spaces** because it doesn't require a credit card and has persistent storage.

### Step 5.1 — Sign up for Hugging Face

1. Go to **https://huggingface.co/join**
2. Sign up with your email or GitHub
3. Verify your email

### Step 5.2 — Create a new Space

1. Go to **https://huggingface.co/new-space**
2. Fill in:
   - **Owner:** your username
   - **Space name:** `phishbuster-uk`
   - **License:** Apache 2.0
   - **Select Space SDK:** **Docker** → **Blank**
   - **Hardware:** CPU basic (free)
   - **Public/Private:** Public
3. Click **Create Space**

### Step 5.3 — Configure the Space

1. On your new Space page, click the **Files** tab.
2. Click **+ Add file** → **Upload files**.
3. Upload all your `phishbuster-uk` files (same as Phase 3 — drag and drop).

**Or, much easier:** link from GitHub.
1. Click **Settings** tab on your Space.
2. Scroll to **Linked repository**.
3. Connect to your GitHub `phishbuster-uk` repo.
4. Hugging Face will sync automatically on every push.

### Step 5.4 — Update the README header for HF Spaces

HF Spaces needs a YAML header at the top of `README.md` to know about port and config.

1. On your Space, click **Files** → click `README.md` → **Edit**
2. At the very top (line 1), paste this:

```yaml
---
title: PhishBuster UK
emoji: 🛡️
colorFrom: red
colorTo: indigo
sdk: docker
app_port: 8080
pinned: true
license: apache-2.0
short_description: AI-augmented phishing detection for Microsoft 365 (UK-focused)
---

```

3. Leave a blank line after the closing `---`.
4. Keep all your existing README content below.
5. Click **Commit changes to main**.

### Step 5.5 — Wait for build

The Space will start building automatically. Click the **Logs** tab (top right) to watch.

First build takes 5–8 minutes. When you see:
```
INFO:     Uvicorn running on http://0.0.0.0:8080
```

…click the **App** tab and your dashboard should load.

### Step 5.6 — Seed the demo data

The Space terminal isn't directly accessible on the free tier, so we make seeding automatic.

1. Files → click `Dockerfile` → Edit
2. Find the `CMD` line at the bottom (looks like `CMD ["python", "-m", "src.dashboard.app"]`)
3. Replace it with:

```dockerfile
CMD ["sh", "-c", "python scripts/seed_demo_data.py --count 80 --days 14 || true; python -m src.dashboard.app"]
```

4. Commit to main.

The Space rebuilds (5 minutes), seeds 80 demo incidents on first run, and starts the dashboard. The `|| true` means subsequent restarts won't fail when data already exists.

### Step 5.7 — Get your live URL

Your URL is:

```
https://YOUR-USERNAME-phishbuster-uk.hf.space
```

(Replace `YOUR-USERNAME` with your HF username — typically `saranrocks007`.)

Visit it in a browser and confirm the dashboard loads with seeded data.

---

## 📍 Phase 6: Connect Live URL to README (3 minutes)

### Step 6.1 — Update the live demo link

1. Go to your GitHub repo → click `README.md` → click the pencil ✏️ icon
2. Find this line at the top:
   ```
   **[🌐 Live Demo](https://saranrocks007-phishbuster-uk.hf.space)**
   ```
3. Make sure the URL exactly matches what HF gave you.
4. Same for the "Live Demo" link near the bottom.
5. Scroll down → **Commit changes** → **Commit directly to main**

### Step 6.2 — Add the URL to "About"

1. On your GitHub repo's main page, click the **⚙️ gear icon** next to "About"
2. **Website:** paste your HF URL
3. **Save changes**

The website now appears at the top of your repo's right sidebar.

---

## 📍 Phase 7: Promote (variable time)

### Step 7.1 — Add to your portfolio

Update **https://saransengottuvelportfolio.vercel.app** with a project entry:

- **Title:** PhishBuster UK
- **Description:** UK-focused phishing detection for Microsoft 365
- **Live demo:** Your HF URL
- **GitHub:** `https://github.com/saranrocks007/phishbuster-uk`
- **Screenshot:** take one of the dashboard

### Step 7.2 — Post on LinkedIn

Use this template (customise as needed):

> 🚀 Just open-sourced **PhishBuster UK** — a SOC-grade phishing detection & response platform built for the UK threat landscape.
>
> 🎯 **What it does:**
> A 10-detector pipeline (NLP classifier, header forensics, threat intelligence from VirusTotal/AbuseIPDB/URLhaus/PhishTank, YARA-based attachment scanning, BEC sender anomaly detection, live URL sandboxing, quishing, AI-content heuristics, domain age, UK brand impersonation) integrated with Microsoft 365 / Graph API. Auto-quarantines confirmed phishing, raises tickets, alerts SOC, exports STIX 2.1 IOCs, and forwards to NCSC.
>
> 🇬🇧 **Why UK-specific:**
> Generic global tools under-detect HMRC, Royal Mail, NatWest, NHS, and DVLA impersonation. PhishBuster UK is purpose-built for these patterns, with NCSC SERS auto-forwarding and Cyber Essentials Plus evidence packs.
>
> 🛠️ **Stack:** Python · scikit-learn · FastAPI · SQLAlchemy · YARA · Docker · Hugging Face Spaces
>
> 🌐 **Live demo:** [your URL]
> 📦 **GitHub:** https://github.com/saranrocks007/phishbuster-uk
>
> Apache 2.0 licensed — contributions welcome.
>
> Open to opportunities in detection engineering / SOC roles, particularly in the Netherlands and Ireland 🇳🇱🇮🇪
>
> #cybersecurity #detectionengineering #phishing #soc #infosec #opensource #python #microsoft365 #ukcybersec

### Step 7.3 — Share on Reddit

See the previous reply for full subreddit-specific drafts. Tier 1 subs to target:
- **r/netsec** (most strict — needs technical depth)
- **r/cybersecurity** (more accessible)
- **r/blueteamsec** (small, high signal)

Don't post all on the same day — spread over 7–10 days to avoid spam filters.

### Step 7.4 — Submit to Show HN

If you want maximum reach, post to Hacker News:
- URL: https://news.ycombinator.com/submit
- Title: `Show HN: PhishBuster UK – Phishing detection for Microsoft 365 tuned to UK lures`
- URL: your GitHub repo
- Best timing: Tuesday/Wednesday/Thursday morning UK time (catches both UK afternoon and US morning)

---

## ✅ Final checklist

After everything is done, verify:

- [ ] Repo is public at `https://github.com/saranrocks007/phishbuster-uk`
- [ ] README displays badges, live demo link, and detection table correctly
- [ ] All 5 GitHub Actions workflows are visible in the Actions tab
- [ ] CodeQL has run and passed at least once
- [ ] Repo has 16+ topics in the About section
- [ ] Repo has a Website link pointing to your HF URL
- [ ] Live URL works and shows seeded dashboard with KPIs / brand heatmap / incident stream
- [ ] Repo is pinned on your GitHub profile
- [ ] v1.0.0 release is published
- [ ] Portfolio site has the project listed
- [ ] LinkedIn post published with link

---

## 🆘 If something goes wrong

| Problem | Solution |
|---------|---------|
| GitHub upload skipped some files | Upload them in smaller batches. Some browsers cap at ~50 files per drag. |
| `.github` folder didn't upload | Create files manually via "Create new file" — paste contents from local files |
| README has weird formatting | View raw → check for missing closing brackets in tables |
| HF Space build fails | Click Logs tab → screenshot the error → file an issue or ask me |
| Dashboard URL shows "no module named src" | Dockerfile path issue — check the WORKDIR is `/app` |
| Demo data doesn't appear | Build process didn't run seed step; check Logs for the "Seeded N incidents" message |
| CI workflow fails | Click into the run → if it's the deploy workflow without `FLY_API_TOKEN`, that's expected — only matters if you want Fly.io deploys |

---

## 📞 Need help?

If you get stuck anywhere, send me:
1. Which step you're on
2. Screenshot of the error
3. What you've already tried

Most issues take 2–3 minutes to fix once we see the actual error message.

---

**Time budget summary:**

| Phase | Time |
|-------|------|
| 1. Prepare on computer | 5 min |
| 2. Create GitHub repo | 5 min |
| 3. Upload all files | 10 min |
| 4. Polish repo | 10 min |
| 5. Live URL on HF Spaces | 15 min |
| 6. Connect live URL to README | 3 min |
| 7. Promote (LinkedIn etc.) | varies |
| **Total** | **~50 min** |

Good luck! 🚀
