# ThreatIQ — Threat Intelligence Platform

> Built with FastAPI + Gemini 2.0 Flash

ThreatIQ aggregates, categorizes, and visualizes security threat intelligence from
multiple open-source feeds in real time. It combines free RSS feeds, IP/hash lookup
APIs, AlienVault OTX pulses, and an AI-generated daily briefing into a single dashboard.

---

## Features

| Feature | Data Source | Free? |
|---|---|---|
| **Threat Feed** | 6 RSS sources (Krebs, BleepingComputer, SANS, THN, etc.) | No key needed |
| **Scrolling Ticker** | Latest threat headlines in stock-ticker format | No key needed |
| **SANS Stormcast** | Embedded Daily YouTube Podcast | Free/Public |
| **Charts** | Derived from RSS (category + source distribution) | No key needed |
| **IP Reputation** | AbuseIPDB | 1,000/day free |
| **File Hash Lookup** | VirusTotal (70+ AV engines) | 500/day free |
| **OTX Threat Pulses** | AlienVault OTX | Fully free |
| **AI Briefing** | Gemini 2.0 Flash | 1,500/day free |

---

## Setup

### Step 1 — Clone and Install
```bash
unzip threatiq.zip && cd threatiq
pip install -r requirements.txt
```

### Step 2 — Get API Keys (all free)

| Service | URL | Time |
|---|---|---|
| Gemini | https://aistudio.google.com | 30 seconds |
| AbuseIPDB | https://www.abuseipdb.com/register | 2 minutes |
| VirusTotal | https://www.virustotal.com/gui/sign-in | 2 minutes |
| AlienVault OTX | https://otx.alienvault.com | 2 minutes |

### Step 3 — Configure .env
```bash
cp .env.example .env
# Open .env and paste your API keys
```

### Step 4 — Run
```bash
uvicorn main:app --reload --port 8000
# Then open: http://localhost:8000
```

The `--reload` flag automatically restarts the server when you edit `main.py`.

---

## Project Structure

```
threatiq/
├── main.py            # FastAPI backend — all API routes
├── static/
│   └── index.html     # Single-page dashboard (HTML + CSS + JS)
├── requirements.txt   # Python dependencies
├── .env.example       # API key template
└── README.md          # This file
```

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Serves the dashboard HTML |
| `GET` | `/api/news` | Aggregated RSS articles. Params: `?category=Malware&limit=20` |
| `GET` | `/api/stats` | Statistics for charts (category + source distribution) |
| `GET` | `/api/ioc/ip/{ip}` | AbuseIPDB IP reputation check |
| `GET` | `/api/ioc/hash/{hash}` | VirusTotal file hash lookup |
| `GET` | `/api/otx/pulses` | AlienVault OTX threat pulses |
| `GET` | `/api/briefing` | Gemini AI threat intelligence briefing |
| `GET` | `/api/status` | Which API keys are configured |

---

## Possible Enhancements

- **Email alerts** — use SendGrid (free tier) to email the daily briefing to the team
- **MITRE ATT&CK mapping** — Gemini can map news articles to TTPs automatically
- **Domain reputation** — add VirusTotal domain lookup alongside IP/hash
- **Historical tracking** — store articles in SQLite to track threat trends over time
- **Export to PDF** — add a report generation button using `reportlab`
- **Hosting** — deploy to Google Cloud Run (free tier) using `gcloud run deploy`

---

## Key Concepts

**FastAPI** — Python web framework. `@app.get("/path")` creates an API endpoint.
**async/await** — Asynchronous code lets multiple API calls run simultaneously.
**RSS** — Really Simple Syndication. Structured news feed format, used by every major security blog.
**IOC** — Indicator of Compromise. Evidence of a security breach: malicious IPs, hashes, domains.
**AbuseIPDB** — Community database of IPs reported for malicious activity.
**VirusTotal** — Aggregates 70+ antivirus engines to analyze files/URLs/hashes.
**AlienVault OTX** — Open Threat Exchange. Crowd-sourced threat intel platform.
**TLP** — Traffic Light Protocol. Controls how threat intel is shared: WHITE=public, GREEN=community, AMBER=limited, RED=restricted.
