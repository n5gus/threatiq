# ThreatIQ — Threat Intelligence Platform

> Built with FastAPI + Gemini 2.0 Flash · Google Hackathon @ The LAB Miami · March 2025

ThreatIQ aggregates, categorizes, and visualizes security threat intelligence from
multiple open-source feeds in real time. It combines free RSS feeds, IP/hash lookup
APIs, AlienVault OTX pulses, and an AI-generated daily briefing into a single dashboard.

---

## Features

| Feature | Data Source | Free? |
|---|---|---|
| **Threat Feed** | 6 RSS sources (Krebs, BleepingComputer, SANS, THN, etc.) | No key needed |
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

## Hackathon Demo Script

**1. Open the dashboard (30 seconds)**
> Show the stats cards loading in real-time, then the threat category donut chart.
> "This data is being pulled live from 6 security news sources with zero delay."

**2. Navigate to Threat Feed (45 seconds)**
> Click category filters to show only Malware, then Vulnerability.
> "The AI automatically categorizes every article using keyword analysis."

**3. IOC Lookup — IP (45 seconds)**
> Enter: `185.220.101.45` → show MALICIOUS verdict from AbuseIPDB
> Enter: `8.8.8.8` → show CLEAN verdict
> "This is the kind of check a SOC analyst does 50+ times a day — we made it one click."

**4. IOC Lookup — Hash (30 seconds)**
> Enter a known malware hash (find one on VirusTotal's public samples)
> Show the 70+ engine detection rate bar

**5. AI Briefing (1 minute)**
> Click Generate → let Gemini produce the briefing live
> "Gemini is synthesizing headlines from 6 sources into a SOC-ready briefing. This replaces
> 30 minutes of manual review every morning."

**6. OTX Pulses (30 seconds)**
> Show the threat pulse grid with TLP badges and IOC counts
> "This is crowd-sourced threat intel from 10,000+ security researchers globally."

**Total demo time: ~4 minutes**

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
