# =============================================================================
# main.py — ThreatIQ Backend
# =============================================================================
#
# WHAT IS THIS FILE?
# This is the web server. It does two things:
#   1. Serves the dashboard HTML at http://localhost:8000/
#   2. Provides REST API endpoints that the dashboard calls via JavaScript
#
# TECH STACK:
#   FastAPI  — modern Python web framework (much faster and cleaner than Flask)
#   uvicorn  — ASGI server that runs FastAPI (think: the thing that actually
#              listens on a port and accepts HTTP connections)
#   feedparser — parses RSS/Atom feeds without any API key
#   httpx    — async HTTP client for calling external APIs (AbuseIPDB, etc.)
#   google-genai — Gemini SDK for AI-powered threat briefings
#
# HOW TO RUN:
#   uvicorn main:app --reload --port 8000
#   Then open: http://localhost:8000
#
# WHY FASTAPI INSTEAD OF FLASK?
#   FastAPI is async by default, which means it can handle multiple API
#   calls (RSS feeds, external APIs) simultaneously instead of waiting
#   for each one to finish before starting the next. This makes the
#   dashboard load much faster.
# =============================================================================

import asyncio
import os
import re
from collections import defaultdict
from datetime import datetime, timezone

import feedparser          # Parses RSS/Atom feeds
import google.genai as genai
import httpx               # Async HTTP client
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

# Load .env file into environment variables
load_dotenv()

# =============================================================================
# ── 1. CONFIGURATION ──────────────────────────────────────────────────────────
# =============================================================================

# Read API keys from environment — NEVER hardcode these in source code
GOOGLE_API_KEY  = os.environ.get("GOOGLE_API_KEY")
ABUSEIPDB_KEY   = os.environ.get("ABUSEIPDB_KEY")
VIRUSTOTAL_KEY  = os.environ.get("VIRUSTOTAL_KEY")
OTX_KEY         = os.environ.get("OTX_KEY")

# Configure the Gemini SDK only if we have a key
if GOOGLE_API_KEY:
    genai.configure(api_key=GOOGLE_API_KEY)

# =============================================================================
# ── 2. DATA SOURCES ───────────────────────────────────────────────────────────
# These RSS feeds require NO API key — fully open and free.
# feedparser.parse() downloads and parses any RSS/Atom feed URL.
# =============================================================================

RSS_FEEDS = {
    "Krebs on Security":  "https://krebsonsecurity.com/feed/",
    "BleepingComputer":   "https://www.bleepingcomputer.com/feed/",
    "SANS ISC":           "https://isc.sans.edu/rssfeed.xml",
    "The Hacker News":    "https://feeds.feedburner.com/TheHackersNews",
    "Schneier on Security": "https://www.schneier.com/blog/atom.xml",
    "Threatpost":         "https://threatpost.com/feed/",
}

# =============================================================================
# ── 3. THREAT CATEGORIZER ─────────────────────────────────────────────────────
# Classifies articles by scanning their text for security keywords.
# This gives us data for the pie chart on the dashboard — no extra API needed.
# =============================================================================

CATEGORIES = {
    "Malware":       ["malware", "ransomware", "trojan", "virus", "backdoor",
                      "rootkit", "spyware", "worm", "botnet", "infostealer"],
    "Phishing":      ["phishing", "credential", "spear-phishing", "business email",
                      "bec", "smishing", "vishing", "social engineering"],
    "Vulnerability": ["cve-", "vulnerability", "patch", "exploit", "zero-day",
                      "rce", "remote code", "injection", "bypass", "escalation"],
    "Data Breach":   ["breach", "leak", "stolen data", "exposed", "compromised",
                      "data loss", "exfiltration", "database dump"],
    "APT / Nation State": ["apt", "nation-state", "espionage", "threat actor",
                           "campaign", "state-sponsored", "advanced persistent"],
}

def categorize(title: str, summary: str) -> str:
    """
    Classify a security article into a threat category.
    Scans both the title and summary for known keywords.
    Returns the first matching category, or "General" if none match.
    """
    text = (title + " " + summary).lower()
    for category, keywords in CATEGORIES.items():
        if any(k.lower() in text for k in keywords):
            return category
    return "General"


def strip_html(text: str) -> str:
    """Remove HTML tags from RSS article summaries."""
    return re.sub(r'<[^>]+>', '', text or "").strip()


# =============================================================================
# ── 4. RSS PARSER ─────────────────────────────────────────────────────────────
# feedparser.parse() is a synchronous (blocking) function. We run it in a
# thread pool executor so it doesn't block the async event loop. This lets
# FastAPI continue handling other requests while waiting for the RSS download.
# =============================================================================

def _parse_feed_sync(source_name: str, feed_url: str, limit: int) -> list:
    """
    Synchronous RSS parser — runs in a thread pool.
    Called internally by get_news() and get_stats().
    """
    articles = []
    try:
        feed = feedparser.parse(feed_url)
        for entry in feed.entries[:limit]:
            title   = entry.get("title", "No title")
            link    = entry.get("link", "#")
            raw_sum = entry.get("summary", entry.get("description", ""))
            summary = strip_html(raw_sum)[:350]
            pub     = entry.get("published", entry.get("updated", "Unknown date"))

            articles.append({
                "title":     title,
                "link":      link,
                "summary":   summary,
                "published": pub,
                "source":    source_name,
                "category":  categorize(title, summary),
            })
    except Exception:
        pass  # Skip feeds that are temporarily unavailable
    return articles


# =============================================================================
# ── 5. FASTAPI APP SETUP ──────────────────────────────────────────────────────
# =============================================================================

app = FastAPI(
    title="ThreatIQ",
    description="Threat Intelligence Aggregation Platform",
    version="1.0.0"
)

# CORS = Cross-Origin Resource Sharing.
# This header tells browsers it's OK for JavaScript on one origin (e.g.
# localhost:8000) to call the API. Without this, browsers block fetch() calls.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # In production: specify your actual domain
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# ── 6. ROUTES ─────────────────────────────────────────────────────────────────
# Each function below handles one URL pattern.
# The decorator (@app.get("/path")) registers it with FastAPI.
# FastAPI automatically converts the function's return dict to JSON.
# =============================================================================

@app.get("/")
async def serve_dashboard():
    """
    Serve the main dashboard HTML page.
    FileResponse reads a file from disk and sends it as an HTTP response.
    The browser then renders it as a webpage.
    """
    return FileResponse("static/index.html")


# ── Route: GET /api/news ──────────────────────────────────────────────────────
# Query params: category=all|Malware|Phishing|..., limit=30
# Example: /api/news?category=Malware&limit=10

@app.get("/api/news")
async def get_news(category: str = "all", limit: int = 40):
    """
    Aggregate security news from all RSS feeds.
    Fetches all feeds in parallel for speed (asyncio.gather).
    """
    loop = asyncio.get_event_loop()

    # run_in_executor runs a blocking function in a thread pool without
    # blocking the async event loop. This is the standard pattern for
    # calling synchronous libraries (like feedparser) from async code.
    tasks = [
        loop.run_in_executor(None, _parse_feed_sync, source, url, 8)
        for source, url in RSS_FEEDS.items()
    ]

    # asyncio.gather runs all tasks concurrently and waits for all to finish.
    # If we called them sequentially, 6 feeds × ~1s each = 6s. Parallel = ~1s.
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_articles = []
    for result in results:
        if isinstance(result, list):   # Skip any feeds that threw exceptions
            all_articles.extend(result)

    # Apply category filter if specified
    if category.lower() != "all":
        all_articles = [a for a in all_articles if a["category"].lower() == category.lower()]

    return {
        "articles": all_articles[:limit],
        "total":    len(all_articles),
        "sources":  list(RSS_FEEDS.keys()),
    }


# ── Route: GET /api/stats ─────────────────────────────────────────────────────
# Returns aggregated statistics for the dashboard charts.

@app.get("/api/stats")
async def get_stats():
    """
    Aggregate statistics across all feeds for dashboard charts.
    Returns category distribution and per-source article counts.
    """
    loop = asyncio.get_event_loop()
    tasks = [
        loop.run_in_executor(None, _parse_feed_sync, source, url, 10)
        for source, url in RSS_FEEDS.items()
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_articles = []
    for r in results:
        if isinstance(r, list):
            all_articles.extend(r)

    # defaultdict(int) is a dict where missing keys start at 0
    # This lets us write cat_counts["Malware"] += 1 without checking if key exists
    cat_counts    = defaultdict(int)
    source_counts = defaultdict(int)

    for a in all_articles:
        cat_counts[a["category"]]   += 1
        source_counts[a["source"]]  += 1

    return {
        "category_distribution": dict(cat_counts),
        "source_distribution":   dict(source_counts),
        "total_articles":        len(all_articles),
        "feed_count":            len(RSS_FEEDS),
    }


# ── Route: GET /api/ioc/ip/{ip_address} ──────────────────────────────────────
# Checks an IP address against AbuseIPDB's reputation database.
# AbuseIPDB tracks IPs that have been reported for spam, brute force, etc.

@app.get("/api/ioc/ip/{ip_address}")
async def check_ip(ip_address: str):
    """
    Check an IP address's abuse reputation via AbuseIPDB API.
    Returns confidence score (0-100%), abuse categories, and recent reports.
    """
    if not ABUSEIPDB_KEY:
        # Graceful fallback — shows a message instead of crashing
        return {"error": "ABUSEIPDB_KEY not configured. Add it to your .env file.", "configured": False}

    # httpx.AsyncClient is an async HTTP client — the async equivalent of requests.
    # The 'async with' block ensures the connection is properly closed afterward.
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": ABUSEIPDB_KEY,
                    "Accept": "application/json"
                },
                params={
                    "ipAddress":    ip_address,
                    "maxAgeInDays": 90,      # Look back 90 days for reports
                    "verbose":      True,    # Include reporter categories
                },
                timeout=10.0,
            )
            data = response.json()

            # AbuseIPDB wraps results in a "data" key
            result = data.get("data", data)

            # Derive a simple verdict for display
            score = result.get("abuseConfidenceScore", 0)
            result["verdict"] = (
                "MALICIOUS"  if score >= 75 else
                "SUSPICIOUS" if score >= 25 else
                "CLEAN"
            )
            result["configured"] = True
            return result

        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="AbuseIPDB request timed out")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


# ── Route: GET /api/ioc/hash/{file_hash} ─────────────────────────────────────
# Checks a file hash (MD5, SHA-1, or SHA-256) against VirusTotal.
# VirusTotal scans files with 70+ antivirus engines and stores results.

@app.get("/api/ioc/hash/{file_hash}")
async def check_hash(file_hash: str):
    """
    Look up a file hash in VirusTotal's database.
    Returns detection count across 70+ AV engines and a CLEAN/MALICIOUS verdict.
    """
    if not VIRUSTOTAL_KEY:
        return {"error": "VIRUSTOTAL_KEY not configured. Add it to your .env file.", "configured": False}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": VIRUSTOTAL_KEY},
                timeout=15.0,
            )

            if response.status_code == 404:
                return {
                    "configured": True,
                    "verdict": "NOT FOUND",
                    "message": "This hash has not been seen by VirusTotal. "
                               "It may be new or very rare."
                }

            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="VirusTotal API error")

            data  = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values())

            return {
                "configured":   True,
                "hash":         file_hash,
                "name":         attrs.get("meaningful_name", "Unknown filename"),
                "type":         attrs.get("type_description", "Unknown"),
                "size_bytes":   attrs.get("size", 0),
                "malicious":    malicious,
                "suspicious":   suspicious,
                "clean":        stats.get("undetected", 0),
                "total_engines": total,
                "detection_rate": f"{malicious}/{total}",
                "first_seen":   attrs.get("first_submission_date", "Unknown"),
                "verdict": (
                    "MALICIOUS"  if malicious >= 3 else
                    "SUSPICIOUS" if malicious >= 1 or suspicious >= 2 else
                    "CLEAN"
                ),
            }

        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="VirusTotal request timed out")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


# ── Route: GET /api/otx/pulses ────────────────────────────────────────────────
# AlienVault OTX (Open Threat Exchange) is a community threat intel platform.
# "Pulses" are threat intelligence reports contributed by the community.
# Each pulse contains IOCs (IPs, domains, hashes) and context about a threat.

@app.get("/api/otx/pulses")
async def get_otx_pulses():
    """
    Fetch the latest threat intelligence pulses from AlienVault OTX.
    Each pulse is a crowd-sourced threat report with IOCs and context.
    """
    if not OTX_KEY:
        return {"error": "OTX_KEY not configured. Register free at otx.alienvault.com", "configured": False}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                "https://otx.alienvault.com/api/v1/pulses/subscribed",
                headers={"X-OTX-API-KEY": OTX_KEY},
                params={"limit": 10},
                timeout=15.0,
            )
            data = response.json()

            pulses = []
            for pulse in data.get("results", []):
                pulses.append({
                    "name":             pulse.get("name", "Unnamed pulse"),
                    "description":      pulse.get("description", "")[:300],
                    "tags":             pulse.get("tags", [])[:6],
                    "indicators_count": pulse.get("indicator_count", 0),
                    "modified":         pulse.get("modified", ""),
                    "author":           pulse.get("author_name", "Unknown"),
                    # TLP = Traffic Light Protocol (sharing classification)
                    # white=public, green=community, amber=limited, red=restricted
                    "tlp":              pulse.get("tlp", "white"),
                })

            return {"configured": True, "pulses": pulses, "count": len(pulses)}

        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


# ── Route: GET /api/briefing ──────────────────────────────────────────────────
# Uses Gemini to generate a professional threat intelligence briefing
# based on the current day's security news headlines.

@app.get("/api/briefing")
async def get_briefing():
    """
    Generate an AI-powered threat intelligence briefing using Gemini 2.0 Flash.
    Pulls current headlines from all RSS feeds, then asks Gemini to synthesize
    them into a professional SOC-style briefing.
    """
    if not GOOGLE_API_KEY:
        return {"error": "GOOGLE_API_KEY not configured. Get a free key at aistudio.google.com"}

    # Collect headlines from all feeds
    loop = asyncio.get_event_loop()
    tasks = [
        loop.run_in_executor(None, _parse_feed_sync, source, url, 5)
        for source, url in RSS_FEEDS.items()
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    headlines = []
    for result in results:
        if isinstance(result, list):
            for a in result:
                headlines.append(f"[{a['source']}] {a['title']}")

    if not headlines:
        return {"error": "Could not retrieve headlines to generate briefing."}

    # Build the Gemini prompt
    today = datetime.now().strftime("%A, %B %d, %Y")
    headlines_block = "\n".join(headlines[:24])

    prompt = f"""
    You are a senior threat intelligence analyst writing a daily briefing for a SOC team.
    Today is {today}. Based on the following headlines from trusted security news sources,
    produce a concise, actionable threat intelligence briefing.

    HEADLINES:
    {headlines_block}

    Write the briefing with EXACTLY these sections:
    EXECUTIVE SUMMARY
    [2-3 sentences summarizing today's threat landscape]

    KEY THREATS
    • [Threat 1 — be specific, cite the source if relevant]
    • [Threat 2]
    • [Threat 3]
    • [Threat 4 if warranted]

    NOTABLE THREAT ACTORS
    [Any nation-state, APT group, or criminal organization mentioned. If none, write "No specific threat actor attribution in today's feed."]

    RECOMMENDED ACTIONS
    1. [Specific defensive action]
    2. [Specific defensive action]
    3. [Specific defensive action]

    THREAT LEVEL: [LOW | MODERATE | HIGH | CRITICAL]
    [One sentence justification for the threat level]

    Keep the briefing under 350 words. Use professional security operations language.
    """

    try:
        client   = genai.Client()
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt
        )
        return {
            "briefing":       response.text,
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "headline_count": len(headlines),
            "sources_used":   list(RSS_FEEDS.keys()),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gemini error: {str(e)}")


# ── Route: GET /api/status ────────────────────────────────────────────────────
# Health check — tells the frontend which API keys are configured.
# Used by the dashboard to show the "API Status" panel in the sidebar.

@app.get("/api/status")
async def get_status():
    """Return which API keys are configured (without revealing the actual keys)."""
    return {
        "gemini":      bool(GOOGLE_API_KEY),
        "abuseipdb":   bool(ABUSEIPDB_KEY),
        "virustotal":  bool(VIRUSTOTAL_KEY),
        "otx":         bool(OTX_KEY),
        "rss_feeds":   len(RSS_FEEDS),
        "server_time": datetime.now(timezone.utc).isoformat(),
    }


# =============================================================================
# ── 7. ENTRY POINT ────────────────────────────────────────────────────────────
# This block only runs when you execute the file directly:
#   python main.py
# (Not when imported as a module, which is what uvicorn does internally.)
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    # host="0.0.0.0" means accept connections from any network interface
    # (not just localhost) — needed if you want others on your LAN to access it
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
