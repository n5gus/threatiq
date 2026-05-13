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
import random
import json
import time
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
load_dotenv(override=True)

# =============================================================================
# ── 1. CONFIGURATION ──────────────────────────────────────────────────────────
# =============================================================================

# Read API keys from environment — NEVER hardcode these in source code
GOOGLE_API_KEY  = os.environ.get("GOOGLE_API_KEY")
ABUSEIPDB_KEY   = os.environ.get("ABUSEIPDB_KEY")
VIRUSTOTAL_KEY  = os.environ.get("VIRUSTOTAL_KEY")
OTX_KEY         = os.environ.get("OTX_KEY")

# Caching for AI Briefing
BRIEFING_CACHE_FILE  = "briefing_cache.json"
CACHE_EXPIRY_SECONDS = 3600  # 1 hour

# Caching for OTX Pulses
OTX_CACHE_FILE       = "otx_cache.json"
OTX_CACHE_EXPIRY_SECONDS = 600  # 10 minutes

# The google-genai SDK does not use global configuration.
# The client is instantiated where needed.

def is_placeholder_key(key: str | None) -> bool:
    """Check if an API key is missing or a placeholder value."""
    if not key:
        return True
    placeholders = ["your_google_api_key_here", "your_abuseipdb_key_here", 
                    "your_virustotal_key_here", "your_otx_key_here", "placeholder"]
    return key.lower().strip() in placeholders
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
        resp = httpx.get(feed_url, timeout=7.0, follow_redirects=True)
        resp.raise_for_status()
        feed = feedparser.parse(resp.text)
        for entry in feed.entries[:limit]:
            title   = entry.get("title", "No title")
            link    = entry.get("link", "#")
            raw_sum = entry.get("summary", entry.get("description", ""))
            summary = strip_html(raw_sum)[:350]
            pub     = entry.get("published", entry.get("updated", "Unknown date"))

            # Extract a numerical timestamp for sorting, or use current time if missing
            struct_time = entry.get("published_parsed") or entry.get("updated_parsed")
            timestamp   = time.mktime(struct_time) if struct_time else time.time()

            articles.append({
                "title":     title,
                "link":      link,
                "summary":   summary,
                "published": pub,
                "timestamp": timestamp,
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


# =============================================================================
# ── 6.5 GEOLOCATION MAPPING ──────────────────────────────────────────────────
# Mapping of common threat actor origins and key security regions to centroids.
# =============================================================================

COUNTRY_GEO = {
    "Russia":      [61.5, 105.3,  ["russia", "moscow", "kremlin", "fsb", "apt28", "apt29"]],
    "China":       [35.8, 104.1,  ["china", "beijing", "chinese", "apt41", "volt typhoon"]],
    "USA":         [37.0, -95.7,  ["usa", "united states", "america", "fbi", "nsa", "cisa"]],
    "Iran":        [32.4,  53.6,   ["iran", "tehran", "charming kitten", "muddywater"]],
    "North Korea": [40.3, 127.5,  ["north korea", "dprk", "pyongyang", "lazarus", "kimsuky"]],
    "Israel":      [31.0, 34.8,   ["israel", "tel aviv", "mossad", "unit 8200"]],
    "Ukraine":     [48.3, 31.1,   ["ukraine", "kyiv", "ukrainian"]],
    "Brazil":      [-14.2, -51.9, ["brazil", "brasília", "são paulo"]],
    "UK":          [55.3, -3.4,   ["uk", "united kingdom", "london", "gchq"]],
    "Germany":     [51.1, 10.4,   ["germany", "berlin", "bundeswehr"]],
    "France":      [46.2, 2.2,    ["france", "paris", "dgse"]],
    "Canada":      [56.1, -106.3, ["canada", "ottawa"]],
    "Australia":   [-25.2, 133.7, ["australia", "canberra", "sigint"]],
    "India":       [20.5, 78.9,   ["india", "delhi", "mumbai"]],
    "Japan":       [36.2, 138.2,  ["japan", "tokyo"]],
    "South Korea": [35.9, 127.7,  ["south korea", "seoul"]],
    "Taiwan":      [23.6, 120.9,  ["taiwan", "taipei"]],
    "Turkey":      [38.9, 35.2,   ["turkey", "ankara", "istanbul"]],
    "Belarus":     [53.7, 27.9,   ["belarus", "minsk"]],
    "Poland":      [51.9, 19.1,   ["poland", "warsaw"]],
    "Middle East": [25.0, 45.0,   ["middle east", "arabia"]],
    "Europe":      [50.0, 10.0,   ["europe"]],
}

def get_jitter() -> float:
    """Returns a random float between -0.6 and 0.6 to jitter overlapping markers."""
    return (random.random() - 0.5) * 1.2


async def _fetch_all_articles_internal() -> list:
    """Internal helper to fetch all articles across all RSS feeds in parallel."""
    loop = asyncio.get_event_loop()
    tasks = [
        loop.run_in_executor(None, _parse_feed_sync, source, url, 20)
        for source, url in RSS_FEEDS.items()
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    all_articles = []
    for r in results:
        if isinstance(r, list):
            all_articles.extend(r)
    # Sort all articles by timestamp descending
    all_articles.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    return all_articles


@app.get("/api/news/map")
async def get_map_data():
    """
    Scans recent news articles for country/region keywords.
    Returns a list of geo-located markers for the dashboard map.
    """
    articles = await _fetch_all_articles_internal()
    points = []

    for art in articles[:50]: # Scan most recent 50
        text = (art["title"] + " " + art["summary"]).lower()
        for name, geo in COUNTRY_GEO.items():
            lat, lng, keywords = geo
            if name.lower() in text or any(k in text for k in keywords):
                points.append({
                    "lat": lat + get_jitter(),
                    "lng": lng + get_jitter(),
                    "title": art["title"],
                    "url": art["link"],
                    "source": art["source"],
                    "country": name
                })
                break
    return points


# ── Route: GET /api/news ──────────────────────────────────────────────────────
# Query params: category=all|Malware|Phishing|..., limit=30
# Example: /api/news?category=Malware&limit=10

@app.get("/api/news")
async def get_news(category: str = "all", limit: int = 100):
    """Aggregate security news with optional category filtering."""
    all_articles = await _fetch_all_articles_internal()

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
        loop.run_in_executor(None, _parse_feed_sync, source, url, 20)
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
    if is_placeholder_key(ABUSEIPDB_KEY):
        # Graceful fallback — shows a message instead of crashing
        return {"error": "ABUSEIPDB_KEY not configured or still a placeholder. Add it to your .env file.", "configured": False}

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
    if is_placeholder_key(VIRUSTOTAL_KEY):
        return {"error": "VIRUSTOTAL_KEY not configured or still a placeholder. Add it to your .env file.", "configured": False}

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


# ── Route: GET /api/ioc/domain/{domain} ──────────────────────────────────────
# Checks a domain against VirusTotal's database.
# VirusTotal aggregates category, reputation, and AV analysis for domains.

@app.get("/api/ioc/domain/{domain}")
async def check_domain(domain: str):
    """
    Look up a domain's reputation in VirusTotal.
    Returns verdict, categories, reputation score, and AV engine analysis stats.
    """
    if is_placeholder_key(VIRUSTOTAL_KEY):
        return {"error": "VIRUSTOTAL_KEY not configured or still a placeholder. Add it to your .env file.", "configured": False}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": VIRUSTOTAL_KEY},
                timeout=15.0,
            )

            if response.status_code == 404:
                return {
                    "configured": True,
                    "verdict": "NOT FOUND",
                    "message": "This domain has not been analysed by VirusTotal yet."
                }

            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="VirusTotal API error")

            data  = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values()) or 1

            # Flatten category values from multiple engines into a unique set
            raw_cats   = attrs.get("categories", {})
            categories = list(set(raw_cats.values()))[:6]

            return {
                "configured":    True,
                "domain":        domain,
                "reputation":    attrs.get("reputation", 0),
                "registrar":     attrs.get("registrar", "Unknown"),
                "creation_date": attrs.get("creation_date"),   # unix timestamp
                "categories":    categories,
                "malicious":     malicious,
                "suspicious":    suspicious,
                "clean":         stats.get("undetected", 0),
                "total_engines": total,
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


# ── Route: GET /api/ioc/url ───────────────────────────────────────────────────
# Submits a URL to VirusTotal for scanning, then polls for the analysis result.
# Flow: POST /api/v3/urls → get analysis ID → poll GET /api/v3/analyses/{id}

@app.get("/api/ioc/url")
async def scan_url(url: str):
    """
    Submit a URL to VirusTotal and return the scan analysis result.
    Submits the URL, then polls the analysis endpoint until status = completed.
    """
    if is_placeholder_key(VIRUSTOTAL_KEY):
        return {"error": "VIRUSTOTAL_KEY not configured or still a placeholder. Add it to your .env file.", "configured": False}

    async with httpx.AsyncClient() as client:
        try:
            # Step 1 — Submit the URL for scanning (form-encoded body as VT requires)
            submit = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": VIRUSTOTAL_KEY},
                data={"url": url},
                timeout=15.0,
            )
            submit.raise_for_status()
            analysis_id = submit.json().get("data", {}).get("id", "")

            if not analysis_id:
                raise HTTPException(status_code=500, detail="VirusTotal did not return an analysis ID")

            # Step 2 — Poll until the analysis is complete (usually 1-2 passes)
            for attempt in range(6):
                await asyncio.sleep(2 if attempt > 0 else 0.5)
                poll = await client.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers={"x-apikey": VIRUSTOTAL_KEY},
                    timeout=15.0,
                )
                poll.raise_for_status()
                poll_data  = poll.json()
                poll_attrs = poll_data.get("data", {}).get("attributes", {})

                if poll_attrs.get("status") == "completed":
                    stats      = poll_attrs.get("stats", {})
                    malicious  = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total      = sum(stats.values()) or 1

                    return {
                        "configured":    True,
                        "url":           url,
                        "analysis_id":   analysis_id,
                        "malicious":     malicious,
                        "suspicious":    suspicious,
                        "clean":         stats.get("undetected", 0),
                        "total_engines": total,
                        "verdict": (
                            "MALICIOUS"  if malicious >= 3 else
                            "SUSPICIOUS" if malicious >= 1 or suspicious >= 2 else
                            "CLEAN"
                        ),
                    }

            # If still queued after 6 polls, return a partial result
            return {
                "configured":    True,
                "url":           url,
                "analysis_id":   analysis_id,
                "verdict":       "PENDING",
                "message":       "Analysis is still queued by VirusTotal. Try again in a few seconds.",
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
async def get_otx_pulses(refresh: bool = False):
    """
    Fetch the latest threat intelligence pulses from AlienVault OTX.
    Each pulse is a crowd-sourced threat report with IOCs and context.
    Includes a file-based cache to stay within free tier API quotas.
    """
    if is_placeholder_key(OTX_KEY):
        return {"error": "OTX_KEY is not configured or is a placeholder. Register free at otx.alienvault.com and update your .env file.", "configured": False}

    # 1. Check if we have a valid cached OTX pulses first
    if not refresh and os.path.exists(OTX_CACHE_FILE):
        try:
            with open(OTX_CACHE_FILE, "r") as f:
                cache_data = json.load(f)
            
            # Check if cache is still valid (less than 10 minutes old)
            cache_time = cache_data.get("generated_at_unix", 0)
            if (time.time() - cache_time) < OTX_CACHE_EXPIRY_SECONDS:
                return cache_data
        except Exception:
            pass # If cache is corrupt, proceed to generate a fresh one

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
                    "id":               pulse.get("id", ""),
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

            result = {"configured": True, "pulses": pulses, "count": len(pulses), "generated_at_unix": time.time()}

            # Save to cache file for subsequent loads
            try:
                with open(OTX_CACHE_FILE, "w") as f:
                    json.dump(result, f, indent=2)
            except Exception:
                pass # Even if cache saving fails, return the new result

            return result

        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


# ── Route: GET /api/briefing ──────────────────────────────────────────────────
# Uses Gemini to generate a professional threat intelligence briefing
# based on the current day's security news headlines.

@app.get("/api/briefing")
async def get_briefing(refresh: bool = False):
    """
    Generate an AI-powered threat intelligence briefing using Gemini 2.0 Flash.
    Includes a file-based cache to stay within free tier API quotas.
    """
    if is_placeholder_key(GOOGLE_API_KEY):
        return {"error": "GOOGLE_API_KEY not configured or still a placeholder. Get a free key at aistudio.google.com"}

    # 1. Check if we have a valid cached briefing first
    old_cache = None
    if os.path.exists(BRIEFING_CACHE_FILE):
        try:
            with open(BRIEFING_CACHE_FILE, "r") as f:
                old_cache = json.load(f)
            
            # Check if cache is still valid (less than 1 hour old)
            cache_time = old_cache.get("generated_at_unix", 0)
            if not refresh and (time.time() - cache_time) < CACHE_EXPIRY_SECONDS:
                return old_cache
        except Exception:
            pass # If cache is corrupt, proceed to generate a fresh one

    # 2. Collect headlines from all feeds (needed if refresh or cache expired)

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
    - [Threat 1 — be specific, cite the source if relevant]
    - [Threat 2]
    - [Threat 3]
    - [Threat 4 if warranted]

    NOTABLE THREAT ACTORS
    [Any nation-state, APT group, or criminal organization mentioned. If none, write "No specific threat actor attribution in today's feed."]

    RECOMMENDED ACTIONS
    1. [Specific defensive action]
    2. [Specific defensive action]
    3. [Specific defensive action]

    THREAT LEVEL: [LOW | MODERATE | HIGH | CRITICAL]
    [One sentence justification for the threat level]

    IMPORTANT: Do NOT use any markdown formatting such as asterisks (** or *) for bold or lists. 
    Use plain hyphens (-) for bullet points. Keep the briefing under 350 words. 
    Use professional security operations language.
    """

    try:
        client   = genai.Client(api_key=GOOGLE_API_KEY)
        response = client.models.generate_content(
            model="gemini-flash-latest",
            contents=prompt
        )
        
        # Post-processing: remove any asterisks that Gemini might still include
        clean_text = response.text.replace("*", "")
        
        result = {
            "briefing":       clean_text,
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "generated_at_unix": time.time(), # Added for TTL checks
            "headline_count": len(headlines),
            "sources_used":   list(RSS_FEEDS.keys()),
        }

        # Save to cache file for subsequent loads
        try:
            with open(BRIEFING_CACHE_FILE, "w") as f:
                json.dump(result, f, indent=2)
        except Exception:
            pass # Even if cache saving fails, return the new result

        return result
    except Exception as e:
        # If we failed due to an API error but already have a successful old cache, fall back to it
        if old_cache and "AI Generation Error" not in old_cache.get("briefing", ""):
            old_cache["briefing"] += f"\n\n[Warning: Background refresh failed: {str(e)}]"
            return old_cache

        error_result = {
            "briefing":       f"AI Generation Error: {str(e)}\n\n(This error was cached to protect quotas. Try again later.)",
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "generated_at_unix": time.time(), # Important: Cache error TTL
            "headline_count": len(headlines) if 'headlines' in locals() else 0,
            "sources_used":   [],
        }

        # Cache the error response to stop endless hammering
        try:
            with open(BRIEFING_CACHE_FILE, "w") as f:
                json.dump(error_result, f, indent=2)
        except Exception:
            pass

        return error_result


# ── Route: GET /api/tweetfeed ─────────────────────────────────────────────────
# TweetFeed.live — Free real-time IOCs from security researchers on X/Twitter.
# No API key required. Data is scraped from X by the TweetFeed project and
# served via a free REST API. Updated every 15 minutes.
# API docs: https://tweetfeed.live/api/
# Endpoint: GET https://api.tweetfeed.live/v1/{time}/{filter1}/{filter2}

TWEETFEED_CACHE_FILE      = "tweetfeed_cache.json"
TWEETFEED_CACHE_EXPIRY    = 600  # 10 minutes

@app.get("/api/tweetfeed")
async def get_tweetfeed(
    period: str = "today",
    ioc_type: str = "",
    tag: str = "",
    refresh: bool = False
):
    """
    Fetch IOCs shared by security researchers on X/Twitter via TweetFeed.live.
    
    Parameters:
    - period: today, week, month, year
    - ioc_type: ip, url, domain, sha256, md5 (optional)
    - tag: phishing, malware, cobalt strike, etc. (optional)
    - refresh: force cache refresh
    
    No API key required — fully free and open.
    """

    # Build cache key from parameters
    cache_key = f"{period}_{ioc_type}_{tag}"

    # 1. Check cache
    if not refresh and os.path.exists(TWEETFEED_CACHE_FILE):
        try:
            with open(TWEETFEED_CACHE_FILE, "r") as f:
                cache_data = json.load(f)

            cached_entry = cache_data.get(cache_key)
            if cached_entry:
                cache_time = cached_entry.get("fetched_at_unix", 0)
                if (time.time() - cache_time) < TWEETFEED_CACHE_EXPIRY:
                    return cached_entry
        except Exception:
            pass

    # 2. Build API URL
    # Format: GET https://api.tweetfeed.live/v1/{time}/{filter1}/{filter2}
    url_parts = [f"https://api.tweetfeed.live/v1/{period}"]
    if tag:
        url_parts.append(tag)
    if ioc_type:
        url_parts.append(ioc_type)
    api_url = "/".join(url_parts)

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(api_url, timeout=15.0)

            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"TweetFeed API returned {response.status_code}"
                )

            raw_iocs = response.json()

            # 3. Process and summarize the data
            iocs = []
            type_counts = defaultdict(int)
            tag_counts  = defaultdict(int)

            for item in raw_iocs[:200]:  # Limit to 200 most recent
                ioc_entry = {
                    "date":   item.get("date", ""),
                    "user":   item.get("user", ""),
                    "type":   item.get("type", ""),
                    "value":  item.get("value", ""),
                    "tags":   item.get("tags", []),
                    "tweet":  item.get("tweet", ""),
                }
                iocs.append(ioc_entry)
                type_counts[ioc_entry["type"]] += 1
                for t in ioc_entry["tags"]:
                    tag_counts[t.strip("#").lower()] += 1

            # Sort tags by frequency
            top_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:15]

            result = {
                "configured": True,
                "period":     period,
                "ioc_type":   ioc_type or "all",
                "tag_filter": tag or "none",
                "total":      len(raw_iocs),
                "showing":    len(iocs),
                "iocs":       iocs,
                "type_breakdown": dict(type_counts),
                "top_tags":       [{"tag": t[0], "count": t[1]} for t in top_tags],
                "fetched_at":     datetime.now(timezone.utc).isoformat(),
                "fetched_at_unix": time.time(),
            }

            # 4. Save to cache
            try:
                cache_data = {}
                if os.path.exists(TWEETFEED_CACHE_FILE):
                    with open(TWEETFEED_CACHE_FILE, "r") as f:
                        cache_data = json.load(f)
                cache_data[cache_key] = result
                with open(TWEETFEED_CACHE_FILE, "w") as f:
                    json.dump(cache_data, f, indent=2)
            except Exception:
                pass

            return result

        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="TweetFeed API request timed out")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


# ── Route: GET /api/status ────────────────────────────────────────────────────
# Health check — tells the frontend which API keys are configured.
# Used by the dashboard to show the "API Status" panel in the sidebar.

@app.get("/api/status")
async def get_status():
    """Return which API keys are configured (without revealing the actual keys)."""
    return {
        "gemini":      not is_placeholder_key(GOOGLE_API_KEY),
        "abuseipdb":   not is_placeholder_key(ABUSEIPDB_KEY),
        "virustotal":  not is_placeholder_key(VIRUSTOTAL_KEY),
        "otx":         not is_placeholder_key(OTX_KEY),
        "tweetfeed":   True,  # Always available — no key needed
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
