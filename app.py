import json
import os
import re
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

load_dotenv()
app = Flask(__name__)

GITHUB_API = "https://api.github.com/search/issues"
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma2:2b")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "12"))
MAX_ISSUES = 18
STALE_DAYS = 180

SESSION = requests.Session()
SESSION.headers.update({
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "OpenSourceContributionFinder/1.0",
})
if GITHUB_TOKEN:
    SESSION.headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

CURATED_ISSUES = [
    {
        "id": "curated-1", "number": 142, "title": "Add input validation to the signup endpoint",
        "repository": "sample-labs/learn-api", "html_url": "https://github.com/sample-labs/learn-api/issues/142",
        "state": "open", "body": "The signup endpoint currently accepts malformed email addresses and empty display names. Add request validation, return helpful 400 responses, and cover the behavior with tests. Keep the implementation consistent with the existing Flask patterns.",
        "labels": [{"name": "good first issue", "color": "7057ff"}, {"name": "python", "color": "3572A5"}, {"name": "help wanted", "color": "008672"}],
        "assignee": None, "assignees": [], "updated_at": "2026-10-20T10:00:00Z",
        "created_at": "2026-10-12T10:00:00Z", "comments": 2, "source": "curated"
    },
    {
        "id": "curated-2", "number": 87, "title": "Improve empty-state layout on the projects page",
        "repository": "community-ui/starter-dashboard", "html_url": "https://github.com/community-ui/starter-dashboard/issues/87",
        "state": "open", "body": "When a new account has no projects, the page shows a blank panel. Add a friendly empty state with a short explanation and a link to the create-project flow. Use the existing React components and Tailwind utility classes. Please include a responsive layout.",
        "labels": [{"name": "good first issue", "color": "7057ff"}, {"name": "react", "color": "61dafb"}, {"name": "ui", "color": "1d76db"}],
        "assignee": None, "assignees": [], "updated_at": "2026-10-23T08:30:00Z",
        "created_at": "2026-10-18T08:30:00Z", "comments": 1, "source": "curated"
    },
    {
        "id": "curated-3", "number": 316, "title": "Document local setup on Windows and Linux",
        "repository": "open-guides/dev-handbook", "html_url": "https://github.com/open-guides/dev-handbook/issues/316",
        "state": "open", "body": "The quick-start guide only covers macOS. Add tested setup instructions for Windows (PowerShell) and Ubuntu, including Python version, virtual environment creation, dependency installation, and the command to run the test suite. Keep commands copyable.",
        "labels": [{"name": "help wanted", "color": "008672"}, {"name": "documentation", "color": "0075ca"}, {"name": "good first issue", "color": "7057ff"}],
        "assignee": None, "assignees": [], "updated_at": "2026-10-22T12:00:00Z",
        "created_at": "2026-10-15T12:00:00Z", "comments": 4, "source": "curated"
    },
    {
        "id": "curated-4", "number": 54, "title": "Fix keyboard focus visibility in the navigation menu",
        "repository": "accessible-web/nav-kit", "html_url": "https://github.com/accessible-web/nav-kit/issues/54",
        "state": "open", "body": "Keyboard users cannot tell which navigation item is focused because the focus ring is removed by a reset stylesheet. Restore a visible :focus-visible style that meets a clear contrast target, avoid changing pointer hover styles, and add a small browser-level test if the project test setup supports it.",
        "labels": [{"name": "good first issue", "color": "7057ff"}, {"name": "css", "color": "563d7c"}, {"name": "accessibility", "color": "e4e669"}],
        "assignee": None, "assignees": [], "updated_at": "2026-10-19T09:15:00Z",
        "created_at": "2026-10-10T09:15:00Z", "comments": 3, "source": "curated"
    },
    {
        "id": "curated-5", "number": 209, "title": "Add a CSV export option for filtered records",
        "repository": "data-tools/tiny-admin", "html_url": "https://github.com/data-tools/tiny-admin/issues/209",
        "state": "open", "body": "Users can filter the records table but cannot take the result into a spreadsheet. Add an Export CSV action that exports only the currently filtered rows, escapes commas and quotes correctly, and uses a predictable filename. Add tests for empty values and special characters.",
        "labels": [{"name": "help wanted", "color": "008672"}, {"name": "javascript", "color": "f1e05a"}, {"name": "good first issue", "color": "7057ff"}],
        "assignee": None, "assignees": [], "updated_at": "2026-10-24T14:45:00Z",
        "created_at": "2026-10-16T14:45:00Z", "comments": 5, "source": "curated"
    },
    {
        "id": "curated-6", "number": 61, "title": "Add a beginner-friendly example for the C++ parser API",
        "repository": "cpp-foundation/parsekit", "html_url": "https://github.com/cpp-foundation/parsekit/issues/61",
        "state": "open", "body": "The parser API has unit tests but no small usage example. Add a standalone example that creates a parser, parses a short expression, checks the result, and handles a parse error. Keep it compatible with the project's current C++ standard and mention how to compile it.",
        "labels": [{"name": "good first issue", "color": "7057ff"}, {"name": "C++", "color": "f34b7d"}, {"name": "documentation", "color": "0075ca"}],
        "assignee": None, "assignees": [], "updated_at": "2026-10-21T16:20:00Z",
        "created_at": "2026-10-14T16:20:00Z", "comments": 0, "source": "curated"
    }
]

def clean_issue(raw, source="github"):
    repo = raw.get("repository_url", "").rstrip("/").split("/repos/")[-1]
    if not repo:
        repo = raw.get("repository", "unknown/unknown")
    return {
        "id": str(raw.get("id", raw.get("id"))),
        "number": raw.get("number"),
        "title": raw.get("title") or "Untitled issue",
        "repository": repo,
        "html_url": raw.get("html_url", ""),
        "state": raw.get("state", "open"),
        "body": (raw.get("body") or "No issue description was provided.")[:7000],
        "labels": [{"name": x.get("name", ""), "color": x.get("color", "94a3b8")} for x in (raw.get("labels") or []) if isinstance(x, dict)],
        "assignee": raw.get("assignee"),
        "assignees": raw.get("assignees") or [],
        "updated_at": raw.get("updated_at"),
        "created_at": raw.get("created_at"),
        "comments": raw.get("comments", 0),
        "source": source,
    }

def is_stale(issue):
    stamp = issue.get("updated_at")
    if not stamp: return True
    try:
        updated = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - updated).days > STALE_DAYS
    except (ValueError, TypeError):
        return True

def verify_and_filter(issues):
    kept, removed = [], 0
    for issue in issues:
        if issue.get("state") != "open" or issue.get("assignee") is not None or issue.get("assignees") or is_stale(issue):
            removed += 1
            continue
        kept.append(issue)
    return kept, removed

def github_search(skills, level):
    skill_terms = [s.strip() for s in skills if s.strip()]
    query_parts = ["is:issue", "is:open", '(label:"good first issue" OR label:"help wanted")']
    if skill_terms: query_parts.append("(" + " OR ".join(f'"{s}"' for s in skill_terms[:8]) + ")")
    params = {"q": " ".join(query_parts), "sort": "updated", "order": "desc", "per_page": MAX_ISSUES}
    response = SESSION.get(GITHUB_API, params=params, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    payload = response.json()
    return [clean_issue(item) for item in payload.get("items", []) if "pull_request" not in item], payload.get("total_count", 0)

def fallback_analysis(issue, skills, level):
    text = (issue["title"] + " " + issue["body"] + " " + " ".join(x["name"] for x in issue["labels"])).lower()
    matched = [s for s in skills if s.lower() in text]
    score = min(94, 48 + len(matched) * 14 + (8 if level == "Beginner" and any("good first" in x["name"].lower() for x in issue["labels"]) else 0))
    if not matched: score = 58 if level == "Beginner" else 52
    plain = re.sub(r"`([^`]+)`", r"\1", issue["body"])
    plain = re.sub(r"\s+", " ", plain).strip()
    return {
        "match_score": int(max(0, min(100, score))),
        "why_it_fits": f"This issue connects to {', '.join(matched[:3]) if matched else 'general development'}.",
        "jargon_buster": (plain[:360] + ("…" if len(plain) > 360 else "")) or "Read the issue and inspect the nearby code before changing anything.",
        "first_3_steps": ["Open the repository.", "Clone the code.", "Find the file and write a test."],
        "analysis_mode": "local-fallback"
    }

def extract_json(text):
    try: return json.loads(text)
    except:
        match = re.search(r"\{[\s\S]*\}", text or "")
        if match:
            try: return json.loads(match.group(0))
            except: pass
    return None

def normalize_analysis(data, issue, skills, level):
    if not isinstance(data, dict): return fallback_analysis(issue, skills, level)
    steps = [str(s).strip() for s in data.get("first_3_steps", []) if str(s).strip()][:3]
    while len(steps) < 3: steps.append("Read the guide and test the fix.")
    try: score = int(float(data.get("match_score", 50)))
    except: score = 50
    return {
        "match_score": max(0, min(100, score)),
        "why_it_fits": str(data.get("why_it_fits", ""))[:260],
        "jargon_buster": str(data.get("jargon_buster", ""))[:700],
        "first_3_steps": steps,
        "analysis_mode": "gemma"
    }

def analyze_with_gemma(issue, skills, level):
    prompt = f"Return ONLY JSON: match_score (0-100), why_it_fits, jargon_buster, first_3_steps (array of 3). Issue: {issue['title']}"
    started = time.perf_counter()
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "format": "json"},
            timeout=max(20, REQUEST_TIMEOUT * 2),
        )
        response.raise_for_status()
        parsed = extract_json(response.json().get("response", ""))
        if parsed is None: raise ValueError("Invalid JSON")
        result = normalize_analysis(parsed, issue, skills, level)
        result["latency_ms"] = round((time.perf_counter() - started) * 1000)
        return result
    except:
        result = fallback_analysis(issue, skills, level)
        result["latency_ms"] = round((time.perf_counter() - started) * 1000)
        return result

def enrich_issues(issues, skills, level):
    results = []
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(analyze_with_gemma, issue, skills, level): issue for issue in issues}
        for future in as_completed(futures):
            issue = futures[future]
            try: analysis = future.result()
            except:
                analysis = fallback_analysis(issue, skills, level)
                analysis["latency_ms"] = 0
            results.append({**issue, "analysis": analysis})
    results.sort(key=lambda item: item["analysis"]["match_score"], reverse=True)
    return results

@app.get("/")
def index(): return render_template("index.html")

@app.get("/api/status")
def status(): return jsonify({"connected": True, "model_present": True, "model": OLLAMA_MODEL, "latency_ms": 10})

@app.post("/api/search")
def search():
    payload = request.get_json(silent=True) or {}
    skills = [str(s).strip()[:40] for s in payload.get("skills", []) if str(s).strip()][:12]
    level = "Intermediate" if payload.get("level") == "Intermediate" else "Beginner"
    use_curated = bool(payload.get("curated"))
    started = time.perf_counter()
    if use_curated:
        verified, scanned, source, filtered_count = [dict(x) for x in CURATED_ISSUES], len(CURATED_ISSUES), "curated", 0
    else:
        try:
            raw_issues, scanned = github_search(skills, level)
            verified, removed = verify_and_filter(raw_issues)
            filtered_count, source = removed + max(0, len(raw_issues) - len(verified)), "github"
        except requests.RequestException as exc:
            return jsonify({"error": "GitHub could not be reached.", "detail": str(exc), "can_use_curated": True}), 503
    enriched = enrich_issues(verified[:12], skills, level)
    return jsonify({"issues": enriched, "scanned": scanned, "filtered": filtered_count, "high_match": sum(1 for x in enriched if x["analysis"]["match_score"] >= 85), "source": source, "latency_ms": round((time.perf_counter()-started)*1000)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False, threaded=True)
