
Return ONLY valid JSON matching this exact structure:
{{
  "merge_verdict": "BLOCK_MERGE" or "CHANGES_REQUESTED" or "APPROVED_READY",
  "trust_score": 0 to 100 integer,
  "category_scores": {{
    "security": 0 to 100 integer,
    "performance": 0 to 100 integer,
    "maintainability": 0 to 100 integer,
    "correctness": 0 to 100 integer
  }},
  "executive_summary": "2 crisp sentences summarizing what the PR changes and its primary risk.",
  "inline_findings": [
    {{
      "line_number": "e.g. L12",
      "severity": "CRITICAL" or "HIGH" or "MEDIUM" or "LOW",
      "category": "Security" or "Performance" or "Logic" or "Clean Code",
      "title": "Short title of the bug or improvement",
      "why_it_matters": "Clear explanation of the vulnerability or bug impact",
      "suggested_fix_code": "Exact corrected line or snippet of code"
    }}
  ],
  "auto_patched_code": "The complete, corrected production-ready code with all bugs fixed",
  "generated_unit_tests": "Complete pytest unit tests verifying the fix and edge cases"
}}"""

    start_time = time.perf_counter()
    try:
        resp = requests.post(
            f"{OLLAMA_URL.rstrip('/')}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "format": "json",
                "stream": False,
                "options": {
                    "temperature": 0.15,
                    "num_predict": 1400
                }
            },
            timeout=45
        )
        latency_ms = round((time.perf_counter() - start_time) * 1000, 1)
        resp.raise_for_status()
        data = resp.json()
        raw_response = data.get("response", "{}")

        try:
            parsed = json.loads(raw_response)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", raw_response, re.DOTALL)
            parsed = json.loads(match.group(0)) if match else {}

        normalized = normalize_gemma_output(parsed, diff_text, prescan)
        return normalized, latency_ms, "LIVE_GEMMA_OLLAMA"
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 1)
        fallback = build_fallback_review(diff_text, prescan)
        return fallback, latency_ms, f"HYBRID_SAFE_FALLBACK ({type(exc).__name__})"


# ==============================================================================
# FLASK ROUTES
# ==============================================================================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health", methods=["GET"])
def api_health():
    start = time.perf_counter()
    try:
        r = requests.get(f"{OLLAMA_URL.rstrip('/')}/api/tags", timeout=2.5)
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        models = [m.get("name", "") for m in r.json().get("models", [])] if r.ok else []
        has_gemma = any("gemma" in m.lower() for m in models)
        return jsonify({
            "online": r.ok,
            "model": OLLAMA_MODEL,
            "gemma_ready": has_gemma,
            "installed_models": models,
            "ollama_url": OLLAMA_URL,
            "ping_ms": latency_ms,
            "external_bytes_sent": 0
        })
    except Exception:
        return jsonify({
            "online": False,
            "model": OLLAMA_MODEL,
            "gemma_ready": False,
            "installed_models": [],
            "ollama_url": OLLAMA_URL,
            "ping_ms": 0,
            "external_bytes_sent": 0
        })


@app.route("/api/scan-local-git", methods=["POST"])
def api_scan_local_git():
    payload = request.get_json(silent=True) or {}
    repo_path = (payload.get("repo_path") or ".").strip()
    abs_path = os.path.abspath(os.path.expanduser(repo_path))

    if not os.path.isdir(abs_path):
        return jsonify({"ok": False, "error": f"Directory not found: {abs_path}"}), 400

    try:
        # 1. Try uncommitted working tree + staged changes first
        diff_cmd = subprocess.run(
            ["git", "-C", abs_path, "diff", "HEAD"],
            capture_output=True, text=True, timeout=5
        )
        diff_output = diff_cmd.stdout.strip()

        # 2. If working tree is clean, grab latest commit diff (HEAD~1..HEAD)
        if not diff_output:
            last_commit_cmd = subprocess.run(
                ["git", "-C", abs_path, "show", "--format=", "HEAD"],
                capture_output=True, text=True, timeout=5
            )
            diff_output = last_commit_cmd.stdout.strip()

        # 3. If brand new repo with untracked files, synthesize a diff from status
        if not diff_output:
            status_cmd = subprocess.run(
                ["git", "-C", abs_path, "status", "--porcelain"],
                capture_output=True, text=True, timeout=5
            )
            status_lines = [line.strip() for line in status_cmd.stdout.splitlines() if line.strip()]
            synthesized = [f"diff --git a/local_repo b/local_repo\n--- a/clean\n+++ b/working_tree"]
            for sline in status_lines[:3]:
                parts = sline.split(maxsplit=1)
                fname = parts[1] if len(parts) > 1 else parts[0]
                fpath = os.path.join(abs_path, fname)
                if os.path.isfile(fpath) and os.path.getsize(fpath) < 40_000:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        snippet = f.read(1800).splitlines()
                        synthesized.append(f"@@ -0,0 +1,{len(snippet)} @@ {fname}")
                        synthesized.extend([f"+{l}" for l in snippet[:45]])
            diff_output = "\n".join(synthesized)

        branch_cmd = subprocess.run(
            ["git", "-C", abs_path, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=3
        )
        branch = branch_cmd.stdout.strip() or "main"

        return jsonify({
            "ok": True,
            "repo_path": abs_path,
            "branch": branch,
            "diff": diff_output or "# No git changes found in directory."
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/review", methods=["POST"])
def api_review():
    payload = request.get_json(silent=True) or {}
    diff_text = (payload.get("diff") or "").strip()
    pr_title = (payload.get("title") or "Local Pull Request Diff").strip()

    if not diff_text:
        return jsonify({"ok": False, "error": "Please provide a code diff or select a preset PR."}), 400

    # Stage 1: Deterministic Local AST + Regex Pre-Scanner
    prescan = run_deterministic_prescan(diff_text)

    # Stage 2: Local Gemma 2B Deep Semantic Review
    review_data, gemma_latency_ms, engine_mode = call_local_gemma(diff_text, prescan)

    return jsonify({
        "ok": True,
        "pr_title": pr_title,
        "engine_mode": engine_mode,
        "model": OLLAMA_MODEL,
        "ollama_url": OLLAMA_URL,
        "external_cloud_bytes": 0,
        "telemetry": {
            "prescan_latency_ms": prescan["prescan_latency_ms"],
            "gemma_latency_ms": gemma_latency_ms,
            "total_latency_ms": round(prescan["prescan_latency_ms"] + gemma_latency_ms, 1)
        },
        "metrics": prescan["metrics"],
        "static_flags": prescan["static_flags"],
        "review": review_data
    })


if __name__ == "__main__":
    print(f"🔒 Local Private PR Reviewer starting on http://127.0.0.1:{PORT}")
    print(f"🧠 Local AI Engine: {OLLAMA_MODEL} via {OLLAMA_URL} (0 Cloud Bytes)")
    app.run(host="127.0.0.1", port=PORT, debug=True)
