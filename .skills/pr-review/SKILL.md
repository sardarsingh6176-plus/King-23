---
name: local-private-pr-review
description: Use this skill whenever a developer or team wants to review a Git Pull Request, uncommitted diff, or source file for security vulnerabilities, leaked secrets, logic bugs, and performance regressions strictly on local loopback (127.0.0.1) without sending proprietary code to external cloud AI services.
license: MIT
---

# Local Private Pull Request Reviewer Skill (Gemma 2B)

## Overview
This skill executes a two-stage, air-gapped code review pipeline solving Hacktoberfest Hack Day Problem Statement #17:
1. **Stage 1 (Deterministic AST & Secret Pre-Scanner):** Runs <5ms Python `ast` and regex checks to flag hardcoded API keys, SQL injection string interpolation, unsafe `eval()`/`exec()`, and cyclomatic complexity spikes.
2. **Stage 2 (Local Gemma 2B Semantic Triage):** Passes the unified diff and Stage 1 flags to `gemma2:2b` hosted on local Ollama (`http://127.0.0.1:11434/api/generate`) with `format: "json"`.

## Concrete Execution Steps
1. Verify local Ollama is running: `curl http://127.0.0.1:11434/api/tags`
2. Capture the target diff locally: `git diff HEAD` or `git show HEAD`
3. Run Stage 1 static analysis and Stage 2 `gemma2:2b` JSON inference via `POST http://127.0.0.1:5003/api/review`.
4. Block merge immediately (`BLOCK_MERGE`) if any `CRITICAL` secret or injection vector is present, and output the auto-patched code and `pytest` unit test suite.
