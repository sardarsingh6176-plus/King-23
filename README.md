# 🔒 AegisPR — Local, Private Pull Request Reviewer

**Hacktoberfest Hack Day Hyderabad 2026**  
**Problem Statement:** #17 — *Local, Private Pull Request Reviewer* ("Teams can't send proprietary code to cloud AI services, so they miss out on automated code review. Help teams get useful, trustworthy review of their code changes without sharing their code with outside services.")  
**Track:** Track 2 — Best Use of Gemma (Open-Weight Model at the Core)

---

## 🧠 Model & License Compliance
* **Open-Weight Model Used:** Google `gemma2:2b` executed 100% locally via Ollama (`http://127.0.0.1:11434/api/generate` with `format: "json"`).
* **Model License:** Gemma is provided under and subject to the [Gemma Terms of Use](https://ai.google.dev/gemma/terms).
* **Source Code License:** [MIT License](./LICENSE).

---

## 🏗️ Zero-Cloud Privacy Architecture

```text
+-------------------------------------------------------------------------+
|                   DEVELOPER MACHINE (100% AIR-GAPPED)                   |
|                                                                         |
|  [Git Repo / PR Diff]                                                   |
|          |                                                              |
|          v                                                              |
|  +-------------------------------------------------------------------+  |
|  | Stage 1: Deterministic Python AST & Secret Pre-Scanner (<5ms)     |  |
|  | - Flags leaked keys (Stripe, AWS, GitHub PATs), SQLi, eval(), XSS |  |
|  +-------------------------------------------------------------------+  |
|          |                                                              |
|          v  (Local Loopback 127.0.0.1:11434 — 0 External Bytes)         |
|  +-------------------------------------------------------------------+  |
|  | Stage 2: Google Gemma (gemma2:2b via Ollama JSON Mode)            |  |
|  | - Computes Trust Score (0-100) & 4 Category Scores                |  |
|  | - Line-by-line semantic findings + 1-Click Auto-Patched Code      |  |
|  | - Auto-generates pytest unit tests & GitHub Markdown PR Review    |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
