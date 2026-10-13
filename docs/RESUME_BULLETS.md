# AttackGraph AI - Resume Bullets & Portfolio Talking Points

Curated, quantified, and technically rigorous resume bullet points grounded in repository code, real performance telemetry, and verifiable artifacts.

---

## 1. Application Security Engineer / Product Security Roles

- **Engineered an autonomous, graph-based application security assessment platform** (FastAPI, PostgreSQL, React Flow, Gemini Agent) evaluating multi-tenant web applications and REST APIs across 41 benchmark cases spanning OWASP Juice Shop, DVWA, and crAPI.
- **Architected two-session differential authorization detector for BOLA/IDOR (CWE-639 / API1:2023)**, verifying tenant boundary enforcement via cross-user session simulation; achieved **100.0% precision [95% CI: 51.0%–100.0%]** across live container environments with zero false positives.
- **Pioneered dual-recall evaluation methodology** contrasting in-scope detector recall (**100.0%**) against overall system recall (**62.5%–77.8%**), explicitly penalizing architectural blindspots (DOM-based XSS, 128-bit random UUIDs, POST JSON reflections) as false negatives using Wilson score intervals.
- **Designed context-aware reflected input engine (CWE-79)** classifying HTML body, script block, and attribute breakouts; enforced conservative triage policy restricting unexecuted reflection canaries to `HYPOTHESIS` to eliminate false-positive alert fatigue.
- **Engineered templated triage report generator and structural evidence-grounding validator** (`reports/triage.py`), verifying that all endpoints, HTTP status codes, user handles, and CWEs mentioned in security notes are strictly present in stored evidence traces.
- **Automated enterprise compliance reporting** generating OASIS SARIF v2.1.0 and executive PDF reports with automated regex-based redaction of Bearer tokens, base64 JWTs, and database credentials.

---

## 2. Security Software Engineer / Platform Security Roles

- **Hardened agent execution environment with defense-in-depth guardrails**, implementing strict hostname allowlists, URL path-traversal normalizers, anti-DoS loop blockers, and cross-scan node scoping to prevent SSRF and AWS IMDS metadata exfiltration.
- **Eliminated credential leakage in web server access logs and browser history** by deprecating query-string authentication in favor of strict `X-API-Key` HTTP header validation, streaming report downloads through authenticated in-memory blob URLs.
- **Engineered two-layer directed graph architecture (Asset Layer vs. Attack Layer)** with weakest-link path confidence scoring ($\min(C_e)$) and backward belief propagation that automatically marks downstream nodes as undermined upon human review refutation.
- **Established enterprise CI/CD security pipeline on GitHub Actions** integrating Bandit (SAST), pip-audit (SCA), Gitleaks (secret detection), frontend TypeScript bundle builds, and PostgreSQL service containers covering 156 unit and integration tests.
- **Fixed critical Bandit B310 vulnerability** in automated route discovery calibration by migrating legacy `urllib.request` calls to modern, scheme-validated `httpx` async clients.
- **Refactored dependency manifest to eliminate 4 high-severity vulnerabilities** (CVEs in `requests`), achieving clean software supply chain verification with zero flagged CVEs.

---

## 3. AI Security / Offensive AI & Defensive Agents Roles

- **Conducted empirical step-budget benchmark comparison (30 runs across budgets 3, 5, 8)** showing a deterministic pipeline completed in **~8.1s–14.0s at $0.00 cost** while finding ground-truth BOLA vulnerabilities at step 4 (8.5s), compared to an LLM function-calling agent discovering valid findings at step 5–6 (**~20s–60s, 6k–27k tokens**).
- **Hardened LLM decision loop against indirect prompt injection** by enforcing 256-character truncation boundaries on untrusted HTTP target data and wrapping target observations in passive JSON data schemas.
- **Diagnosed and resolved agent latency bottlenecks** by identifying client-side HTTP socket timeout defaults and Gemini API rate limit handling, engineering immediate backoff fallbacks across Flash models to achieve consistent sub-second to two-second inference.
- **Restricted LLM agent execution to typed function-calling primitives** (`nmap_scan`, `ffuf_scan`, `http_probe`, `access_control_check`), eliminating arbitrary code execution vectors while providing full deterministic audit replays of agent thought traces.
