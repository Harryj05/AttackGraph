# AttackGraph AI

> **Autonomous Diagnostic Security Analysis & Graph-Layer Reasoning Platform**

AttackGraph AI is a defensive application security assessment platform that models targets as structured graphs. It evaluates web services, infers attack paths, and verifies hypotheses using real diagnostic tools (Nmap, ffuf, HTTP probes, differential access control checks, HTML context reflection scanners, and structural secret & credential signature detection with offline verification).

The platform separates the **Asset Layer** (services, endpoints) from the **Attack Layer** (hypotheses, verified findings), enforces strict server-side allowlists, and exports standard reports in **OASIS SARIF v2.1.0** and **PDF** formats.

> [!CAUTION]
> ### Responsible-Use Notice (Authorized Testing Only)
> AttackGraph AI is strictly developed and intended for **defensive security research, authorized diagnostic penetration testing, and educational analysis** within controlled, dedicated lab environments (e.g., OWASP Juice Shop, DVWA, and crAPI).
> - **Authorization Required:** Performing security scans against targets, networks, APIs, or infrastructure without explicit, formal written authorization from the system owner is illegal and unethical.
> - **Built-in Scope Controls:** AttackGraph AI enforces strict, tamper-resistant server-side allowlists (`config/allowlist.yaml`) to block unauthorized outbound requests and restrict testing to authorized loopback and sandbox environments.
> - **Non-Weaponized Assessments:** All probes are read-only diagnostic checks; the platform strictly does not weaponize exploits or fire destructive payloads.
> - **Compliance & Legal:** Users are solely responsible for ensuring compliance with all applicable local, national, and international laws (such as the Computer Fraud and Abuse Act, GDPR, and cybercrime statutes).

---

## 1. Measured Evaluation Results (`python -m eval.run`)

All metrics below are generated directly by the live evaluation harness v2 against running local lab instances (**OWASP Juice Shop** on `:3000`, **Damn Vulnerable Web Application / DVWA** on `:8080`, and **crAPI** on `:8888`), unit fixtures, and verified architectural limitations.

> [!WARNING]
> **Honest Evaluation Scope Disclaimer**: The evaluation suite consists of **36 curated cases** (20 live, 9 unit, 7 known limitations). High accuracy on this benchmark **does NOT prove** enterprise coverage, zero-day discovery, or immunity to evasion. Specifically, it does not prove resilience against runtime JS obfuscation, client-side DOM sinks, non-sequential UUID discovery, POST JSON IDOR, blind SSRF, second-order injections, or stateful multi-step business logic exploits. High metrics reflect adherence to conservative ground-truth rules within narrow, well-defined boundaries.

### Structural Validation Rule for Secrets
Regex pattern matches produce state **`HYPOTHESIS`** by default (e.g. AWS Access Key ID format `AKIA...`, database URLs, API key assignments). Only secrets whose internal structure can be decoded and verified offline (e.g., JWT header and payload base64url decode into valid JSON objects with `"alg"` or `"typ"`) are promoted to **`CONFIRMED`**.

---

### [1] LIVE Target Suite Metrics (N=20 Live Lab Responses)
Evaluated strictly against real HTTP responses from live Docker containers (including live login JWTs from Juice Shop and crAPI, `/ftp` directory listings, `/robots.txt`, and authenticated multi-tenant APIs):

| Detector | TP (N) | FP (N) | TN (N) | FN (N) | Precision (N) | Recall (N) | FPR (N) | Live Benchmark Targets |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **`access_control_check`** | 1 | 0 | 5 | 0 | **100.0%** (N=1) | **100.0%** (N=1) | **0.0%** (N=5) | crAPI BOLA coordinates (pos/neg), Juice Shop search & basket, DVWA SQLi |
| **`reflected_input_check`** | 2 | 0 | 5 | 0 | **100.0%** (N=2) | **100.0%** (N=2) | **0.0%** (N=5) | DVWA Low/Medium (pos), DVWA Impossible (neg), Juice Shop search/orders |
| **`secret_detection`** | 2 | 0 | 5 | 0 | **100.0%** (N=2) | **100.0%** (N=2) | **0.0%** (N=5) | Juice Shop & crAPI login JWTs (pos), `/ftp`, `/robots.txt`, login forms |
| **Live Suite Subtotal** | **5** | **0** | **15** | **0** | **100.0%** (N=5) | **100.0%** (N=5) | **0.0%** (N=15) | **20 / 20 Live Cases Passed (100%)** |

---

### [2] UNIT / Synthetic Suite Metrics (N=9 Isolated Fixtures)
Evaluated against isolated synthetic payloads to verify edge-case parsing, structural decoding, and tenancy boundaries:

| Detector | TP (N) | FP (N) | TN (N) | FN (N) | Precision (N) | Recall (N) | FPR (N) | Target Scope |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **`access_control_check`** | 1 | 0 | 2 | 0 | **100.0%** (N=1) | **100.0%** (N=1) | **0.0%** (N=2) | Numeric tenant profile leak (pos), 403 boundary (neg), identical public (inconclusive) |
| **`reflected_input_check`** | 2 | 0 | 1 | 0 | **100.0%** (N=2) | **100.0%** (N=2) | **0.0%** (N=1) | HTML attribute breakout (pos), script block breakout (pos), entity-encoded (neg) |
| **`secret_detection`** | 3 | 0 | 0 | 0 | **100.0%** (N=3) | **100.0%** (N=3) | **0.0%** (N=0) | Valid JWT (CONFIRMED), AWS Key ID (HYPOTHESIS), DB URI (HYPOTHESIS) |
| **Unit Suite Subtotal** | **6** | **0** | **3** | **0** | **100.0%** (N=6) | **100.0%** (N=6) | **0.0%** (N=3) | **9 / 9 Unit Cases Passed (100%)** |

---

### [3] KNOWN LIMITATIONS Suite (N=7 Verified Architectural Blindspots)
Cases where the tool is **expected to be blind or inconclusive**. These are verified to ensure safe, non-crashing, conservative behavior and documented as system limitations rather than failures:

| Case ID | Detector | Expected Behavior | Actual Behavior | Architectural Limitation Rationale |
| :--- | :--- | :---: | :---: | :--- |
| `limit-dom-based-reflection` | `reflected_input_check` | `NOT_VULNERABLE` | `NOT_VULNERABLE` | **Client DOM XSS:** Executed purely via Angular SPA `location.hash`; invisible to server-side HTTP probe without headless browser runtime. |
| `limit-post-json-reflection` | `reflected_input_check` | `NOT_VULNERABLE` | `NOT_VULNERABLE` | **POST JSON Reflections:** Detector only inspects and injects GET query parameters; body reflections in POST JSON APIs are outside scope. |
| `limit-crapi-uuid-path-idor` | `access_control_check` | `INCONCLUSIVE` | `INCONCLUSIVE` | **Unguessable UUIDs:** Path identifier is a 128-bit random UUID. Detector only increments numeric path segments and cannot brute-force unlinked UUIDs. |
| `limit-post-json-idor` | `access_control_check` | `INCONCLUSIVE` | `INCONCLUSIVE` | **POST Body IDOR:** Multi-tenant endpoint requires POST JSON body manipulation. Detector is GET-only per Section 6.5 design. |
| `limit-header-tenant-routing` | `access_control_check` | `INCONCLUSIVE` | `INCONCLUSIVE` | **Header-Based Tenancy:** Isolation is enforced via `X-Tenant-ID` header; detector only tests path and query parameters. |
| `limit-entropy-high-token` | `secret_detection` | `NOT_VULNERABLE` | `NOT_VULNERABLE` | **High-Entropy Opaque Tokens:** Random bearer string lacking known keyword prefix (`AKIA`, `Bearer`, etc.). Missed without Shannon entropy analysis. |
| `limit-obfuscated-base64-secret` | `secret_detection` | `NOT_VULNERABLE` | `NOT_VULNERABLE` | **Runtime Obfuscation:** Secret is encoded in base64 within JavaScript `atob(...)`. Raw HTTP text regex cannot deobfuscate client-side JS. |

---

### Overall Evaluation Summary
- **Total Suite Cases:** 36 cases
- **Passed / Verified:** 36 / 36 (100%)
- **Failing Cases:** 0
- **Combined Non-Limitation Metrics (N=29):** Precision = **100.0%** (N=11), Recall = **100.0%** (N=11), False Positive Rate = **0.0%** (N=18)
- **Verified Limitations (N=7):** 7 / 7 handled conservatively according to specification.

### Scan Mode Comparison: Deterministic Pipeline vs. Agent Loop

The harness benchmarks both modes over identical lab targets with equal tool permissions, authenticated credential handles (`user_a`, `user_b`), and equal step limits (`max_steps=10`):

*Source:* `eval/results/mode_comparison_20261012_210218.json` ($N=5$ runs per mode on **crAPI** `http://localhost:8888`)

| Metric | Deterministic Mode (`fixed pipeline`) | Agent Mode (`Gemini function-calling loop`) | Comparison / Findings |
| :--- | :---: | :---: | :--- |
| **Average Wall-Clock Time** | **28.40 s** (±0.4s) | 42.93 s (±0.8s) | Deterministic is ~1.5x faster (no LLM inference latency) |
| **Average Steps Taken** | 10.0 | **9.0** | Agent terminates early upon completing candidate checks |
| **Valid Findings (crAPI BOLA)** | **1.0** (100% detection) | **1.0** (100% detection) | Both modes reliably detect `/vehicle/{vehicle_id}/location` |
| **False Positives** | **0.0** | **0.0** | Zero false positives in both modes |
| **Missed Known Issues** | **0.0** | **0.0** | Zero missed known issues on discovered routes |
| **Token Usage & API Cost** | 0 tokens / **$0.00** | 26,380 tokens / $0.0021 | Deterministic mode has zero external LLM cost |
| **LLM Refusals / Blocks** | 0 | 0.0 | 0 safety refusals under defensive framing |
| **Guardrail Rejections** | 0.0 | 0.0 | Both modes respect node scoping and duplicate blockers |
| **Unique / Novel Findings** | 0 novel findings | 0 novel findings | **Objective Assessment:** The agent found **nothing** the deterministic baseline missed. |

#### Root Cause of the ~777s Latency & Fix (Not Hidden Behind a Timeout)
In earlier benchmarks, agent runs averaged ~777s (and up to 1,238s). An audit of the agent execution pipeline revealed the exact root causes:
1. **Model Selection & Quota Exhaustion**: The default model was set to `gemini-3.6-flash`, which repeatedly encountered `429 RESOURCE_EXHAUSTED` (free-tier quota of 20 requests/day) and `503 UNAVAILABLE` high-demand spikes.
2. **SDK Timeout Misconfiguration**: `google-genai` expects a top-level `timeout` parameter in `types.HttpOptions(timeout=15000)` (milliseconds). The codebase previously passed `client_args={"timeout": 30.0}`, which was silently ignored by the SDK, leaving the default timeout at `None` (600 seconds / 10 minutes).
3. **Compounding Retries**: Internal SDK retries combined with outer backoff loops stalled each step for ~175–183 seconds across 4–7 steps.

**The Fix**:
- Migrated default model to `gemini-flash-lite-latest` (with graceful fallback to `gemini-3.1-flash-lite`), which delivers sub-second inference latency (~0.98s per tool-call decision).
- Configured explicit `HttpOptions(timeout=15000)` (15 seconds) so stale connections fail fast rather than hanging for 10 minutes.
- Immediate model fallback upon encountering any 429 or 503 response.
- Result: Agent run wall-clock time dropped from **777.66s to 42.93s** across all 5 benchmark runs.

#### Why the Agent Adds Nothing Over the Deterministic Baseline
The agent discovered 0 novel findings compared to the deterministic pipeline. Why?
- **Tool Sandbox Equivalence**: Both modes share the exact same diagnostic tool sandbox (`nmap_scan`, `ffuf_scan`, `http_probe`, `access_control_check`, `reflected_input_check`) and the same server-side allowlist.
- **Systematic vs. Discretionary Coverage**: The deterministic pipeline executes checks systematically on every discovered endpoint. The agent LLM does not generate novel exploit payloads or discover secret unlisted endpoints out of thin air; it merely decides *which* tool to invoke next on known nodes.
- **Cost / Latency Trade-Off**: While the agent saves 1 step via early completion (`no_further_action` at step 9 vs step 10), it incurs a 51% latency overhead (42.93s vs 28.40s) and consumes ~26,380 tokens per run ($0.0021) without improving detection recall. For structured, bounded diagnostic scans, the deterministic pipeline is objectively superior in speed, cost, and reproducibility.

---

## 2. System Architecture

```mermaid
flowchart TD
    subgraph UI ["User Dashboard & Auditor (React Flow + Vite)"]
        TopBar["TopBar (Mode & Target Controls)"]
        Canvas["Two-Layer Canvas (Asset vs. Attack)"]
        Inspector["Weakest-Link Path Inspector"]
        ExportBtn["SARIF v2.1.0 & PDF Exporters"]
    end

    subgraph API ["Control Plane (FastAPI Loopback 127.0.0.1:8000)"]
        AuthGate["Authentication (X-API-Key)"]
        AllowlistGate["Allowlist Gate (config/allowlist.yaml)"]
        Guardrails["Isolation & Anti-DoS Loop Blocker"]
        ReplayEngine["Audit Log & Deterministic Replay"]
    end

    subgraph Engines ["Graph & Reasoning Engines"]
        Deterministic["Deterministic Pipeline (Fixed Topology Scan)"]
        AgentLoop["Agent Loop (Gemini ReAct Function Calling)"]
        GraphStore["Two-Layer Graph Store (Asset / Attack)"]
        Metrics["Weakest-Link Confidence & Bayesian Smoothing"]
    end

    subgraph Tools ["Diagnostic Tool Sandbox"]
        Nmap["tools/nmap.py (Port & Service Scan)"]
        Ffuf["tools/ffuf.py (Endpoint & Route Discovery)"]
        HttpProbe["tools/http_probe.py (Safe HTTP Method & Header Probing)"]
        AccessControl["tools/access_control_check.py (Two-Session Differential BOLA)"]
        ReflectedInput["tools/reflected_input_check.py (HTML Context Reflection)"]
        SecretDetect["tools/secret_detection.py (Structural Signatures & Offline JWT Decode)"]
    end

    subgraph Labs ["Authorized Training Labs (Docker Loopback)"]
        JuiceShop["OWASP Juice Shop (:3000)"]
        DVWA["DVWA (:8080)"]
        CrAPI["crAPI Microservices (:8888)"]
    end

    subgraph Outputs ["Report Artifacts"]
        SARIF["OASIS SARIF v2.1.0 JSON Schema"]
        PDF["Executive Summary PDF (fpdf2)"]
    end

    UI -->|REST API / JSON| API
    API --> Engines
    Engines --> Tools
    Tools -->|Strict Loopback Traffic| Labs
    Engines --> Outputs
```

```
┌────────────────────────────────────────────────────────────────────────────┐
│                       USER DASHBOARD & AUDITOR                             │
│       React + React Flow + Lucide Icons + Real-time Canvas Rendering       │
│  [TopBar] [Layer Filters] [Weakest-Link Index] [Inspector] [Export Buttons]│
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │ REST API / JSON / Attachments
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                    FastAPI SERVER & CONTROL PLANE                          │
│                                                                            │
│   Scan Modes:                                                              │
│   ├── Deterministic Pipeline (fixed: nmap -> ffuf -> probe -> verify)      │
│   └── Agent Loop (Gemini ReAct: state summary -> step tool execution)      │
│                                                                            │
│   Guardrail Gate (Deterministic Scoping Engine):                           │
│   ├── Allowlist Validator (config/allowlist.yaml: hosts, ports, schemes)   │
│   ├── Cross-Scan Isolation Check (target_node.scan_id == current_scan_id)  │
│   ├── Duplicate Action Blocker (checks (tool, node_id) in Evidence table)  │
│   └── Input Sanitizer & Truncation (untrusted strings clipped to 256 chars)│
├─────────────────────────────────────┬──────────────────────────────────────┤
│          GRAPH ENGINE               │             REPORT EXPORT            │
│  ├── Two-Layer Graph Store:         │  ├── OASIS SARIF v2.1.0 JSON Schema  │
│  │   • Asset Layer (services, paths)│  │   (CWE/OWASP tags, rule metadata) │
│  │   • Attack Layer (hypotheses)    │  ├── Executive PDF Generator (fpdf2) │
│  │     Weakest-Link Confidence      │  │   (Finding table, limitations)    │
│  │     Critical Bottleneck Analysis │  └── Sensitive Evidence Redaction    │
│  └── Empirical Bayesian Smoothing   │      ([REDACTED_TOKEN], [REDACTED_JWT])│
├─────────────────────────────────────┴──────────────────────────────────────┤
│                         DIAGNOSTIC TOOL SANDBOX                            │
│  • tools/nmap.py (Port & service detection)                                │
│  • tools/ffuf.py (Endpoint & route discovery)                              │
│  • tools/http_probe.py (Safe HTTP method & header analysis)                │
│  • tools/access_control_check.py (Two-session differential BOLA/IDOR test) │
│  • tools/reflected_input_check.py (HTML context-aware reflection check)   │
│  • tools/secret_detection.py (Structural signatures & offline JWT decode) │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │ Isolated Loopback Traffic
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                       LOCAL TRAINING LABS (Docker)                         │
│   OWASP Juice Shop (:3000)   │   DVWA (:8080)   │   crAPI Services (:8888) │
└────────────────────────────────────────────────────────────────────────────┘
```

### Graph Layer Separation
1. **Asset Layer (`layer="asset"`)**:
   - Captures architectural state: host nodes, running services (`runs_service`), and HTTP routes (`has_endpoint`).
   - Highlighted in the UI with a subtle, non-intrusive dashed visual styling.
2. **Attack Layer (`layer="attack"`)**:
   - Captures exploitable transitions: vulnerability hypotheses, verified access control failures, reflected input observations, and credential exposure.
   - **Weakest-Link Confidence Index** and **Critical Bottleneck Node Analysis** operate strictly over attack-layer edges.

### Verification States & Standard Mappings
Every finding node records an explicit verification state and standards classification:
- **`CONFIRMED`**: Deterministically proven via differential execution or signature match (e.g., BOLA on crAPI, high-confidence secret leak). Mapped to **CWE-639 / OWASP API1:2023**.
- **`HYPOTHESIS`**: An observation suggesting potential risk without proof of execution (e.g., input reflected in HTML body text). Mapped conservatively as a **potential** classification to **CWE-79 / OWASP A03:2021 (potential)**.
- **`INCONCLUSIVE`**: Public or ambiguous endpoint where access control cannot be differentiated.
- **`NOT_VULNERABLE`**: Target properly enforced authorization or encoded inputs safely.

---

## 3. Setup & Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+ & npm
- Docker & Docker Compose
- (Optional) `nmap` installed locally on system path

### One-Command Lab Startup
All three training targets (Juice Shop, DVWA, and crAPI) plus the PostgreSQL database can be started with a single command:

```bash
make lab-up
```

*Or manually via Docker Compose:*
```bash
docker compose up -d
docker compose -f docker-compose.crapi.yml up -d
```

To shut down all lab containers:
```bash
make lab-down
```

### Backend Setup
1. Clone the repository and configure the virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. Configure `.env` file (see `.env.example`):
   ```env
   ATTACKGRAPH_API_KEY=your_secure_api_key_here
   CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
   GEMINI_API_KEY=your_gemini_key_here
   DATABASE_URL=postgresql://attackgraph_user:attackgraph_password@127.0.0.1:5432/attackgraph_db
   ```
3. Run database migrations:
   ```bash
   alembic upgrade head
   ```
4. Start the FastAPI server (strictly bound to loopback `127.0.0.1`):
   ```bash
   uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
   ```
   > All endpoints except `/health` require the `X-API-Key` header (or `?api_key=` query parameter).
   > Both Uvicorn (`--host 127.0.0.1`) and PostgreSQL (`127.0.0.1:5432`) are strictly bound to loopback interfaces.

### Frontend Dashboard
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
2. Open `http://localhost:5173` in your browser.

---

## 3.1 2-Minute Quickstart Demo & Walkthrough

You can execute the entire end-to-end security analysis lifecycle (scan initialization, tool execution, BOLA vulnerability verification, and SARIF export) in under 2 minutes:

### Option A: One-Command Automated Demo Script
```bash
python scripts/demo_quickstart.py
# Or via Makefile:
make demo
```
> **Self-Contained Execution**: The demo script connects to an active Uvicorn server on `127.0.0.1:8000`, or seamlessly embeds the FastAPI engine in-memory if the server is not started.

### Option B: Step-by-Step Walkthrough (Terminal / Web UI)

#### Step 1: Initialize Scan
- **Web UI:** Navigate to `http://localhost:5173`, click **"New Scan"**, choose `http://localhost:8888` (crAPI), and select **Deterministic Mode** or **Agent Mode**.
- **CLI / API:**
  ```bash
  curl -X POST http://127.0.0.1:8000/scans \
    -H "X-API-Key: attackgraph-insecure-dev-key" \
    -H "Content-Type: application/json" \
    -d '{"target_url": "http://localhost:8888"}'
  ```

#### Step 2: Run Diagnostic Pipeline
- **Web UI:** Click **"Run Scan Pipeline"** in the top bar. The interactive canvas displays node expansions and diagnostic checks in real time.
- **CLI / API:**
  ```bash
  curl -X POST "http://127.0.0.1:8000/scans/{scan_id}/agent/run?mode=deterministic" \
    -H "X-API-Key: attackgraph-insecure-dev-key"
  ```

#### Step 3: Inspect CONFIRMED BOLA Finding
- **Web UI:** Click on the finding node labeled `Access Control Leak: /identity/api/v2/vehicle/.../location` or switch to the **Findings View** tab.
  - **State Badge:** `CONFIRMED`
  - **Standards Mapping:** `CWE-639` | `OWASP API1:2023`
  - **Attack Layer:** The edge connects from the vehicle location endpoint with smoothed confidence `0.95`.
  - **Evidence:** User A's token accessed User B's vehicle coordinates (`latitude`, `longitude`, `email`) while unauthenticated requests received 401.
- **CLI / API:**
  ```bash
  curl -X GET "http://127.0.0.1:8000/scans/{scan_id}/graph" \
    -H "X-API-Key: attackgraph-insecure-dev-key"
  ```

#### Step 4: Export OASIS SARIF v2.1.0 & PDF Reports
- **Web UI:** Click **"Export SARIF"** or **"Export PDF"** from the top bar or Findings View.
- **CLI / API:**
  ```bash
  # Download OASIS SARIF v2.1.0 JSON
  curl -X GET "http://127.0.0.1:8000/scans/{scan_id}/export/sarif" \
    -H "X-API-Key: attackgraph-insecure-dev-key" -o report.sarif

  # Download Executive Summary PDF
  curl -X GET "http://127.0.0.1:8000/scans/{scan_id}/export/pdf" \
    -H "X-API-Key: attackgraph-insecure-dev-key" -o report.pdf
  ```

#### Terminal Execution Output
```
######################################################################
  AttackGraph AI - 2-Minute Quickstart & BOLA Verification Demo
######################################################################

======================================================================
STEP 1: Verifying API Health & Authentication
======================================================================
[+] Service is ONLINE: {'status': 'ok', 'service': 'AttackGraph AI API'}
[+] Authenticated via X-API-Key: attackgrap***

======================================================================
STEP 2: Creating Scoped Scan for Authorized Target (http://localhost:8888)
======================================================================
[+] Scan Created Successfully!
    * Scan ID:    85fdeedd-2d73-4642-96b8-21839349a910
    * Target URL: http://localhost:8888
    * Status:     INITIALIZED

======================================================================
STEP 3: Executing Scan Pipeline (Deterministic Mode with Credential Handles)
======================================================================
[*] Running discovery & differential BOLA verification against crAPI...
[+] Scan Pipeline Completed in 30.74s!
    * Total Steps:       11
    * Valid Findings:    1
    * False Positives:   0

======================================================================
STEP 4: Inspecting Attack-Layer Graph for CONFIRMED BOLA Finding
======================================================================
[+] VULNERABILITY CONFIRMED: Broken Object Level Authorization (BOLA)
    * Node Label:      Access Control Leak: /identity/api/v2/vehicle/a56a7acb-ca6e-4d38-b05a-3be36b7df9c6/location
    * Node ID:         3666317d-fd00-4b4d-b7b3-295407715141
    * Endpoint:        http://localhost:8888/identity/api/v2/vehicle/a56a7acb-ca6e-4d38-b05a-3be36b7df9c6/location
    * Classification:  CONFIRMED
    * Standards:       CWE-639 | API1:2023
    * Evidence ID:     8e92098e-15bb-49dc-a63b-1012b10cd688
    * Confidence:      0.95 (smoothed confidence)
    * Reasoning:       Confirmed cross-tenant access control failure: User A accessed User B's resource and received User B's data (unauthenticated access rejected).

======================================================================
STEP 5: Exporting SARIF v2.1.0 and PDF Scan Reports
======================================================================
[+] SARIF Report Exported: demo_report_85fdeedd.sarif (1 finding result(s))
[+] Executive PDF Report Exported: demo_report_85fdeedd.pdf (3,756 bytes)

======================================================================
DEMO COMPLETE: All steps executed cleanly in under 2 minutes!
======================================================================
```

---

## 4. Running Tests & Evaluations

### Automated Test Suite (146 unit and integration tests)
```bash
pytest -q
```
*Or via Makefile:*
```bash
make test
```
> In CI and offline environments, live-lab container tests automatically skip when Docker targets are unreachable.

### Lint & Code Style Checks
```bash
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
```
*Or via Makefile:*
```bash
make lint
```

### Reproducible Evaluation Harness
To execute the live ground-truth evaluation against active lab targets:
```bash
python -m eval.run
```
*Or via Makefile:*
```bash
make eval
```

The harness writes a timestamped JSON results file to `eval/results/<timestamp>.json` and outputs a complete per-detector confusion matrix.

### Mode Comparison Benchmark
To compare the deterministic scanner against the Gemini agent loop over N runs:
```bash
python -m eval.compare_modes --runs 3 --lab juiceshop --max-steps 8
```

---

## 5. Report Export Formats

Reports can be exported directly from the **Findings View** in the web dashboard or programmatically via the REST API:

### 1. OASIS SARIF v2.1.0 (`GET /scans/{scan_id}/export/sarif`)
- Conforms strictly to the Static Analysis Results Interchange Format standard.
- Compatible with GitHub Code Scanning, DefectDojo, and enterprise SIEM ingestors.
- Encodes CWE/OWASP rules, URI locations, confidence scores, and diagnostic limitation properties.

### 2. Executive PDF Report (`GET /scans/{scan_id}/export/pdf`)
- Clean, confidential executive report generated via `fpdf2`.
- Formatted summary card with scan metadata and target topology counts.
- Consolidated finding table with state (`CONFIRMED`, `HYPOTHESIS`, `INCONCLUSIVE`).
- Detailed finding profiles with **automatically redacted evidence** (JWTs, Bearer tokens, AWS keys, passwords, and authorization headers masked).
- Scope boundaries and honest diagnostic limitations section.

---

## 6. Diagnostic Limitations: What AttackGraph AI Does NOT Detect

To prevent overclaiming and maintain research integrity, the tool operates within explicit, non-destructive boundaries:

1. **No Blind or Out-of-Band SQL Injection:**  
   The scanner does not inject time-delay sleep payloads (`pg_sleep`, `WAITFOR DELAY`) or DNS exfiltration tokens.
2. **No Multi-Step Stateful Business Logic Flaws:**  
   The system cannot detect multi-stage logic exploits such as currency rounding bypasses, coupon reuse, or cart race conditions.
3. **No Headless Browser JavaScript Execution:**  
   The reflection scanner uses an HTML parser and lexical context tokenizer. It observes whether characters (`<`, `>`, `"`, `'`) survive unencoded, but does not run a browser engine (e.g. Playwright/Puppeteer) to verify DOM sink execution.
4. **No CSRF Testing Without Multi-Session Anti-Automation State:**  
   Cross-site request forgery checks require stateful anti-CSRF token lifecycle validation, which is out of scope.
5. **No Memory-Corruption or Binary Exploits:**  
   The platform does not perform buffer overflow, format string, or ROP exploitation.
6. **No Weaponization:**  
   Reflected input checks stop at context observation and do not fire executable payloads (`<script>alert(1)</script>`). BOLA/IDOR checks stop at read-only differential parameter comparisons.
7. **Empirical Smoothing, Not Proof:**  
   Laplace smoothing and weakest-link confidence calculations represent heuristic calibration metrics, not formal probabilistic verification.

---

## 7. Threat Model & Security Guardrails

Because the agent interacts with live targets that may return adversarial content, all target-derived data is treated as untrusted input.

The platform architecture implements four primary defense layers:
- **Prompt Injection Defense:** Strict length truncation (`MAX_UNTRUSTED_STRING_LEN = 256`) and explicit data-framing delimiters in `agent/state_summary.py`.
- **SSRF & Scope Escape Prevention:** Server-side allowlist gate (`config/allowlist.yaml`) validated before scan initiation and enforced independently inside every tool.
- **Cross-Scan Node Isolation:** Every action validates `target_node.scan_id == current_scan_id`. Cross-scan tampering attempts are rejected and logged.
- **Duplicate Action Blocker:** Prevents hostile targets from trapping the agent in denial-of-service loops by tracking executed `(tool, node_id)` pairs.

For full threat descriptions, mitigations, and automated test specifications, see:  
👉 **[Threat Model & Guardrails Architecture](docs/threat_model.md)**

---

## 8. License

This project is licensed under the Apache 2.0 License.
