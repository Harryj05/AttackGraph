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

## 1. Measured Evaluation Results (`python -m eval.run`)

All metrics below are generated directly by the live evaluation harness v2 against running local lab instances (**OWASP Juice Shop** on `:3000`, **Damn Vulnerable Web Application / DVWA** on `:8080`, and **crAPI** on `:8888`), synthetic unit fixtures, and verified architectural limitations.

> [!WARNING]
> **Honest Evaluation Scope Disclaimer**: The evaluation benchmark consists of **41 curated cases** (25 live lab targets, 9 unit fixtures, 7 known limitations). High accuracy on this benchmark **does NOT prove** enterprise coverage, zero-day discovery, or immunity to evasion. Specifically, it does not prove resilience against runtime JS obfuscation, client-side DOM sinks, non-sequential UUID discovery, POST JSON IDOR, blind SSRF, second-order injections, or stateful multi-step business logic exploits. High metrics reflect adherence to conservative ground-truth rules within narrow, well-defined boundaries.

### Dual-Recall Evaluation Methodology & Wilson 95% CIs
To prevent overclaiming, we report **Dual Recall** with **Wilson score 95% confidence intervals**:
1. **In-Scope Recall**: Measures detector accuracy against endpoints that satisfy its architectural preconditions (excluding known blind spots).
2. **Overall Recall**: Evaluates comprehensive vulnerability coverage by penalizing the tool—classifying all architectural blind spots within the target category as **False Negatives ($FN$)**.

---

### [1] LIVE Target Suite Metrics (N=25 Live Lab Responses)
Evaluated strictly against real HTTP responses from live Docker containers (including Juice Shop basket BOLA, crAPI mechanic report BOLA, vehicle location BOLA, live login JWTs from Juice Shop and crAPI, and encoded reflection defenses):

| Detector | TP | FP | TN | FN (In-Scope) | FN (Overall) | Precision (95% CI) | In-Scope Recall (95% CI) | Overall Recall (95% CI) | FPR (N) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`access_control_check`** | 4 | 0 | 5 | 0 | 2 | **100.0%** [51.0%–100.0%] (N=4) | **100.0%** [51.0%–100.0%] (N=4) | **66.7%** [30.0%–90.3%] (N=6) | **0.0%** (N=5) |
| **`reflected_input_check`** | 2 | 0 | 5 | 0 | 2 | **100.0%** [34.2%–100.0%] (N=2) | **100.0%** [34.2%–100.0%] (N=2) | **50.0%** [15.0%–85.0%] (N=4) | **0.0%** (N=5) |
| **`secret_detection`** | 4 | 0 | 5 | 0 | 0 | **100.0%** [51.0%–100.0%] (N=4) | **100.0%** [51.0%–100.0%] (N=4) | **100.0%** [51.0%–100.0%] (N=4) | **0.0%** (N=5) |
| **Live Suite Subtotal** | **10** | **0** | **15** | **0** | **4** | **100.0%** [72.2%–100.0%] (N=10) | **100.0%** [72.2%–100.0%] (N=10) | **71.4%** [45.4%–88.3%] (N=14) | **0.0%** (N=15) |

*Live targets tested:* Juice Shop 2-user basket BOLA (`/rest/basket/{basket_id}`), crAPI mechanic report BOLA (`/workshop/api/mechanic/mechanic_report?report_id=1`), crAPI vehicle location (`/identity/api/v2/vehicle/{id}/location`), DVWA low/medium/impossible XSS, Juice Shop search/orders/echo, and Juice Shop / crAPI login JWTs. **All 25 live cases passed.**

---

### [2] UNIT / Synthetic Suite Metrics (N=9 Isolated Fixtures)
Evaluated against isolated synthetic payloads to verify edge-case parsing, structural decoding, and tenancy boundaries:

| Detector | TP | FP | TN | FN (In-Scope) | FN (Overall) | Precision (95% CI) | In-Scope Recall (95% CI) | Overall Recall (95% CI) | FPR (N) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`access_control_check`** | 1 | 0 | 2 | 0 | 1 | **100.0%** [20.6%–100.0%] (N=1) | **100.0%** [20.6%–100.0%] (N=1) | **50.0%** [9.4%–90.5%] (N=2) | **0.0%** (N=2) |
| **`reflected_input_check`** | 2 | 0 | 1 | 0 | 0 | **100.0%** [34.2%–100.0%] (N=2) | **100.0%** [34.2%–100.0%] (N=2) | **100.0%** [34.2%–100.0%] (N=2) | **0.0%** (N=1) |
| **`secret_detection`** | 3 | 0 | 0 | 0 | 2 | **100.0%** [43.9%–100.0%] (N=3) | **100.0%** [43.9%–100.0%] (N=3) | **60.0%** [23.1%–88.2%] (N=5) | **0.0%** (N=0) |
| **Unit Suite Subtotal** | **6** | **0** | **3** | **0** | **3** | **100.0%** [61.0%–100.0%] (N=6) | **100.0%** [61.0%–100.0%] (N=6) | **66.7%** [35.4%–87.9%] (N=9) | **0.0%** (N=3) |

---

### [3] KNOWN LIMITATIONS Suite (N=7 Verified Architectural Blindspots)
Cases where the tool is **expected to be blind or inconclusive**. These represent systemic boundaries documented as limitations rather than failures:

| Case ID | Detector | Ground Truth | Tool Outcome | Architectural Limitation Rationale |
| :--- | :--- | :---: | :---: | :--- |
| `limit-dom-based-reflection` | `reflected_input_check` | `VULNERABLE` | `NOT_VULNERABLE` | **Client DOM XSS:** Executed purely via Angular SPA `location.hash`; invisible to server-side HTTP probe without headless browser runtime. |
| `limit-post-json-reflection` | `reflected_input_check` | `VULNERABLE` | `NOT_VULNERABLE` | **POST JSON Reflections:** Detector only inspects and injects GET query parameters; body reflections in POST JSON APIs are outside scope. |
| `limit-crapi-uuid-path-idor` | `access_control_check` | `VULNERABLE` | `INCONCLUSIVE` | **Unguessable UUIDs:** Path identifier is a 128-bit random UUID. Detector only increments numeric path segments and cannot brute-force unlinked UUIDs. |
| `limit-post-json-idor` | `access_control_check` | `VULNERABLE` | `INCONCLUSIVE` | **POST Body IDOR:** Multi-tenant endpoint requires POST JSON body manipulation. Detector is GET-only per Section 6.5 design. |
| `limit-header-tenant-routing` | `access_control_check` | `VULNERABLE` | `INCONCLUSIVE` | **Header-Based Tenancy:** Isolation is enforced via `X-Tenant-ID` header; detector only tests path and query parameters. |
| `limit-entropy-high-token` | `secret_detection` | `VULNERABLE` | `NOT_VULNERABLE` | **High-Entropy Opaque Tokens:** Random bearer string lacking known keyword prefix (`AKIA`, `Bearer`, etc.). Missed without Shannon entropy analysis. |
| `limit-obfuscated-base64-secret` | `secret_detection` | `VULNERABLE` | `NOT_VULNERABLE` | **Runtime Obfuscation:** Secret is encoded in base64 within JavaScript `atob(...)`. Raw HTTP text regex cannot deobfuscate client-side JS. |

---

### Combined Benchmark Metrics (N=41 Total Cases)

| Detector | Precision (95% CI) | In-Scope Recall (95% CI) | Overall Recall (95% CI) | FPR (N) | Total Cases Evaluated |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`access_control_check`** | **100.0%** [56.5%–100.0%] (N=5) | **100.0%** [56.5%–100.0%] (N=5) | **62.5%** [30.6%–86.3%] (N=8) | **0.0%** (N=7) | 15 cases (9 Live, 3 Unit, 3 Limitations) |
| **`reflected_input_check`** | **100.0%** [51.0%–100.0%] (N=4) | **100.0%** [51.0%–100.0%] (N=4) | **66.7%** [30.0%–90.3%] (N=6) | **0.0%** (N=6) | 12 cases (7 Live, 3 Unit, 2 Limitations) |
| **`secret_detection`** | **100.0%** [64.6%–100.0%] (N=7) | **100.0%** [64.6%–100.0%] (N=7) | **77.8%** [45.3%–93.7%] (N=9) | **0.0%** (N=5) | 14 cases (9 Live, 3 Unit, 2 Limitations) |
| **Overall Platform** | **100.0%** [80.6%–100.0%] (N=16) | **100.0%** [80.6%–100.0%] (N=16) | **69.6%** [49.1%–84.4%] (N=23) | **0.0%** (N=18) | **41 / 41 Cases Verified (100%)** |

*Artifact Source:* [`eval/results/latest.json`](eval/results/latest.json).

---

### Scan Mode Comparison: Step-Budget Benchmark (Budgets 3, 5, 8 | N=5 Runs Each)

The harness systematically benchmarks both modes over identical lab targets with equal tool permissions, authenticated credential handles (`user_a`, `user_b`), and step budgets using the live Gemini API (`gemini-3.5-flash-lite`):

#### 1. OWASP Juice Shop (`http://localhost:3000`)
*Artifact Source:* [`eval/results/mode_comparison_juiceshop.json`](eval/results/mode_comparison_juiceshop.json)

| Budget | Mode | Steps ($\mu \pm \sigma$) | Nodes ($\mu \pm \sigma$) | Valid Findings ($\mu \pm \sigma$) | False Positives | Steps to 1st Valid | Sec to 1st Valid | Wall-Clock Time (s) | Tokens Used ($\mu \pm \sigma$) |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **3** | **Deterministic** | $3.0 \pm 0.0$ | $8.0 \pm 0.0$ | $0.0 \pm 0.0$ | $0.0 \pm 0.0$ | N/A | N/A | **12.77 s** $\pm$ 0.15 s | **0** ($0.00) |
| | **Agent (LLM)** | $3.0 \pm 0.0$ | $8.0 \pm 0.0$ | $0.0 \pm 0.0$ | $0.0 \pm 0.0$ | N/A | N/A | 19.75 s $\pm$ 0.59 s | 6,993 $\pm$ 55 ($0.0006) |
| **5** | **Deterministic** | $5.0 \pm 0.0$ | $8.0 \pm 0.0$ | $0.0 \pm 0.0$ | $0.0 \pm 0.0$ | N/A | N/A | **13.63 s** $\pm$ 0.96 s | **0** ($0.00) |
| | **Agent (LLM)** | $5.0 \pm 0.0$ | $8.2 \pm 0.4$ | $0.2 \pm 0.4$ | $0.0 \pm 0.0$ | $5.0 \pm 0.0$ | 25.69 s $\pm$ 0.0 s | 23.95 s $\pm$ 1.03 s | 15,025 $\pm$ 71 ($0.0012) |
| **8** | **Deterministic** | $8.0 \pm 0.0$ | $9.0 \pm 0.0$ | $1.0 \pm 0.0$ | $0.0 \pm 0.0$ | $4.0 \pm 0.0$ | **13.71 s** $\pm$ 0.10 s | **14.01 s** $\pm$ 0.09 s | **0** ($0.00) |
| | **Agent (LLM)** | $8.0 \pm 0.0$ | $9.6 \pm 0.5$ | $1.6 \pm 0.5$ | $0.0 \pm 0.0$ | $5.4 \pm 0.55$ | 24.30 s $\pm$ 1.19 s | 30.29 s $\pm$ 0.99 s | 27,457 $\pm$ 554 ($0.0022) |

#### 2. OWASP crAPI (`http://localhost:8888` - Known BOLA Ground Truth)
*Artifact Source:* [`eval/results/mode_comparison_crapi.json`](eval/results/mode_comparison_crapi.json)

| Budget | Mode | Steps ($\mu \pm \sigma$) | Nodes ($\mu \pm \sigma$) | Valid Findings ($\mu \pm \sigma$) | False Positives | Steps to 1st Valid | Sec to 1st Valid | Wall-Clock Time (s) | Tokens Used ($\mu \pm \sigma$) | Excluded (API Errors) |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **3** | **Deterministic** | $3.0 \pm 0.0$ | $5.8 \pm 0.4$ | $0.0 \pm 0.0$ | $0.0 \pm 0.0$ | N/A | N/A | **8.09 s** $\pm$ 0.62 s | **0** ($0.00) | 0 |
| | **Agent (LLM)** | $3.0 \pm 0.0$ | $6.0 \pm 0.0$ | $0.0 \pm 0.0$ | $0.0 \pm 0.0$ | N/A | N/A | 33.70 s $\pm$ 5.17 s | 6,231 $\pm$ 83 ($0.0005) | 0 |
| **5** | **Deterministic** | $5.0 \pm 0.0$ | $6.0 \pm 0.0$ | $0.0 \pm 0.0$ | $0.0 \pm 0.0$ | N/A | N/A | **8.19 s** $\pm$ 0.38 s | **0** ($0.00) | 0 |
| | **Agent (LLM)** | $5.0 \pm 0.0$ | $6.2 \pm 0.4$ | $0.2 \pm 0.4$ | $0.0 \pm 0.0$ | $5.0 \pm 0.0$ | 18.33 s $\pm$ 0.0 s | 20.69 s $\pm$ 1.98 s | 12,663 $\pm$ 49 ($0.0010) | 0 |
| **8** | **Deterministic** | $8.0 \pm 0.0$ | $6.6 \pm 0.5$ | $0.6 \pm 0.5$ | $0.0 \pm 0.0$ | **$8.0 \pm 0.0$** | **8.77 s** $\pm$ 0.10 s | **8.74 s** $\pm$ 0.08 s | **0** ($0.00) | 0 |
| | **Agent (LLM)** | $8.0 \pm 0.0$ | $7.0 \pm 0.0$ | **1.0** $\pm$ 0.0 | $0.0 \pm 0.0$ | $7.4 \pm 0.8$ | 56.51 s $\pm$ 4.78 s | 60.29 s $\pm$ 5.72 s | 22,617 $\pm$ 407 ($0.0018) | 0 |

> [!NOTE]
> **Deterministic vs. Agent Architectural Trade-off**:
> - **Deterministic Pipeline Mechanics & Budget 5 vs. 8 Ordering**: The deterministic pipeline executes 2 steps per endpoint (`http_probe` then `access_control_check`). Discovered endpoints are ordered by discovery arrival: `robots.txt` (steps 3–4), `index.html` (steps 5–6), and vehicle API endpoints (steps 7–8). At Budget 5, execution terminates at step 5 after probing `index.html`, never reaching the vehicle endpoints (scoring 0 findings). At Budget 8, the BOLA is tested and verified at **Step 8** (scoring 1 finding in runs where `location` is reached).
> - **Deterministic Variance ($0.6 \pm 0.5$) Empirical Root Cause**: Discovered endpoints originate from `ffuf` running 40 concurrent fuzzing threads against crAPI. Network response arrival order between `/vehicle/vehicles` (common.txt line 22) and `/vehicle/{vehicle_id}/location` (line 23) fluctuates under concurrency. When `location` arrives first (3/5 runs), it is tested at steps 7–8 (1 finding); when `vehicles` arrives first (2/5 runs), it is tested at steps 7–8 and the 8-step budget is exhausted before reaching `location` (0 findings).
> - **Agent (LLM) Adaptive Prioritization**: The agent reasons over discovered attack surfaces, prioritizing vehicle API endpoints directly from the graph state, achieving $1.0 \pm 0.0$ recall on crAPI Budget 8 and uncovering multiple finding categories ($1.6 \pm 0.5$) on Juice Shop Budget 8, at the cost of live API latency (~20s–60s) and token consumption.
> - **API Error Handling**: Runs encountering live Gemini API errors (503 Service Unavailable, timeouts, quota) are flagged as `INVALID`, excluded from statistical aggregation, and audited in the `Excluded` column.

---

### Evaluation Limitations & Methodological Constraints

1. **Sample Size ($N=5$ Runs per Budget)**: Step-budget comparison benchmarks evaluate $N=5$ iterations per budget level (30 runs per lab, 60 total benchmark runs) to balance statistical observation against live Gemini API rate limits and local lab execution overhead.
2. **Sparse Ground Truth per Target**: Local authorized benchmark labs provide a focused set of ground-truth findings (1 confirmed BOLA in crAPI, 3 vulnerabilities in Juice Shop). Consequently, each finding detection creates discrete score increments ($0.0 \to 0.2 \to 1.0$).
3. **Wide Confidence Intervals**: With finite case counts in live dynamic lab environments, 95% Wilson score confidence intervals for recall and precision remain moderately wide (e.g. 100% precision with [51.0%, 100.0%] Wilson bounds).
4. **Deterministic Remediation Templates**: Triage notes (`reports/triage.py`) are strictly generated from deterministic remediation templates rather than unconstrained LLM free-text generation; all entity claims (endpoints, status codes, user handles, CWEs) are programmatically verified against stored database evidence traces.

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
   > All endpoints except `/health` require the `X-API-Key` HTTP header. URL query parameter authentication (`?api_key=...`) is strictly rejected with HTTP 401 to prevent credential leakage in server logs and browser histories.
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

## 8. Claims Traceability Matrix

Every quantitative performance metric, security guardrail, and architectural capability reported in this README maps directly to verified repository code, passing automated tests, and machine-readable JSON artifacts:

| README Claim / Metric | Metric Value | Source Implementation | Test Suite / Runner | Backing Artifact |
| :--- | :---: | :--- | :--- | :--- |
| **Live BOLA Detection (In-Scope)** | **100.0%** [51.0%–100.0%] | [`tools/access_control_check.py`](tools/access_control_check.py) | [`eval/run.py`](eval/run.py), [`test_verification.py`](tests/test_verification.py) | [`eval/results/latest.json`](eval/results/latest.json) |
| **Reflection Check (In-Scope)** | **100.0%** [34.2%–100.0%] | [`tools/reflected_input_check.py`](tools/reflected_input_check.py) | [`eval/run.py`](eval/run.py), [`test_reflected_input_check.py`](tests/test_reflected_input_check.py) | [`eval/results/latest.json`](eval/results/latest.json) |
| **Structural Secrets (In-Scope)** | **100.0%** [51.0%–100.0%] | [`tools/secret_detection.py`](tools/secret_detection.py) | [`eval/run.py`](eval/run.py), [`test_secret_detection.py`](tests/test_secret_detection.py) | [`eval/results/latest.json`](eval/results/latest.json) |
| **Overall Recall (w/ Blindspots)** | **69.6%** [49.1%–84.4%] | [`eval/run.py`](eval/run.py) (Dual Recall) | [`test_eval_harness.py`](tests/test_eval_harness.py) | [`eval/results/latest.json`](eval/results/latest.json) |
| **Step-Budget Mode Benchmark** | Det ~7.9–14.0s ($0.00) vs Agent ~20–60s | [`eval/compare_modes.py`](eval/compare_modes.py) | [`test_mode_comparison_and_triage.py`](tests/test_mode_comparison_and_triage.py) | [`eval/results/mode_comparison.json`](eval/results/mode_comparison.json) |
| **Prompt Injection Defense** | Max 256 chars & data framing | [`agent/state_summary.py`](agent/state_summary.py) | [`test_guardrails_hostile_content.py`](tests/test_guardrails_hostile_content.py) | [`docs/threat_model.md`](docs/threat_model.md) |
| **SSRF & Scope Escape Defense** | Server allowlist + normalization | [`api/allowlist.py`](api/allowlist.py) | [`test_scans.py`](tests/test_scans.py), [`test_http_probe.py`](tests/test_http_probe.py) | [`config/allowlist.yaml`](config/allowlist.yaml) |
| **Strict Header Authentication** | HTTP 401 on `?api_key=...` | [`api/auth.py`](api/auth.py) | [`test_security_hardening.py`](tests/test_security_hardening.py) | Header enforcement |
| **SARIF & PDF Export Redaction** | Masked tokens & credentials | [`reports/export.py`](reports/export.py) | [`test_report_export.py`](tests/test_report_export.py) | Redaction filters |
| **Evidence-Grounded Triage Notes** | Verified endpoints, codes, CWEs | [`reports/triage.py`](reports/triage.py) | [`test_mode_comparison_and_triage.py`](tests/test_mode_comparison_and_triage.py) | Grounded templated notes |

---

## 9. Technical Documentation & Portfolio Resources

For detailed interview walkthroughs, architectural trade-offs, and resume talking points:
- 📖 **[AppSec & AI Engineering Interview Defense Guide](docs/INTERVIEW.md)**: Deep answers to tough interview questions on threat modeling, prompt injection, dual recall, and agent vs. deterministic trade-offs.
- 💼 **[Resume Bullets & Portfolio Talking Points](docs/RESUME_BULLETS.md)**: Metric-backed, quantified bullet points tailored for AppSec Engineer, Security Software Engineer, and AI Security roles.
- 🛡️ **[Threat Model & Guardrails Architecture](docs/threat_model.md)**: Complete threat model specifying system trust boundaries, attack vectors, and automated guardrail mitigations.

---

## 10. License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.
