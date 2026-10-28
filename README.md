# Enterprise AI Cybersecurity SOC Assistant & "Signal Room" Dashboard

A production-grade, full-stack Security Operations Center (SOC) platform and detection correlation engine. Built with **React 19**, **TypeScript**, **Tailwind CSS**, **Express.js**, **PostgreSQL** (via **Drizzle ORM**), **Server-Sent Events (SSE)**, and an isolated **Python Windows Log Detector Microservice Sidecar**.

---

## 🏛️ System Architecture

```
                       ┌────────────────────────────────────────────────────────┐
                       │               React 19 / Vite Frontend                │
                       │             "Signal Room" Dark Aesthetic               │
                       │     (Dashboard, Alerts, Logs, Investigations, Reports) │
                       └───────────────────────────┬────────────────────────────┘
                                                   │
                         HTTP REST + JWT Cookies   │   Server-Sent Events (SSE)
                                                   ▼
                       ┌────────────────────────────────────────────────────────┐
                       │               Express.js Backend (Port 5001)           │
                       │                                                        │
                       │  - Auth & RBAC Security (4 Tiered Personas)            │
                       │  - Normalization Engine (Windows, Suricata, Syslog)    │
                       │  - Real-Time Correlation Engine (6 Detection Rules)    │
                       │  - SSE Transport & Event Bus                           │
                       │  - AI Explanation Engine (Gemini / Deterministic)      │
                       │  - Threat Intelligence Multi-Feed Caching Engine       │
                       │  - Report Synthesis Service (EXEC, INC, OPS)           │
                       └─────────────┬────────────────────────────┬─────────────┘
                                     │                            │
                                     │ Drizzle ORM                │ Loopback HTTP (127.0.0.1:8000)
                                     ▼                            │ Shared Token Authentication
                       ┌───────────────────────────┐              ▼
                       │    PostgreSQL Database    │    ┌───────────────────────────────────┐
                       │                           │    │    Python Detector Microservice   │
                       │ - users & sessions        │    │        (AI_SOC_Assistant)         │
                       │ - alerts & alert_logs     │    │                                   │
                       │ - logs (raw & normalized) │    │ - Windows Security Event Parser   │
                       │ - cases & timeline        │    │ - LOLBin Suspicious Execution     │
                       │ - threat_intel_cache      │    │ - MITRE ATT&CK Classification     │
                       │ - reports                 │    │   (T1110.001 vs T1110.003)        │
                       └───────────────────────────┘    └───────────────────────────────────┘
```

---

## 📋 Comprehensive Phase Status & Implementation Report

### Phase 1: Foundation & PostgreSQL Data Architecture
- **Status:** `Complete`
- **Database Engine:** PostgreSQL via Drizzle ORM.
- **Data Models:**
  - `users`: Secure analyst credentials, role assignment, and audit timestamps.
  - `sessions`: SHA-256 hashed refresh tokens, client IP, user agent, expiration tracking.
  - `logs`: Raw log payload, normalized metadata (IPs, ports, protocol, severity, timestamp).
  - `alerts`: Correlated security detections, MITRE tactic/technique mapping, confidence score, status workflow.
  - `alert_logs`: Many-to-many relationship linking alerts directly to originating forensic log events.
  - `cases`: Comprehensive incident investigation cases, assigned analysts, status, timeline, and containment playbooks.
  - `threat_intel_cache`: Database-backed threat reputation cache with configurable TTL.
  - `reports`: Evidence-backed compliance, executive, and technical incident reports with structured `contentJson`.

### Phase 2: Authentication, Session Management & Enterprise RBAC
- **Status:** `Complete` | **Verification:** 33 / 33 automated tests passing.
- **Credential Protection:** Passwords hashed with `bcryptjs` (salt rounds = 10). Refresh tokens stored as SHA-256 digests; raw tokens never touch the database.
- **Session Lifecycle:** 15-minute short-lived JWT access tokens and 7-day HttpOnly, Secure, SameSite refresh cookies with rotation and token-reuse detection.
- **Granular RBAC Matrix:**
  - `Senior Analyst`: Full alert triage, case status updates, and investigation management.
  - `Threat Hunter`: Deep read-only access to logs, network flows, and indicators; restricted from destructive triage actions.
  - `Detection Engineer`: Log ingestion (`ingest:logs`), rule tuning, and normalization pipeline configuration.
  - `Incident Commander`: Full administrative privilege, case escalation, and containment authorization.

### Phase 3: Ingestion, Normalization & Correlation Detection Engine
- **Status:** `Complete` | **Verification:** 20 / 20 automated tests passing.
- **Log Ingestion:** Supports single-event REST ingestion and multi-line file upload (`.log`, `.txt`, `.json`, `.csv`).
- **Parsers & Normalizers:**
  - Windows Security Events (Event ID 4624 logon, 4625 failed logon, 4672 admin logon, 4688 process creation).
  - Linux/Firewall Key-Value Syslog (iptables packet drops, accept rules).
  - Network IDS (Suricata EVE JSON format).
- **Correlation Detection Rules:**
  - `RULE-WEB-001` (SQL Injection): Regex patterns matching UNION SELECT, sleep injection, boolean bypass.
  - `RULE-WEB-002` (XSS): Detection of `<script>`, `onerror=`, `javascript:` payloads.
  - `RULE-AUTH-001` (Brute-Force Attack): Sliding-window threshold correlation (10 failed attempts within 5 minutes).
  - `RULE-AUTH-002` (Success After Brute Force): Suspicious successful logon following repeated failures.
  - `RULE-NET-001` (Port Scanning): High-volume SYN/connection attempts across distinct destination ports.
  - `RULE-PRIV-001` (Privilege Escalation): Suspicious administrative group assignment or process elevation.
- **Deduplication:** 5-minute sliding window suppresses alert storming for identical source/destination/rule tuples while preserving log linkage.

### Phase 4: Real-Time Telemetry Streaming & Transport (SSE)
- **Status:** `Complete` | **Verification:** 14 / 14 automated tests passing.
- **Transport:** Server-Sent Events (`GET /api/stream/events`) with persistent heartbeat (`ping` every 15 seconds).
- **Channel Isolation & Pooling:** Server-side listener tracking with automatic resource cleanup upon client disconnect.
- **Event Bus Topics:**
  - `log.ingested`: Dispatched immediately upon single log ingestion.
  - `alert.created`: Dispatched when correlation engine triggers a new alert.
  - `alert.status_changed`: Dispatched during analyst triage (`Investigating`, `False Positive`, `Contained`).
  - `dashboard.stats_updated`: Coalesced telemetry updates refreshing overview metrics.
- **State Recovery:** Frontend transparently recovers missed state via REST fallback upon reconnection.

### Phase 5: AI Incident Explanation & Investigation Assistant
- **Status:** `Complete` | **Verification:** 10 / 10 automated tests passing.
- **Dual-Mode Generation:** Powered by Google Gemini 2.5 Flash with zero-latency deterministic rule fallback when API keys are unconfigured.
- **Investigation Output:** Reconstructs structured executive summary, technical breakdown, MITRE ATT&CK alignment, and step-by-step remediation actions.
- **Security Safeguards:** Zero secret exposure; prompt injection sanitization; evidence hash verification with `isStale` automatic invalidation.

### Phase 6: Threat Intelligence Integrations & Enrichment
- **Status:** `Complete` | **Verification:** 10 / 10 automated tests passing.
- **Providers:** AbuseIPDB, VirusTotal, and AlienVault OTX.
- **PostgreSQL Caching:** 24-hour TTL (`threat_intel_cache`) with manual cache-busting capabilities.
- **Security & Protection:** Strict SSRF safeguards (no arbitrary fetching), defanged input normalization (`1[.]1[.]1[.]1`), in-flight promise coalescing.
- **Zero-Key Operation:** Gracefully runs in local-only mode without crashes or fake scores when API keys are absent.

### Phase 7: Python Windows Log Detector Microservice Sidecar
- **Status:** `Complete` | **Verification:** 7 / 7 Vitest + 12 / 12 Python tests passing.
- **Architecture:** Lightweight HTTP sidecar (`AI_SOC_Assistant/detector_service.py`) bound exclusively to `127.0.0.1:8000`.
- **Authentication:** Enforced loopback shared secret authorization (`Authorization: Bearer <secret>`). Secrets are never logged or exposed to the browser.
- **Parsing Hardening:**
  - Refined LOLBin detection: Requires remote URLs paired with staging output flags (`-o`, `-O`, `--output`) or executable payload extensions (`.exe`, `.ps1`), eliminating benign `curl` false positives.
  - MITRE ATT&CK Classification: Distinguishes between **T1110.001** (Password Guessing against a single target) and **T1110.003** (Password Spraying across $\ge 2$ distinct user accounts).
- **Fault-Tolerant Integration:** Non-blocking enrichment. On service timeout, network failure, or invalid JSON, native dashboard ingestion proceeds uninterrupted.

### Phase 8: Reporting Engine, Case Linking & Multi-Format Synthesis
- **Status:** `Complete` | **Verification:** 9 / 9 Vitest tests passing.
- **Synthesis Service (`server/services/reportService.ts`):** Synthesizes live telemetry from PostgreSQL `cases`, `alerts`, and `logs` into three standard report templates:
  1. **Executive Incident Report (`EXEC-YYYY-XXXX`):** C-suite impact assessment, business risk ratings, regulatory action recommendations, and executive decision checklists.
  2. **Technical Investigation Report (`INC-YYYY-XXXX`):** In-depth digital forensics trail, process execution trees, MITRE ATT&CK mapping, IOC evidence, and containment playbooks.
  3. **Operational Summary (`OPS-YYYY-XXXX`):** Fleet-wide security coverage score, 24-hour/weekly event counts, severity breakdowns, and proactive defense recommendations.
- **Interactive UI (`client/src/components/ReportModal.tsx` & `Home.tsx`):**
  - Live modal supporting preview inspection and template generation linked to active cases.
  - Status management (`Draft` → `Review` → `Published`).
  - Search and filter controls for instantaneous archive exploration.
- **Export & Delivery:**
  - **Printable HTML / PDF:** Zero-dependency, clean print layout using CSS `@media print` with one-click `window.print()` PDF generation.
  - **Structured Markdown:** GFM-compliant markdown with timestamps and forensic tables.
  - **Raw JSON:** Full JSON export of telemetry and metadata for automated SIEM/SOAR ingestion.
- **Resilience:** Graceful handling of missing or partial telemetry data with zero server crashes.

### Phase 9: Operational Hardening, Diagnostics & Health Monitoring
- **Status:** `Complete`
- **Health Endpoints:**
  - `GET /api/health`: Database connectivity, uptime, active SSE connection count, and Python detector sidecar status.
- **Code Quality:** 100% strict TypeScript compilation (`tsc --noEmit`) with zero errors.

---

## 🧪 Comprehensive Automated Test Matrix

All test suites run deterministically and verify end-to-end functionality:

| Test Suite | Focus Area | Command | Result |
|---|---|---|---|
| **Phase 2 Auth & RBAC** | JWT rotation, bcrypt, 4 RBAC roles | `npx tsx tests/phase2_auth_rbac.test.ts` | **33 / 33 Passed** |
| **Phase 3 Detection Engine** | Normalization, SQLi, Brute-force, Sysmon | `npx tsx tests/phase3_verification.ts` | **20 / 20 Passed** |
| **Phase 4 Real-Time SSE** | Event streams, reconnect, pooling | `npx tsx tests/phase4_realtime.test.ts` | **14 / 14 Passed** |
| **Phase 5 AI Explanation** | Structured narrative, prompt security | `npx tsx tests/phase5_explanation.test.ts` | **10 / 10 Passed** |
| **Phase 6 Threat Intel** | Multi-feed cache, SSRF defense | `npx tsx tests/phase6_threat_intel.test.ts` | **10 / 10 Passed** |
| **Phase 7 Sidecar (TS)** | Fault-tolerance, bounding, timeouts | `npx vitest run --root . tests/windows_detector_poc.test.ts` | **7 / 7 Passed** |
| **Phase 7 Sidecar (Py)** | LOLBin regex, MITRE T1110.001/003 | `python -m unittest test_bruteforce_mitre.py test_lolbin_regex.py test_detector_service.py` | **12 / 12 Passed** |
| **Phase 8 Reporting** | Synthesis, Case linking, HTML/MD export | `npx vitest run --root . tests/phase8_reports.test.ts` | **9 / 9 Passed** |
| **TypeScript Typecheck** | Strict compilation, zero type errors | `npm run check` | **0 Errors** |

---

## 🚀 Setup & Execution Guide

### 1. Prerequisites
- **Node.js:** v20.x or higher
- **PostgreSQL:** v15.x or higher
- **Python:** v3.10+ (for Python log detector sidecar)

### 2. Environment Configuration

Create `.env` in `soc-assistent-dashboard`:
```env
PORT=5001
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/soc_assistant
JWT_SECRET=your_jwt_secret_key_at_least_32_characters_long
SESSION_SECRET=your_session_secret_key_at_least_32_characters_long

# Python Windows Detector Sidecar (Phase 7)
PYTHON_DETECTOR_ENABLED=true
PYTHON_DETECTOR_URL=http://127.0.0.1:8000
PYTHON_DETECTOR_SECRET=your_shared_256bit_secret_token
PYTHON_DETECTOR_TIMEOUT_MS=4000

# Optional Threat Intelligence Feeds (Phase 6)
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
ALIENVAULT_OTX_API_KEY=

# Optional Gemini AI Key (Phase 5)
GEMINI_API_KEY=
```

Create `.env` in `AI_SOC_Assistant`:
```env
PYTHON_DETECTOR_SECRET=your_shared_256bit_secret_token
DETECTOR_HOST=127.0.0.1
DETECTOR_PORT=8000
```

### 3. Database Initialization
```bash
cd soc-assistent-dashboard
npm run db:migrate
npm run db:seed
```

### 4. Running the Application

**Terminal 1: Start Python Log Detector Sidecar**
```bash
cd AI_SOC_Assistant
python detector_service.py
```

**Terminal 2: Start Full-Stack SOC Assistant Dashboard**
```bash
cd soc-assistent-dashboard
npm run dev
```

The frontend will be available at **`http://localhost:3000`** and the backend API at **`http://localhost:5001`**.

---

## 🔒 Security Best Practices Implemented
- **No Hardcoded Secrets:** All credentials are dynamically resolved from environment variables and excluded via `.gitignore`.
- **Strict Network Isolation:** Python sidecar binds exclusively to loopback interface `127.0.0.1`.
- **Input Sanitization & Defanging:** Automatic normalization of defanged indicators (`x[.]com`), preventing accidental outbound lookups.
- **SSRF Defense:** External APIs are accessed only via official SDK endpoints; user-submitted URLs are never fetched directly.
- **XSS-Safe HTML Rendering:** Exported HTML documents automatically sanitize special characters before DOM rendering.
