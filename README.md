# PentestAI — Autonomous Penetration Testing Platform

An agentic penetration-testing platform that unifies a conversational security agent, real-time attack-graph visualization, reasoning telemetry, Human-in-the-Loop (HITL) governance, team collaboration (Groups), and automated DevSecOps remediation — backed by 20 integrated security tools.

> **Authorized use only.** This platform is intended strictly for authorized security audits, internal network assessments, and defensive remediation pipelines. Every scan is checked against a signed scope authorization, and high-risk tools are gated behind Lead approval. See [Security & Scoping Safeguards](#security--scoping-safeguards).

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Core Capabilities](#core-capabilities)
- [Tool Inventory](#tool-inventory)
- [Tech Stack](#tech-stack)
- [Repository Structure](#repository-structure)
- [Quick Start](#quick-start)
- [Configuration & Environment Variables](#configuration--environment-variables)
- [Authentication & Role Model](#authentication--role-model)
- [Agent Chat Usage](#agent-chat-usage)
- [API Endpoints Reference](#api-endpoints-reference)
- [Security & Scoping Safeguards](#security--scoping-safeguards)
- [Enterprise Safety Features](#enterprise-safety-features)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Architecture Overview

```
                        +---------------------------------------+
                        |           React Dashboard (:3000)      |
                        |  Agent Console · Attack Graph (Flow)   |
                        |  Findings · Approvals · Groups · Fixes |
                        +-------------------+-------------------+
                                            |
                          /api/* (Vite proxy / Nginx) + JWT
                                            |
                                            v
                        +---------------------------------------+
                        |            FastAPI Backend (:8000)     |
                        |  Routers: auth/users/engagements/     |
                        |  findings/reasoning/fixes/reports/    |
                        |  scans/agent/groups/admin             |
                        +-------------------+-------------------+
                                            |
              +-----------------------------+-----------------------------+
              |                             |                             |
              v                             v                             v
 +------------------------+   +-------------------------+   +-----------------------+
 | Agent Turn Pipeline    |   | Orchestrator            |   | Remediation Engine    |
 | (app/agent/turn.py)    |   | (decision_loop.py)      |   | (diff/WAF/cURL/PR)    |
 | direct regex dispatch  |   | scope gate · HITL gate  |   | fix_engine · linter   |
 | LLM planner (Gemini /  |   | ToolJobs · dedup store  |   | GitHub PR integration |
 | Ollama / OpenAI /      |   | AI output interpretation|   |                       |
 | Anthropic) · circuit   |   +------------+------------+   +-----------+-----------+
 | breaker · audit log    |                |                          |
 +-----------+------------+                |                          |
             |                             |                          |
             v                             v                          v
 +------------------------+   +-------------------------+   +-----------------------+
 | 20 Tool Adapters       |   | Celery Worker + Redis   |   | Finding Dedup         |
 | native subprocess OR   |   | (async scans, cycles)   |   | fingerprint + pgvector|
 | Docker kali-tools      |   |                         |   | semantic matching     |
 | sandbox                |   |                         |   |                       |
 +-----------+------------+   +------------+------------+   +-----------+-----------+
              |                             |                          |
              +-------------+----------------+--------------------------+
                                            |
                                            v
                              +-------------------------+
                              | SQLite (local dev)  OR  |
                              | PostgreSQL + pgvector   |
                              | (prod / docker-compose) |
                              +-------------------------+
```

**Request flow for a chat scan** (`POST /api/agent/turn` → `execute_turn`):
1. Resolve/ensure the engagement (`_ensure_default_engagement`).
2. Try direct-command regex first (`run <tool> on <target>`, `scan <target> with <tool>`) for instant Docker dispatch.
3. Otherwise plan via LLM (`PLANNER_SYSTEM_PROMPT` + engagement state).
4. Per action: target health circuit-breaker → immutable audit log → dynamic scope ensure → `run_planned_action` (scope gate → HITL approval gate → ToolJob → adapter run → dedup store).
5. Persist prompt + reply to the reasoning timeline; return assistant narrative + tool events.

## Core Capabilities

- **Conversational Security Agent** (`/` Agent Console) — chat-driven recon and scanning with per-engagement history (local + server timeline), tool result cards, thinking indicators, and day-grouped history search.
- **20-Tool Adapter Fleet** — every tool normalizes output into hosts, services, and CVSS-scored findings; runs natively or inside an ephemeral Docker `kali-tools` sandbox (`--rm`, memory/CPU caps, host networking).
- **Interactive Attack Topology** — React Flow DAG of hosts, services, and vulnerabilities with severity color coding, plus a mini-graph and host inventory views.
- **Reasoning Telemetry** — full agent trail (prompts, plans, approvals, tool I/O, interpretations) with SSE streaming, per-cycle/continuous autonomous runs, and a graph view.
- **HITL Approval Queue** (`/alerts`) — high-risk tools (`sqlmap`, `metasploit`, `hashcat`) pause for Lead sign-off; recon tools can auto-approve per engagement autonomy level.
- **RBAC + Team Management** — `lead` / `analyst` platform roles plus per-group `lead` / `co-lead` / `analyst` membership; Leads create accounts and assign roles from Settings → RootX Team (public self-register is analyst-only).
- **Groups & Collaboration** (`/groups`) — team workspaces with member management, co-lead promotion (max 2), mute, activity feed, group chat, and shareable artifacts.
- **Finding Management** — filterable ledger, bulk triage, duplicate detection (fingerprint + semantic), CSV/JSON export, per-engagement summaries.
- **Remediation Pipeline** (`/remediation`) — AI-generated patch proposals with coding-style configs, approve/reject/apply workflow, automated GitHub PR creation, WAF rule generation (ModSecurity/Nginx), verification cURL commands, and fix verification.
- **Compliance Reporting** (`/reports`) — Markdown + JSON dossiers with CVSS breakdowns, live preview, and PDF export.
- **BYOK + Multi-Provider LLM** — server key or per-user encrypted keys across Gemini, Anthropic, OpenAI, and local Ollama; free-tier per-user quota with graceful fallback.
- **Account Security** — bcrypt passwords, JWT sessions, Google SSO, Gmail OTP password reset, TOTP 2FA, session inventory + revocation, and scoped API tokens.

## Tool Inventory

All adapters live in `backend/app/adapters/` and are dispatched by name via `get_adapter()`.

| Tool key | Adapter | What it does |
|---|---|---|
| `nmap` | Nmap (XML + NSE `vuln`) | Port/service discovery, version detection, CVE script findings |
| `masscan` | Masscan-style fast probe | Rapid top-port sweep (one host record per IP, findings per open port) |
| `nuclei` | Nuclei | Template-based vulnerability scanning |
| `nikto` | Nikto | Web-server misconfiguration scanning |
| `zap` | OWASP ZAP | Web application scanning (daemon or fallback) |
| `crawler` | Crawler | Page/form/hidden-route discovery |
| `dirsearch` | Dirsearch | Directory & file brute-forcing (admin/.env/.git) |
| `whatweb` | WhatWeb | Tech-stack fingerprinting |
| `web_vuln_check` | Web vuln checks | Lightweight web vulnerability checks |
| `shadow_api` | Shadow API | Unlinked/API route extraction from source |
| `repeater` | Repeater | Raw HTTP replay with payloads (Burp-like) |
| `dns_enum` | DNS enum | A/MX/PTR enumeration |
| `subdomain`, `subdomain_enum` | Subdomain enum | Subdomain brute-forcing |
| `shodan` | Shodan | Internet-exposure enrichment (or simulated) |
| `sqlmap` | SQLMap | SQL injection testing (⚠️ approval-gated) |
| `metasploit` | Metasploit RPC | Exploitation via Kali `msfrpcd` (⚠️ approval-gated) |
| `hashcat` | Hashcat | Password cracking (⚠️ approval-gated) |
| `loot` | Loot | Secret analysis of dumps (aws_key, jwt, private_key) |
| `cloud_enum`, `cloud` | Cloud enum | Cloud bucket / `.env` enumeration |

Aliases `subdomain_enum` and `cloud` map to the same adapters for planner compatibility.

## Tech Stack

| Layer | Technologies |
|---|---|
| Backend | FastAPI, Python 3.14, SQLAlchemy 2.0, Pydantic v2, Uvicorn, Celery + Redis |
| AI routing | `app/core/llm.py` — Gemini / Anthropic / OpenAI / Ollama, Fernet-encrypted BYOK, free-tier quota |
| Auth | Bcrypt, python-jose JWT (HS256), Google SSO (`google-auth`), Gmail OTP (SMTP), TOTP 2FA (`pyotp`) |
| Data | SQLite (local dev) / PostgreSQL + pgvector (prod), Alembic migrations |
| Scanning | Native subprocess + Docker sandbox (`kali-tools`), `pymetasploit3`, `python-libnmap` |
| Remediation | `diff_generator`, `linter`, `waf_generator`, `github_integration`, `curl_generator`, `weasyprint` (PDF) |
| Frontend | React 18, Vite 6, React Router 7, React Flow 11, Tailwind CSS 3, Axios, Lucide icons |
| Infrastructure | Docker Compose (postgres pgvector:pg16, redis:7, backend, worker, tools profile, nginx frontend) |

## Repository Structure

```
.
├── backend/
│   ├── app/
│   │   ├── adapters/        # 20 tool adapters + base (native/Docker execution)
│   │   ├── agent/           # turn.py (chat pipeline) + planner.py (LLM prompts)
│   │   ├── api/             # admin, agent, auth, engagements, findings, fixes,
│   │   │                    # groups, reasoning, reports, scans, users
│   │   ├── core/            # config, security (JWT/bcrypt/RBAC), llm router,
│   │   │                    # scope_gate, autonomy_policy, sanitizers, email,
│   │   │                    # totp, notifications, fix/waf/diff/curl engines,
│   │   │                    # github_integration, backup, state_engine, audit
│   │   ├── dedup/           # fingerprint + semantic (pgvector) dedup
│   │   ├── models/          # SQLAlchemy models + database sessions
│   │   ├── orchestrator/    # decision_loop, prompts, state_engine
│   │   ├── tasks/           # Celery app + background tasks
│   │   ├── audit_trail.py   # immutable command audit log
│   │   ├── circuit_breaker.py
│   │   ├── data_sanitizer.py
│   │   ├── security_guard.py
│   │   ├── database.py
│   │   └── main.py          # FastAPI app, CORS, security headers, routers
│   ├── alembic/             # DB migrations
│   ├── tests/               # backend tests
│   ├── requirements.txt
│   ├── Dockerfile           # uvicorn app.main:app :8000
│   └── Dockerfile.tools     # kali-tools sandbox image
├── frontend/
│   ├── src/
│   │   ├── api/client.js    # Axios client + auth interceptor
│   │   ├── auth.jsx         # auth context (user, isLead, login/logout)
│   │   ├── App.jsx          # routes + role-aware shell nav
│   │   ├── components/      # AttackGraph, ApprovalQueue, FindingsTable,
│   │   │                    # ReasoningTimeline, ToolCard, GroupChat,
│   │   │                    # EngagementWizard, DashboardCards, ...
│   │   └── pages/           # AgentWorkspace, EngagementList/Detail,
│   │                        # FixesPage, ReportPreview, GroupList/Detail,
│   │                        # LoginPage, Register, Settings
│   ├── vite.config.js
│   ├── nginx.conf
│   └── Dockerfile           # nginx serving dist/ on :80
├── docker-compose.yml       # postgres, redis, backend, worker, tools, frontend
├── .env.example
└── README.md
```

## Quick Start

### Option A — Local dev (SQLite, no Docker services)

Prerequisites: Python 3.10+, Node.js 18+, npm, Git.

```bash
# 1. Backend
cd backend
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Swagger UI: `http://127.0.0.1:8000/docs` · Health: `http://127.0.0.1:8000/health`

```bash
# 2. Frontend (new terminal)
cd frontend
npm install
npm run dev
```

Dashboard: `http://localhost:3000` (Vite proxies `/api` → backend).

> The backend auto-creates SQLite tables on startup (`pentest.db`). For existing DBs it also adds missing `users` profile columns.

### Option B — Full stack via Docker Compose (Postgres + Redis + worker)

```bash
# Set keys first (see Configuration), then:
docker compose up --build
```

- Frontend: `http://localhost:3000` · Backend: `http://localhost:8000`
- Optional tool sandbox: `docker compose --profile tools up`

### First login

1. Register at `/register` (public sign-up creates **analyst** accounts).
2. Leads are created by an existing Lead in **Settings → RootX Team** (username + email + password + role), then log in at `/login` — role comes from the account, no role picker needed.
3. Create an engagement (Agent Console `+` wizard or `/engagements`), approve its scope, then start scanning from the chat.

## Configuration & Environment Variables

Create `backend/.env` (see `.env.example`). Key settings:

| Variable | Default | Purpose |
|---|---|---|
| `LLM_PROVIDER` | `gemini` | `gemini` \| `anthropic` \| `openai` \| `ollama` |
| `GEMINI_API_KEY` | — | Server-side Gemini key (stored raw in env; user BYOK keys are Fernet-encrypted in DB) |
| `GEMINI_MODEL` | `gemini-1.5-flash` | Must be a valid Google model id (e.g. `gemini-1.5-flash`) |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | — | Optional fallback providers |
| `OLLAMA_BASE_URL` / `OLLAMA_MODEL` | `http://localhost:11434` / `llama3.1` | Local air-gapped inference |
| `APP_ENCRYPTION_KEY` | — | Fernet key for BYOK storage (generate via `Fernet.generate_key()`) |
| `JWT_SECRET` | `change-me-in-production` | Min 32 random chars in prod (`python -c "import secrets; print(secrets.token_urlsafe(48))"`) |
| `JWT_EXPIRE_HOURS` | `24` | Session token lifetime |
| `GOOGLE_CLIENT_ID` | — | Google SSO client id (also `VITE_GOOGLE_CLIENT_ID` in `frontend/.env`) |
| `DATABASE_URL` | `sqlite:///./pentest.db` | Prod: `postgresql://pentest:pentest@postgres:5432/pentest_platform` |
| `REDIS_URL` | `redis://localhost:6379/0` | Celery broker |
| `USE_DOCKER` | `false` | `true` = run tools in ephemeral `kali-tools` containers |
| `DOCKER_TOOL_IMAGE` | `kali-tools:latest` | Sandbox image for tool execution |
| `DOCKER_HOST` | — | e.g. `tcp://localhost:2375` when the default socket is unreachable |
| `TOOL_TIMEOUT_SECONDS` | `600` | Per-tool execution ceiling |
| `AUTO_APPROVE_RECON` | `true` | Auto-approve low-risk recon; exploits always need approval |
| `SMTP_HOST/PORT/USER/PASSWORD/FROM` | — | Gmail OTP delivery (empty = dev mode, OTP in console) |
| `MSF_RPC_HOST/PORT/USER/PASS/SSL` | `127.0.0.1:55553` | Kali `msfrpcd` connection (per-scan params can override) |
| `GITHUB_TOKEN/REPO/BASE_BRANCH` | — | 1-click fix PR creation |

## Authentication & Role Model

**Login methods:** password (`POST /api/auth/login`), OAuth token exchange (`/token`), Google SSO (`/google`), Gmail OTP reset flow (`/request-otp` → `/verify-otp-reset` → `/reset-password`), TOTP 2FA (`/2fa/*`), revocable sessions (`/sessions`) and API tokens (`/tokens`).

| Capability | Analyst | Lead |
|---|---|---|
| Chat agent, run recon scans | ✅ | ✅ |
| View engagements, topology, findings | ✅ | ✅ |
| Triage findings, generate/propose fixes | ✅ | ✅ |
| Authorize scopes, approve HITL tools | ❌ | ✅ |
| Create users & assign roles (RootX Team) | ❌ | ✅ |
| Promote/demote users, manage groups | ❌ | ✅ |
| Dispatch GitHub PRs, edit style guides | ❌ | ✅ |

Inside **Groups**, membership roles are `lead` / `co-lead` (max 2, promoted by the group lead) / `analyst`, with mute support. The `is_founder` flag protects the founding Lead from demotion.

## Agent Chat Usage

Open the Agent Console (`/`), pick an engagement, and type:

```
run nmap on 192.168.56.102
scan 192.168.56.102 with nuclei
run masscan on 192.168.56.102
use zap on http://192.168.56.102
```

- Direct commands (`run/scan/use <tool> on/with <target>`) dispatch immediately to Docker/native runners.
- Anything else goes to the LLM planner, which answers questions directly (`actions: []`) or emits an ordered tool plan.
- Every target is scope-checked first; out-of-scope probes are blocked with an explanation, and high-risk tools pause in the Approval Queue.
- Replies include inline tool cards with finding summaries; full rows live under Findings and the reasoning timeline.

## API Endpoints Reference

Interactive docs: `http://127.0.0.1:8000/docs`. All `/api/*` routes (except register/login/OTP/Google) require a Bearer JWT.

### Authentication & Users
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Public sign-up (analyst role, server-enforced) |
| POST | `/api/auth/login` | JSON login → JWT (+ session cookie) |
| POST | `/api/auth/request-otp` | Email 6-digit reset code to registered Gmail |
| POST | `/api/auth/verify-otp-reset` | Verify reset code |
| POST | `/api/auth/reset-password` | Set new password with verified code |
| POST | `/api/auth/token` | OAuth2 password-grant token |
| POST | `/api/auth/logout` | Invalidate current session |
| POST | `/api/auth/google` | Google OAuth code → session JWT |
| GET/PATCH | `/api/auth/me` | Own profile / update profile |
| POST | `/api/auth/change-password` | Rotate password |
| POST | `/api/auth/2fa/setup|enable|disable` | TOTP 2FA lifecycle |
| GET/POST | `/api/auth/sessions`, `/api/auth/sessions/{id}/revoke` | Session inventory + revocation |
| GET/POST/DELETE | `/api/auth/tokens`, `/api/auth/tokens/{id}` | Scoped API tokens |
| GET/PATCH | `/api/users/me`, `/api/users/profile` | Profile shortcuts |
| GET | `/api/users/` | Roster (lead) |
| POST | `/api/users/create` | Lead creates account with role |
| POST | `/api/users/{id}/promote` | Promote/demote operator |

### Engagements & Scope
| Method | Endpoint | Description |
|---|---|---|
| POST/GET | `/api/engagements/` | Create / list engagements |
| GET/PATCH | `/api/engagements/{id}` | Detail / update (status, autonomy) |
| POST | `/api/engagements/{id}/autonomy` | Set autonomy (`human_gated`, …) |
| POST/GET | `/api/engagements/{id}/scope` | Add / list scope authorizations |
| POST | `/api/engagements/{id}/scope/{sid}/approve` | Approve scope (lead) |
| POST | `/api/engagements/{id}/scope/{sid}/upload` | Upload signed scope document |
| GET | `/api/engagements/{id}/hosts`, `.../services`, `.../inventory` | Asset inventory |

### Agent, Telemetry & Approvals
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/agent/turn` | One chat turn: message → plan → gated execution |
| GET/DELETE | `/api/agent/history/{engagement_id}` | Chat timeline / clear it |
| GET | `/api/reasoning/engagement/{id}` | Full reasoning trail |
| POST | `/api/reasoning/engagement/{id}/cycle`, `.../continuous` | Autonomous decision cycles |
| POST | `/api/reasoning/{log_id}/approve` | Approve gated action (lead) |
| GET | `/api/reasoning/engagement/{id}/queue` | Pending HITL approvals |
| GET | `/api/reasoning/engagement/{id}/graph` | Attack-graph data |
| GET | `/api/reasoning/engagement/{id}/jobs`, `/api/reasoning/jobs/{job}/output` | Tool jobs + stdout |
| GET | `/api/reasoning/engagement/{id}/stream` | SSE telemetry stream |

### Findings, Fixes, Reports, Scans
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/findings/engagement/{id}` | Filterable vulnerability ledger |
| POST | `/api/findings/bulk-update` | Bulk triage |
| GET | `/api/findings/engagement/{id}/export` | CSV/JSON export |
| GET/PATCH | `/api/findings/{finding_id}` | Detail / triage update |
| GET | `/api/findings/engagement/{id}/summary`, `.../duplicates` | Stats + duplicate clusters |
| POST/GET | `/api/fixes/styles`, `/api/fixes/engagement/{id}/styles` | Coding-style configs |
| POST | `/api/fixes/generate` | AI patch proposal |
| GET | `/api/fixes/engagement/{id}` | Proposals per engagement |
| POST | `/api/fixes/{id}/approve|reject|apply|create_pr|verify` | Remediation workflow |
| POST | `/api/reports/generate` | Markdown + JSON dossier |
| GET | `/api/reports/engagement/{id}/preview`, `.../pdf` | Live preview + PDF export |
| GET/POST | `/api/scans/tools`, `/api/scans/validate`, `/api/scans/manual` | Tool catalog, validation, manual dispatch |

### Groups & Admin
| Method | Endpoint | Description |
|---|---|---|
| POST/GET | `/api/groups/` | Create / list groups |
| GET | `/api/groups/{id}` | Group detail + members |
| POST | `/api/groups/{id}/members` | Add member with role |
| POST | `/api/groups/{id}/co-lead/{uid}`, `.../demote/{uid}` | Co-lead promotion (max 2) / demote |
| POST | `/api/groups/{id}/mute/{uid}`, `.../unmute/{uid}` | Mute control |
| GET/POST | `/api/groups/{id}/activity` | Activity feed |
| GET/POST | `/api/groups/{id}/messages` | Group chat |
| POST/GET | `/api/groups/{id}/share`, `.../shares`, `.../shares/{sid}/seen` | Shared artifacts |
| GET | `/api/admin/backup` | Platform backup (lead) |
| GET | `/health`, `/api/stats` | Health + platform counters |

## Security & Scoping Safeguards

- **Scope gate** (`core/scope_gate.py`) — every target is cross-checked against the engagement's signed `allowed_targets`/`excluded_targets` and time window before execution; violations are logged and refused.
- **HITL approval** — `HIGH_RISK_TOOLS` (`sqlmap`, `metasploit`, `hashcat`) always require Lead sign-off regardless of autonomy mode.
- **Execution sandbox** — Docker mode runs each tool in an ephemeral, memory/CPU-capped container (`--rm`); native mode resolves binaries without `shell=True` and sanitizes targets/ports (`security_guard.py`, nmap arg allow-list).
- **Target health circuit breaker** — unhealthy targets trip before tool dispatch instead of hanging the turn.
- **Immutable audit trail** — every dispatched command is hash-chained (`audit_trail.py`, `core/audit.py`).
- **Prompt-injection resistance** — planner wraps tool output in `<untrusted_scan_output>` tags with explicit do-not-obey instructions; user input passes through prompt/data sanitizers.
- **Storage integrity** — hosts are unique per `(engagement_id, ip_address)` with in-memory + flush-level dedup; all write paths roll back cleanly on `IntegrityError` so one bad insert can never wedge the session.
- **Transport hardening** — OWASP security headers middleware, credentialed CORS allow-list, HttpOnly session cookies, rate-limited auth endpoints.

## Enterprise Safety Features

Ten enterprise guardrails protect every scan. Each item below explains **what it does in detail**, followed by a **simple-language** analogy. Items marked `[ENFORCED]` are backed by code (file references); items marked `[OPERATIONAL]` need a one-time setup step described alongside.

### 1. Non-Destructive Exploit Whitelisting (Safe Checks Only) `[ENFORCED]`

**In detail.** The scanner is only ever allowed to *prove a vulnerability exists* — it may never run a payload that crashes a service, writes data, or opens a shell. Enforcement lives in `backend/app/core/safe_policy.py` and is wired into every relevant adapter:
- **Nmap** (`adapters/nmap_adapter.py`) runs NSE scripts in detection mode only (`vuln and not dos`); any `exploit`, `dos`, `intrusive`, or `brute` script category smuggled in via parameters is stripped before the command is built.
- **SQLMap** (`adapters/sqlmap_adapter.py`) runs detection-only (`level`/`risk` coerced to sane ints, stacked queries disabled); exfiltration/execution flags (`--dump`, `--os-shell`, `--sql-shell`, `--file-read/write`, …) raise `ValueError` instead of executing.
- **Metasploit** (`adapters/metasploit_adapter.py`) executes `check`-only verification for `exploit` modules (reads the module's own "vulnerable / not vulnerable" verdict) and runs `auxiliary` scanner modules; weaponized exploitation additionally sits behind the Lead HITL approval gate.

**In simple terms.** A security guard checking whether your front door is unlocked by gently turning the handle — never by kicking the door off its hinges.

### 2. Ephemeral Sandboxed Runners (Use-and-Throw Containers) `[ENFORCED]`

**In detail.** Every Docker tool execution (`backend/app/adapters/base.py::execute_in_docker_sandbox`) launches a fresh container that is destroyed the instant the tool exits (`--rm`). Each run is resource-bounded (`--memory`, `--cpus`, `--pids-limit` for fork-bomb containment) and filesystem-isolated (`--read-only` with only `/tmp` writable via tmpfs), so scan artifacts, temp files, and tool state can never leak from one engagement — or one client — into the next. Toggles: `DOCKER_HARDENED`, `DOCKER_PIDS_LIMIT` in `backend/app/core/config.py`.

**In simple terms.** Single-use disposable gloves for each patient — nothing from Company A's scan can ever touch Company B's.

### 3. Cryptographic Scope Pinning (The Digital Geofence) `[ENFORCED]`

**In detail.** When a Lead approves a scope (`POST /api/engagements/{id}/scope/{sid}/approve`), the server computes an HMAC-SHA256 signature over the exact approved state — engagement id, allowed targets, excluded targets, and time window — and stores it on the authorization row (`ScopeAuthorization.signature`, `backend/app/core/safe_policy.py::sign_scope`). Every scan dispatch re-verifies the pin inside `is_target_in_scope()` (`backend/app/core/scope_gate.py`): if anyone edits the target list in the database afterward, the signature stops matching and **all execution is blocked** until a Lead re-approves. Scopes created dynamically (`scans._ensure_scope`, console auto-scope) are pinned at creation, and pre-existing rows self-heal by signing on first check.

**In simple terms.** An invisible dog collar for the yard: even if the AI agent wanders toward `google.com`, the fence checks the signed map and drops the packets instantly.

### 4. Adaptive Rate Limiting & Throttling (The Speed Governor) `[ENFORCED]`

**In detail.** Packet/request ceilings are enforced centrally (`safe_policy.clamp_nmap_timing`, `clamp_masscan_rate`) and wired into the adapters: nmap timing templates are capped at `NMAP_MAX_TIMING` (default `-T4`), and masscan probe rates are capped at `MASSCAN_MAX_RATE` (default 1000 pps). Scans therefore proceed at a steady, authorized pace instead of bursting thousands of packets per second at a target.

**In simple terms.** A speed limiter on the car — the scanner drives at a safe, steady pace instead of accidentally DDoS-ing the client's website.

### 5. Immutable Audit Trail (The Black-Box Flight Recorder) `[ENFORCED]`

**In detail.** Every dispatched command is appended to a per-day JSONL ledger under `AUDIT_TRAIL_DIR` (default `backend/audit_trail/`) by `backend/app/audit_trail.py::log_audit_event` — which `execute_turn` already calls on every tool action. Each entry carries an **IST timestamp** and a **SHA-256 hash chain** (`entry_hash` commits to `prev_hash`), so editing or deleting any line invalidates every line after it; `verify_chain()` proves integrity on demand. Secrets are redacted before writing, and the module only ever opens the ledger in append mode — it cannot edit or delete. (Auth-domain events are additionally stored via `core/audit.py`.)

**In simple terms.** An airplane's black box: once written, nobody — not even the administrator — can edit or fake the log, so you always have legal proof of exactly what ran.

### 6. Target Health Circuit Breaker (Automatic Safety Fuse) `[ENFORCED]`

**In detail.** Before any tool is dispatched, `execute_turn` runs `TargetCircuitBreaker.check_http_health()` (`backend/app/circuit_breaker.py`): a lightweight HEAD/GET probe with a 2.5 s budget. The fuse **trips** — aborting the dispatch — on HTTP 500/502/503/504, on absolute latency breaches, and on >50% latency spikes versus the host's rolling baseline (exponential moving average tracked per host). Crucially, the breaker judges *degradation, not absence*: a refused connection or DNS miss simply means "no web service here" and lets non-web scans (nmap/masscan) proceed, while a host that *was* healthy and stops answering trips immediately.

**In simple terms.** The circuit breaker in your house: if the server starts overheating under load, the switch flips off before anything catches fire.

### 7. Zero-Data-Exfiltration Proofs (Harmless Demonstrations) `[ENFORCED]`

**In detail.** High-severity findings prove the *class* of exposure without persisting the sensitive *value*: `loot_adapter` masks every matched secret (AWS keys, JWTs, private keys, passwords, bearer tokens) keeping only type + shape (`AKIA***LE`); sqlmap is restricted to detection and database-name enumeration — table dumps are refused at the policy layer; and `redact_secrets()` scrubs secret patterns from reasoning-timeline text before it is stored. You get "vault door open, photographed" — never the cash.

**In simple terms.** Photographing the open vault door to prove it is insecure, instead of stealing the cash inside.

### 8. Dedicated Static Egress Gateways (The Official Calling Card) `[ENFORCED + OPERATIONAL]`

**In detail.** **Code (done):** every Python-driven probe stamps an identification header — `User-Agent: PentestAI/<tool>` plus `X-PentestAI-Authorized-Scan: <SCANNER_IDENTITY>` (centralized in `safe_policy.scanner_headers()`, wired into dirsearch, whatweb, crawler, repeater, and web_vuln adapters) — so the client's SOC can distinguish authorized scan traffic in its WAF/SIEM. **Operational (your one-time setup):** run scans from fixed egress IPs (NAT gateway / static public IP on the scanning host or Kali VM), share those IPs plus the header values with the client's SOC for allowlisting, and set `SCANNER_IDENTITY` per client if you want per-engagement attribution.

**In simple terms.** Visitor badge + uniform: the client's security team sees the badge, checks the guest list, and waves you through instead of calling the police.

### 9. Rootless & Unprivileged Process Execution (No Superuser Power) `[ENFORCED]`

**In detail.** Tool containers drop **all** Linux capabilities (`--cap-drop=ALL`), forbid privilege escalation (`--security-opt=no-new-privileges`), and run as the unprivileged `nobody` user (UID 65534, `HOME=/tmp`) instead of root — toggles `DOCKER_ROOTLESS` / `DOCKER_HARDENED` in config. Consequence, by design: raw-socket techniques (SYN-stealth scans, SYN floods) cannot run inside the sandbox; adapters default to unprivileged connect scans (`-sT`), which need no special capability. Even if a bundled tool had a zero-day, there is no capability left to escape with.

**In simple terms.** The contractor gets a keycard for the utility closet only — never the master key to the building.

### 10. Zero-Trace Credential Vaulting (In-Memory Secrets) `[ENFORCED + POLICY]`

**In detail.** **Code (done):** user BYOK keys are Fernet-encrypted at rest (`core/llm.py`, key: `APP_ENCRYPTION_KEY`); `redact_params()` masks secret-valued tool parameters (cookies, tokens, passwords, `rpc_pass`, …) in every log surface; loot evidence and timeline text are masked as in §7; the audit ledger redacts before writing. **Policy (how to stay compliant):** keep `MSF_RPC_PASS`, SMTP, and cloud credentials in environment/secret-manager only — never paste them into chat (masked if you do, but in-RAM handling is safest); prefer per-scan authenticated checks via env-backed defaults over inline secrets.

**In simple terms.** A code memorized for one phone call and then forgotten — never written on sticky notes, saved in chats, or left on disk.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `POST /api/agent/turn → 500`, `UNIQUE constraint failed: hosts…` | Old masscan build queued one host per port | Pull latest `masscan_adapter.py` + `decision_loop.py` (dedup + per-host flush) |
| `500`, `FOREIGN KEY constraint failed: reasoning_log` | Turn logged against a non-persisted engagement id | Pull latest `turn.py`/`agent.py` (ghost-engagement guard + session rollback) |
| `401 Invalid credentials` on login | Wrong password, or username case mismatch (`Lead_depanshu` ≠ `lead_depanshu`) | Use exact username; reset via Gmail OTP flow; Leads can recreate the account in RootX Team |
| Chat answers but runs no tools | Target outside engagement scope or Docker down | Add the target to the engagement scope; check `USE_DOCKER` + Docker daemon / `DOCKER_HOST` |
| `GEMINI_MODEL` errors | Invalid model id | Use a real id such as `gemini-1.5-flash` |
| No findings on Metasploitable | Scope missing the VM subnet, or only fast ports scanned | Add e.g. `192.168.56.0/24` to scope; follow masscan with `run nmap on <ip>` for NSE CVE scripts |

## License

No license has been specified for this project yet. Add a `LICENSE` file to the repository root to define how others may use, modify, and distribute this code.
