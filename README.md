# AI-Enhanced Cloud XDR Platform — URL Threat Sandbox & Analyzer

Production-grade full-stack web application and automated detonation sandbox for deep URL threat analysis. Developed as part of the AI-Enhanced Cloud XDR Platform for Automated Threat Detection and Response.

---

## 1. Architecture Overview

```
                                    +-----------------------------------+
                                    |    HTTPS / Nginx Reverse Proxy    |
                                    |       (Security Headers, SSL)     |
                                    +-----------------+-----------------+
                                                      |
                                                      v
+-------------------------------------------------------------------------------------------------------------+
|                                        FastAPI Backend Application                                          |
|                                                                                                             |
|  [Routers]                                                                                                  |
|   ├── Auth (JWT, CSRF, Lockout, Argon2/Bcrypt)       ├── Bulk CSV Queue & Job Tracker                      |
|   ├── Scans (Detonation, Rescan, Comparison)        ├── Watchlists & Recurring Scan Engine                 |
|   ├── Rules (Allowlist / Blocklist Precedence)      ├── AI Security Assistant (Prompt-Injection Immune)    |
|   ├── Analyst Feedback (TP/FP/Review Annotations)   ├── XDR Scoped API Tokens (SHA-256 Hashed)             |
|   └── Admin Console & Real-Time Audit Log           └── Platform Dashboard & Threat Distribution Telemetry  |
|                                                                                                             |
|  [Security & Isolation Gates]                                                                               |
|   ├── HostGuard: Rejects loopback, private RFC1918, link-local, multicast, & cloud metadata 169.254.169.254|
|   └── EgressProxy: DNS rebinding defense, validates resolved IPs at connection time on every hop            |
|                                                                                                             |
|  [Detonation Engine]                                                                                        |
|   ├── Playwright Chromium headless sandbox (disposable profile, no scripts executed on host)                |
|   ├── Passive detection rules: JavaScript miner/eval heuristics, homographs, form password leaks, TLS      |
|   └── Scoring algorithm: Explainable mathematical combination with Threat & Hygiene separation              |
+------------------------------------+------------------------------------+-----------------------------------+
                                     |                                    |
               +---------------------+--------------------+               |
               |                                          |               |
               v                                          v               v
+-----------------------------+            +-------------------+    +-----------------------------------------+
| PostgreSQL 16 (JSONB/ORM)   |            | Redis 7 Queue     |    | Dedicated Background Worker             |
|  - users, invitations       |            |  - Async batches  |    |  - Watchlist scheduler                  |
|  - scans, findings          |            |  - Cache          |    |  - Bulk batch processor                 |
|  - blocklist, allowlist     |            +-------------------+    +-----------------------------------------+
|  - watchlists, bulk_jobs    |
|  - audit_log, feedback      |
|  - api_tokens, chat_msgs    |
+-----------------------------+
```

---

## 2. Key Capabilities & Phases Completed

1. **Architecture & Modular Backend (FastAPI)**:
   - High-performance asynchronous API using FastAPI, SQLAlchemy 2.0 ORM, and Pydantic v2 schemas.
   - Centralized error handling and structured logging.
   - Interactive OpenAPI documentation available at `/docs` and `/redoc`.
   - Automatic database engine fallback to SQLite for zero-setup standalone local runs when PostgreSQL is offline.
2. **Accounts, Authentication & RBAC**:
   - Role-Based Access Control enforcing `admin` and `analyst` separation on all sensitive endpoints.
   - Secure password hashing using bcrypt.
   - Server-managed sessions using `HttpOnly`, `SameSite=Lax`, and `Secure` cookies.
   - Double-submit CSRF token enforcement (`X-CSRF-Token`) for state-changing requests.
   - Rate limiting and automatic temporary account lockout (after 5 failed attempts, 15-minute lockout).
   - Invitation-only registration flow with expiring, single-use cryptographic tokens.
   - Comprehensive audit logging (`audit_log`) recording actor, action, target, IP address, user agent, and payload.
3. **Database & Migrations**:
   - 13 normalized tables with foreign keys, indexes, and cascade deletion rules.
   - PostgreSQL JSONB columns for full browser evidence traces and structured findings.
   - Screenshot storage paths decoupled from database records.
   - Complete Alembic migration management (`alembic upgrade head`).
4. **URL Detonation & Strict SSRF Isolation**:
   - Headless disposable Chromium container with isolated user data directory.
   - `HostGuard` gatekeeper rejects private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.169.254`, IPv6 `::1` and `fc00::/7`).
   - `EgressProxy` prevents redirect hops and DNS rebinding attacks by resolving destination IPs and pinning sockets.
   - Downloaded executables and archives are hashed in-memory and immediately destroyed without execution.
   - Passive inspection fallback if the browser sandbox is unavailable.
5. **History, Differential Comparison & Reporting**:
   - Full-text and filterable scan history (search by domain, threat level, score, date range).
   - Differential comparison engine: compares two scans of the same URL/domain to compute threat delta, newly observed findings, resolved findings, and redirect chain modifications.
   - One-click report exports in both structured JSON and printable PDF format.
6. **Bulk Scanning & Recurring Watchlists**:
   - Bulk CSV upload with row limits (max 500 rows) and file size safeguards (5 MB).
   - Asynchronous batch processing queue with progress and error tracking.
   - Watchlists for continuous monitoring of suspicious targets on custom schedules (hourly, daily, weekly).
7. **Policy Management (Allowlist & Blocklist)**:
   - Strict precedence enforcement: **Blocklist strictly overrides Allowlist**. Targets matching the blocklist are immediately blocked and assigned a Critical score.
   - Normalization of domains and URL patterns.
8. **Analyst Feedback & Provenance**:
   - True Positive, False Positive, and Needs Review annotation buttons.
   - Provenance tracking with notes and audit logging to prepare ground-truth data for future ML model training.
9. **AI Threat Analyst Assistant & Scoped API Tokens**:
   - Conversational assistant answering questions about scan findings.
   - Grounded strictly in structured evidence (`llm_payload`) to eliminate prompt injection risks from untrusted web pages.
   - Scoped API tokens (`xdr_<hex>`) hashed with SHA-256 for secure external SIEM/SOAR/XDR integration.
10. **Rich Dark Cyber-Theme Frontend**:
    - Single-page application preserving the original color palette (`--bg:#0b0f17`, `--accent:#4dd4ac`, `--critical:#ff4d6d`).
    - Tabbed interface: Scanner, Dashboard, History, Compare, Bulk Scans, Watchlists, Policies, API Tokens, and Admin.

---

## 3. Quick Start with Docker Compose

To start the complete production-ready stack (FastAPI app, background worker, PostgreSQL 16, Redis 7, and Nginx proxy):

```bash
# 1. Copy environment configuration
cp .env.example .env

# 2. Build and launch all containers
docker compose up -d --build

# 3. Verify health
docker compose ps
```

The application will be accessible at:
- Web Application: **http://localhost** (or port 80 / 5000)
- OpenAPI Swagger UI: **http://localhost/docs**
- Health Check: **http://localhost/health**

### Initial Administrator Credentials:
- **Email:** `admin@xdr.local`
- **Password:** `AdminPass123!` (Configurable via `INITIAL_ADMIN_PASSWORD` in `.env`)

---

## 4. Local Development Setup (Without Docker)

### Prerequisites:
- Python 3.12 or 3.13
- Pip

### 1. Install Dependencies:
```bash
cd url-analyzer-web-app
pip install -r requirements.txt
python -m playwright install --with-deps chromium
```

### 2. Configure Environment:
```bash
cp .env.example .env
# By default, DB_FALLBACK_SQLITE=True will automatically use SQLite if PostgreSQL is not running.
```

### 3. Run Database Migrations:
```bash
alembic upgrade head
```

### 4. Start the Application:
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 5000 --reload
```
Open **http://127.0.0.1:5000** in your browser.

### 5. Start Background Worker (Optional for watchlists/bulk jobs):
```bash
python -m backend.worker
```

### 6. Run the Local Test Scam Page (Demo):
```bash
python demo_server.py
# In another terminal, run with ALLOW_PRIVATE=1 to test local targets:
ALLOW_PRIVATE=1 uvicorn backend.main:app --port 5000
```

---

## 5. Automated Testing

Run the full pytest automated test suite covering authentication, RBAC, SSRF, rules precedence, scans, differential comparison, bulk processing, and tokens:

```bash
pytest tests -v
```

To run individual test modules:
```bash
pytest tests/test_auth_security.py -v       # Auth, lockout, invitations, sessions
pytest tests/test_rbac.py -v                # Admin vs Analyst privilege boundaries
pytest tests/test_ssrf_validation.py -v     # SSRF gate and IP validation
pytest tests/test_rules_precedence.py -v    # Blocklist overrides allowlist
pytest tests/test_scans_comparison.py -v    # Scan execution & diff logic
pytest tests/test_bulk_watchlists.py -v     # CSV parsing & watchlists
pytest tests/test_api_tokens.py -v          # Scoped API token hashing & auth
```

---

## 6. Environment Variables Reference

| Variable | Description | Default |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+psycopg2://postgres:postgres@localhost:5432/url_analyzer` |
| `DB_FALLBACK_SQLITE` | Fallback to SQLite if PostgreSQL is offline | `True` |
| `SECRET_KEY` | Secret key for JWT session cookies (min 32 chars) | `change-this-in-production...` |
| `CSRF_SECRET` | Secret key for HMAC CSRF tokens | `csrf-token-secret...` |
| `COOKIE_SECURE` | Set `True` to require HTTPS for session cookies | `False` (Set `True` in prod) |
| `ALLOW_PRIVATE` | Allow local loopback/private IP targets (demo only!) | `0` |
| `WORKERS` | Max concurrent worker threads | `4` |
| `INITIAL_ADMIN_EMAIL` | Default admin email created on first run | `admin@xdr.local` |
| `INITIAL_ADMIN_PASSWORD` | Default admin password | `AdminPass123!` |
| `VT_API_KEY` | VirusTotal v3 API key (Optional) | `None` |
| `GSB_API_KEY` | Google Safe Browsing API key (Optional) | `None` |
| `GEMINI_API_KEY` | Google Gemini API key for AI assistant (Optional) | `None` |
| `OPENAI_API_KEY` | OpenAI API key for AI assistant (Optional) | `None` |

---

## 7. Security Hardening & Boundaries

- **SSRF Defenses:** Loopback (`127.0.0.0/8`), Link-Local (`169.254.0.0/16`), RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and Cloud Metadata endpoints are completely blocked. Egress proxy pins the connection to the verified IP, neutralizing DNS rebinding attacks.
- **XSS & Content Sanitization:** Untrusted evidence strings extracted from target pages are stripped of non-printable ASCII and rendered strictly via DOM `textContent` (never `innerHTML`).
- **Secret Hygiene:** Passwords are hashed with bcrypt. API tokens are stored as SHA-256 hashes and displayed only once.
- **Container Isolation:** Production containers run under an unprivileged user (`xdr`, UID 1001) with internal bridge networking.

---

## 8. Database Backup & Restore

### PostgreSQL Backup:
```bash
docker compose exec -t postgres pg_dump -U postgres url_analyzer > backup_$(date +%Y%m%d).sql
```

### PostgreSQL Restore:
```bash
cat backup_YYYYMMDD.sql | docker compose exec -T postgres psql -U postgres -d url_analyzer
```

### Storage Directory Backup:
```bash
tar -czvf storage_backup.tar.gz ./storage
```
