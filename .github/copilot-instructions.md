# NetSentinel — Copilot Instructions

**Status:** Pre-implementation — this repository currently contains only design documentation (NetSentinel_PRD.md). Implementation has not started.

---

## Project Overview

NetSentinel is a network security auditing tool that combines static code analysis with live multi-layer network probing. It scans a codebase and live host, scores findings with CVSS 3.1, maps to OWASP Top 10 2021, and presents results in a persistent browser dashboard.

**Core stack:** Python (scanning engine, CLI, dashboard server) + vanilla JavaScript (dashboard UI)

---

## Architecture

### Component Structure

Implementation follows a strict sequential dependency order — each component depends on the previous:

1. **CLI Entry Point** (`cli.py`)
   - Command: `netsentinel scan --target <repo> --host <ip> [options]`
   - Orchestrates the full pipeline
   - Auto-launches dashboard on completion
   - All flags parsed once into `ScanConfig` dataclass — no module reads `sys.argv` directly

2. **Static Analyzer** (`static_analyzer.py`)
   - Read-only file traversal — never executes code
   - Extracts attack surface from TypeScript/Python/Java codebases
   - Produces **Attack Surface Manifest** (JSON) with: ports, routes, secrets, TLS/DNS config
   - Each extractor (`extract_ports`, `extract_routes`, `extract_secrets`, etc.) is independent
   - GitHub URL support: clone to temp dir, analyze, cleanup

3. **Live Probing Engine** (modules 3A-3D)
   - Four probe modules run concurrently via `threading`
   - All findings written to thread-safe queue
   - Modules are fully independent — no shared state

4. **Scoring Engine** (`scoring_engine.py`)
   - Pure function: takes findings list, returns score object
   - Per-domain scores (0-100), weighted overall score, letter grade (A-F)
   - Penalty formula: critical=25, high=15, medium=8, low=3, info=0
   - Weighted score: `(network × 0.25) + (tls × 0.30) + (http × 0.25) + (dns × 0.20)`

5. **Persistent Dashboard** (`dashboard.html` + Python HTTP server)
   - Single HTML file — no npm, no build step, Chart.js bundled inline
   - All filtering/sorting client-side
   - Storage: `~/.netsentinel/index.json` and `~/.netsentinel/scans/<scan-id>.json`
   - Server endpoints: `/api/scans` (list), `/api/scans/<id>` (detail)

---

## Concurrency Model

**Critical distinction — two different models:**

1. **Port scanner (Module 3A only):** `asyncio`
   - Thousands of concurrent socket connects with short timeouts
   - Atomic unit: `async def scan_port(host, port) -> PortResult`
   - Orchestrator: `async def scan_all_ports(host, ports, concurrency=500)`
   - Banner grabber runs synchronously after async scan completes

2. **All other modules:** `threading`
   - Modules 3A, 3B, 3C, 3D each run in separate threads
   - Lower concurrency needs, simpler implementation
   - Subdomain enumeration (Module 3D) uses asyncio internally with concurrency=200

---

## Data Structures

### Finding Schema

Every finding (from static analysis or live probing) follows this structure:

```json
{
  "id": "<uuid>",
  "scan_id": "<uuid>",
  "domain": "network|tls|http|dns|static",
  "title": "Open port 23 (Telnet) detected",
  "description": "...",
  "severity": "critical|high|medium|low|info",
  "cvss_score": 9.1,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "cvss_breakdown": { ... },
  "owasp_category": "A05:2021 – Security Misconfiguration",
  "owasp_id": "A05",
  "evidence": { ... },
  "remediation": "...",
  "false_positive_risk": "low",
  "references": [...]
}
```

### Attack Surface Manifest

Output of static analyzer, input to live probing engine:

```json
{
  "scan_id": "<uuid>",
  "target": "github.com/user/repo",
  "extracted_at": "...",
  "language_detected": ["typescript", "python"],
  "ports": [{"port": 8080, "protocol": "tcp", "source_file": "...", "line": 12}],
  "routes": [{"method": "GET", "path": "/api/users", "source_file": "...", "line": 34}],
  "secrets_found": [{"type": "stripe_key", "file": "...", "line": 42, "preview": "sk_live_****"}],
  "tls_config": { ... },
  "dns_config": { ... }
}
```

---

## Module-Specific Conventions

### Module 3A — Network Probe

- **Dangerous port classification** (defined in `config.py`):
  - Port 23 (Telnet) → critical
  - Port 445 (SMB), 6379 (Redis), 27017 (MongoDB), 9200 (Elasticsearch) → critical
  - Port 21 (FTP), 25 (SMTP), 3389 (RDP), 5432/3306 (Postgres/MySQL public) → high
- **Banner grabber:** only runs on confirmed open ports
- **Manifest cross-check:** ports open but not in manifest → finding
- **ICMP host detection:** don't rely on ICMP alone — confirm with TCP probe to known-open port

### Module 3B — TLS/SSL Probe

- **Protocol checks:** make real socket connections per version — don't rely on headers
- Use Python `ssl` module with version pinning
- **Cipher enumeration:** offer each cipher individually and record accept/reject
- **Heartbleed check:** only run if TLS 1.0 or 1.1 confirmed supported
- **True negative test:** correctly configured TLS 1.3-only server with valid cert should produce zero findings

### Module 3C — HTTP Probe

- **Routes:** use manifest routes if available, else default list: `/`, `/api`, `/admin`, `/health`, `/.env`, `/.git/config`, etc.
- **CORS test:** exactly three requests per route (arbitrary origin, credentialed cross-origin, null origin)
- **XSS/SQLi checks:** GET-only, passive — no state-modifying requests
- **User-Agent:** all requests include `User-Agent: NetSentinel-Scanner/1.0`
- **Sensitive paths:** `/.env`, `/.git/config`, `/wp-config.php`, `/server-status`

### Module 3D — DNS Probe

- **Zone transfer:** attempt AXFR to every NS record, not just the first
- **SPF strictness:** `+all` → critical, `~all` → low, missing → medium
- **DMARC:** missing → medium, `p=none` → low
- **DKIM selectors:** check `default._domainkey`, `google._domainkey`, `mail._domainkey`
- **Subdomain enumeration:** 1000-entry wordlist, asyncio with concurrency=200
- **Open resolver:** send recursive query for external domain to target's nameservers

---

## OWASP Top 10 2021 Mapping

Every finding must have an `owasp_id` field. Use this mapping:

| OWASP ID | Category | Typical modules |
|----------|----------|-----------------|
| A01 | Broken Access Control | HTTP (CORS, sensitive paths) |
| A02 | Cryptographic Failures | TLS (weak ciphers, cert issues, no HSTS) |
| A03 | Injection | HTTP (XSS reflection, SQLi indicators) |
| A04 | Insecure Design | Static (missing auth hints on routes) |
| A05 | Security Misconfiguration | Network (dangerous ports), HTTP (headers), DNS (zone transfer) |
| A06 | Vulnerable and Outdated Components | Network (banner version disclosure) |
| A07 | Identification & Auth Failures | Network (Telnet, FTP, RDP exposed) |
| A08 | Software & Data Integrity Failures | Static (secrets in code, `rejectUnauthorized: false`) |
| A09 | Security Logging & Monitoring | HTTP (error pages, stack traces) |
| A10 | Server-Side Request Forgery | HTTP (sensitive internal paths exposed) |

---

## Testing Strategy

### Negative Test Targets (should catch vulnerabilities)

- **OpenClaw** (Docker container) — all modules, expect F grade
- **Metasploitable3** (local VM) — network/TLS/HTTP, expect D–F grade
- **DVWA** (Docker or demo.dvwa.co.uk) — HTTP layer, expect D grade

### Positive Test Targets (should score well)

- **Caddy** (caddyserver.com) — TLS module, expect A on TLS
- **Fastify demo** — HTTP module, expect A–B on HTTP

### Cross-Validation

Before trusting your output, validate against:

- **TLS Probe** ← `testssl.sh` on badssl.com subdomains
- **Network Probe** ← `nmap` top-1000 scan (compare open port lists)
- **DNS Probe** ← `dnsrecon` (zone transfer, record enumeration)
- **HTTP Probe** ← `securityheaders.com` (compare header findings)

---

## Configuration and Constants

All magic numbers, port classifications, OWASP mappings, scoring weights, and wordlists live in `config.py`. No module hardcodes these values.

**Scoring weights:**
```python
DOMAIN_WEIGHTS = {
    'network': 0.25,
    'tls': 0.30,
    'http': 0.25,
    'dns': 0.20
}
```

**Severity penalties:**
```python
SEVERITY_PENALTIES = {
    'critical': 25,
    'high': 15,
    'medium': 8,
    'low': 3,
    'info': 0
}
```

---

## File Storage

```
~/.netsentinel/
  index.json              ← metadata for all scans (id, target, host, date, grade)
  scans/
    <scan-id>.json        ← full scan result per run
```

- Scan ID format: UUID4
- `index.json` is append-only (except for deletion)
- All files written atomically (write to temp, rename)

---

## Static Analysis Language Support

**Priority order:** TypeScript/JavaScript → Python → Java

### TypeScript/JavaScript

- **Routes:** `app.get('/path')`, `router.post('/path')`, Next.js `pages/api/` and `app/api/`
- **Env vars:** `process.env.PORT`, `.env` file parsing
- **Secrets:** AWS keys (`AKIA...`), Stripe keys (`sk_live_...`), GitHub tokens (`ghp_...`)

### Python

- **Routes:** `@app.route('/path')` (Flask), `@app.get('/path')` (FastAPI), Django URL patterns
- **Env vars:** `os.environ`, `.env` files
- **TLS hints:** `ssl.PROTOCOL_TLSv1` (deprecated), `ssl.OP_NO_TLSv1_3` (bad)

### Java

- **Routes:** `@RequestMapping('/path')`, `@GetMapping('/path')` (Spring)
- **Config:** `application.properties`, `application.yml`
- **Secrets:** JDBC connection strings with embedded passwords

---

## Performance Targets

- **Static analysis:** < 30 seconds for repos up to 100k lines
- **Port scan (top 1000):** < 60 seconds with asyncio concurrency=500
- **Dashboard load:** < 2 seconds on localhost
- **Subdomain enumeration:** asyncio concurrency=200 (adjust based on rate limiting)

---

## Dashboard Implementation

- **Single file:** `dashboard.html` — no npm, no build step
- **Chart library:** Chart.js bundled inline (no CDN calls)
- **Client-side only:** all filtering, sorting, tab switching in vanilla JS
- **CVSS rendering:** parse vector string client-side, render as labeled metric breakdown
- **Auto-open:** use `webbrowser.open()` (cross-platform)

---

## Security and Ethics

**CRITICAL — Legal Boundaries:**

- **No auth probing:** no brute force, credential stuffing, session hijacking
- **Target restrictions:** staging/sandboxed/vulnerable-by-design targets only — never production
- **Passive checks only for XSS/SQLi:** GET requests, no state modification
- **User-Agent disclosure:** always include `User-Agent: NetSentinel-Scanner/1.0`

If implementing auth checks in future versions, require explicit `--auth-probe` flag with legal disclaimer.

---

## Current State

**No implementation exists yet.** When beginning implementation:

1. Start with Component 1 (CLI) — establish the entry point and config dataclass
2. Build Component 2 (Static Analyzer) — get manifest structure working
3. Implement Component 3 modules in parallel (they are independent)
4. Add Component 4 (Scoring) — pure function, easy to test
5. Finish with Component 5 (Dashboard) — visual layer

**Do not build out of order.** Each component depends on the previous.
