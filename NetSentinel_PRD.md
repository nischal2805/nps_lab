# NetSentinel — Product Requirements Document

**Version:** 0.2 (Decisions Locked)
**Status:** Pre-implementation — ready to move to architecture and file structure
**Last Updated:** 2026-03-26

---

## 1. Problem Statement

Security auditing for network-facing applications is either too late (quarterly audits), too manual (Burp Suite requires a human operator), or too fragmented (Snyk does deps, Wiz does cloud, nothing does everything together). For a developer or lab engineer who wants to understand the actual security posture of a running application — from the network layer up — there is no single tool that scans, scores, maps to standards, and explains findings in one workflow.

NetSentinel solves this by combining static attack surface extraction from source code with live multi-layer network probing, scoring every finding with CVSS 3.1, mapping to OWASP Top 10, and presenting everything in a persistent interactive browser dashboard that accumulates results across runs.

---

## 2. Goals

- Point the tool at a codebase (local directory or GitHub repo URL) and a live host, get a complete security audit in one command.
- Cover four network domains: Network/Transport (ports, services, ICMP), TLS/SSL, HTTP application layer, DNS.
- Score every finding with CVSS 3.1 base score.
- Map every finding to an OWASP Top 10 2021 category.
- Produce per-domain scores (0–100) and an overall A–F grade.
- Open an interactive browser dashboard automatically after scan completes.
- Persist scan history across runs — dashboard shows all past scans, not just the latest.
- Support side-by-side comparison across multiple targets for the demo/showpiece.

---

## 3. Non-Goals

- No auth probing (brute force, credential stuffing, session hijacking) — legal risk on real targets.
- No production environment scanning — staging/sandboxed/vulnerable-by-design targets only.
- No autonomous patch generation or PR creation in v1.
- No cloud infrastructure scanning (AWS, GCP, Azure posture).
- No agent-based deployment inside target infrastructure.
- No C/C++ implementation — Python core for speed of development and library availability.

---

## 4. Users / Personas

**Primary — Lab/Course Evaluator**
Wants to see a tool that works convincingly on a live target, produces a credible-looking scored report, and demonstrates real network programming concepts (raw sockets, TLS handshake inspection, DNS queries, HTTP probing). Cares about impressiveness of output over internal elegance.

**Secondary — Developer running self-audit**
Points tool at their own repo + staging server to understand what is exposed before deployment. Wants actionable findings with remediation guidance, not just a score.

---

## 5. Decisions Log

All open questions from v0.1 are now resolved.

| Decision | Choice | Rationale |
|---|---|---|
| Language | Python core, vanilla JS dashboard | Best network library support, fastest path to working tool |
| Concurrency model (port scanner) | asyncio | Thousands of concurrent socket connects with low memory overhead — threads hit OS limits fast |
| Concurrency model (other modules) | threading | Lower concurrency needs, simpler implementation |
| Static analysis targets | TypeScript, Python, Java primary | Production-dominant languages, covers Express/FastAPI/Spring route patterns |
| Dashboard persistence | Across runs — full scan history | More useful for comparison, better demo story |
| Dashboard server | Local Python HTTP server | Self-contained, no external deps |
| Test harness | Metasploitable3 + DVWA + BadSSL (existing) | Building from scratch is unnecessary, these are industry-standard targets |
| Negative test case 1 | OpenClaw | Intentionally misconfigured, exercises all modules |
| Negative test case 2 | Metasploitable3 | Network + TLS + HTTP coverage |
| Negative test case 3 | DVWA | HTTP layer specifically |
| Positive test case 1 | Caddy (`caddyserver.com`) | Best-in-class TLS, should score A on TLS module |
| Positive test case 2 | Fastify demo deployment | Security-conscious HTTP defaults, good HTTP module positive |

---

## 6. System Components

Five components. Implementation order is strictly sequential — each component depends on the previous.

---

### Component 1 — CLI Entry Point (`netsentinel`)

**What it does:**
Single command invocation. Accepts a target codebase (local path or GitHub URL) and a live host. Orchestrates the full pipeline. On completion, launches the dashboard and opens the browser automatically.

**CLI interface:**
```
netsentinel scan --target <github-url-or-local-path> --host <ip-or-domain> [--port <port>]
netsentinel scan --host <ip-or-domain> --live-only
netsentinel scan --target <path> --static-only
netsentinel report --last
netsentinel report --scan-id <id>
netsentinel compare <scan-id-1> <scan-id-2>
netsentinel list
```

**Flag definitions:**
- `--target` — local path or GitHub HTTPS URL to the codebase. Optional if `--live-only`.
- `--host` — IP address or domain of the live target. Optional if `--static-only`.
- `--port` — specific port to focus probing on. Defaults to standard port range.
- `--live-only` — skip static analysis, probe live host directly.
- `--static-only` — skip live probing, only produce Attack Surface Manifest.
- `report --last` — re-open dashboard to the most recent scan.
- `report --scan-id` — re-open dashboard to a specific past scan.
- `compare` — open dashboard directly to the Compare tab for two scan IDs.
- `list` — print all past scan IDs with target, host, date, and overall grade.

**Acceptance criteria:**
- Accepts `--target` and `--host` independently or together.
- Validates all inputs before starting (host reachable via ping, path exists or GitHub URL returns 200, port in valid range).
- Prints real-time progress to stdout: which phase is running, which module, findings count so far.
- On completion, writes scan result to `~/.netsentinel/scans/<scan-id>.json` and opens dashboard.
- Exits with code 0 on clean run, non-zero with descriptive error on failure.
- All scan metadata (scan ID, target, host, timestamp, duration, grade) written to `~/.netsentinel/index.json` for persistence.

**Copilot context note:** Each subcommand (`scan`, `report`, `compare`, `list`) is its own handler function in `cli.py`. Flags are parsed once at entry and passed as a `ScanConfig` dataclass to all downstream modules. No module reads `sys.argv` directly.

---

### Component 2 — Static Analyzer

**What it does:**
Reads the source codebase (cloned from GitHub or local path) and extracts the attack surface without executing any code. Produces a structured **Attack Surface Manifest** — the primary input to the Live Probing Engine.

**Language support (priority order):**
- TypeScript / JavaScript — Express routes (`app.get`, `router.post`), Next.js API routes, environment variable usage
- Python — Flask/FastAPI/Django route decorators, `os.environ`, hardcoded connection strings
- Java — Spring `@RequestMapping`, `@GetMapping`, `application.properties`, `application.yml`

**What it extracts:**

Ports and protocols:
- `EXPOSE` directives in Dockerfiles
- `ports:` mappings in `docker-compose.yml`
- Port numbers in `.env`, `application.properties`, `config.yml`, `config.json`
- Socket bind calls in source (`listen(8080)`, `app.listen(process.env.PORT)`)

HTTP routes:
- Express: `app.get('/path')`, `router.post('/path')`
- FastAPI: `@app.get('/path')`, `@router.post('/path')`
- Flask: `@app.route('/path', methods=['GET'])`
- Spring: `@RequestMapping('/path')`, `@GetMapping('/path')`
- Next.js: files under `pages/api/` and `app/api/`

Secrets and credentials:
- Regex patterns for: AWS keys (`AKIA...`), Stripe keys (`sk_live_...`), GitHub tokens (`ghp_...`), generic `password =`, `secret =`, `api_key =` assignments
- `.env` files with non-placeholder values
- Git history secret scan (last 50 commits, configurable)

TLS configuration hints:
- Which TLS version is configured in server setup files
- Whether cert pinning is referenced
- Whether `rejectUnauthorized: false` or equivalent is set (disables cert verification)

DNS configuration:
- Custom resolver addresses
- Hardcoded IP addresses that should be domain names
- Internal hostnames referenced in config

**Output — Attack Surface Manifest (JSON):**
```json
{
  "scan_id": "<uuid>",
  "target": "github.com/user/repo",
  "extracted_at": "2026-03-26T10:00:00Z",
  "language_detected": ["typescript", "python"],
  "ports": [
    {"port": 8080, "protocol": "tcp", "source_file": "docker-compose.yml", "line": 12, "service_hint": "http"}
  ],
  "routes": [
    {"method": "GET", "path": "/api/users", "source_file": "src/routes/users.ts", "line": 34, "auth_hint": "none"}
  ],
  "outbound_hosts": [
    {"host": "api.stripe.com", "source_file": "src/payments.ts", "line": 8}
  ],
  "secrets_found": [
    {"type": "stripe_key", "file": "src/config.ts", "line": 42, "preview": "sk_live_****", "severity": "critical"}
  ],
  "tls_config": {
    "version_hint": "TLS1.2",
    "cert_verification_disabled": false,
    "cert_pinning": false
  },
  "dns_config": {
    "custom_resolver": false,
    "hardcoded_entries": []
  }
}
```

**Acceptance criteria:**
- Handles TypeScript, Python, Java codebases. Gracefully skips unsupported file types.
- Never executes any code in the target — read-only file traversal only.
- Produces valid Attack Surface Manifest JSON even if some extractors find nothing.
- Secret findings include file path, line number, type, and redacted preview.
- Completes in under 30 seconds for repos up to 100k lines.
- GitHub URL support: clones to a temp directory, runs analysis, cleans up on completion.

**Copilot context note:** Each extractor (`extract_ports`, `extract_routes`, `extract_secrets`, `extract_tls_config`, `extract_dns_config`) is a separate function in `static_analyzer.py`. They each receive the same file tree iterator and return their section of the manifest. The manifest is assembled by the coordinator after all extractors run. No extractor calls another.

---

### Component 3 — Live Probing Engine

**What it does:**
Takes the Attack Surface Manifest (or a bare host/port if running in `--live-only` mode) and executes four probe modules concurrently against the live host. Each module is fully independent. All findings are emitted as structured `Finding` objects.

**Execution model:**
- Modules 3A, 3B, 3C, 3D run concurrently using `threading` (one thread per module).
- Within Module 3A (port scanner), concurrency is `asyncio` — thousands of socket connects simultaneously.
- All modules write findings to a shared thread-safe findings queue.
- The orchestrator collects from the queue after all threads complete.

**Finding schema:**
```json
{
  "id": "<uuid>",
  "scan_id": "<uuid>",
  "domain": "network|tls|http|dns|static",
  "title": "Open port 23 (Telnet) detected",
  "description": "Telnet transmits all data including credentials in plaintext. Any network observer can intercept login sessions.",
  "severity": "critical|high|medium|low|info",
  "cvss_score": 9.1,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "cvss_breakdown": {
    "attack_vector": "Network",
    "attack_complexity": "Low",
    "privileges_required": "None",
    "user_interaction": "None",
    "scope": "Unchanged",
    "confidentiality": "High",
    "integrity": "High",
    "availability": "None"
  },
  "owasp_category": "A05:2021 – Security Misconfiguration",
  "owasp_id": "A05",
  "evidence": {
    "raw_request": "TCP SYN to 192.168.1.1:23",
    "raw_response": "SYN-ACK received — port open",
    "banner": "Linux telnetd"
  },
  "remediation": "Disable the Telnet service immediately. Replace with SSH using key-based authentication.",
  "false_positive_risk": "low",
  "references": ["https://cwe.mitre.org/data/definitions/23.html"]
}
```

---

#### Module 3A — Network Probe (Layer 3/4)

**What it does:**
Port scanning, service fingerprinting, ICMP probing. The broadest and noisiest module.

**Concurrency: asyncio** — port scanner opens thousands of connections simultaneously with short timeouts.

**Checks:**

TCP port scan:
- Scan top 1000 ports by default (Nmap top-1000 list). Configurable via `--port`.
- Concurrent async socket connects with 1-second timeout per port.
- Mark each port: open, closed, or filtered (timeout = filtered, refused = closed).

UDP scan (targeted, not full range):
- Port 53 (DNS) — open UDP resolver is an amplification risk
- Port 161 (SNMP) — unauthenticated SNMP is a critical exposure
- Port 123 (NTP) — open NTP can be used in amplification attacks
- Port 500 (IKE/IPSec) — unexpected VPN endpoint

ICMP:
- Send ICMP echo request. Classify: host up, host down, ICMP filtered.
- Extract TTL for OS fingerprinting hint (TTL ~64 = Linux, ~128 = Windows, ~255 = network device).

Banner grabbing (on confirmed open TCP ports only):
- Send a generic probe, capture first 1024 bytes of response.
- Parse banner for service name and version string.
- Services with known banner formats: HTTP, FTP, SMTP, SSH, Telnet, POP3, IMAP, MySQL, Redis, MongoDB.

Dangerous port classification:
- Port 21 (FTP) → high
- Port 23 (Telnet) → critical
- Port 25 (SMTP open relay) → high
- Port 445 (SMB) → critical
- Port 3389 (RDP) → high
- Port 6379 (Redis) → critical
- Port 27017 (MongoDB) → critical
- Port 9200 (Elasticsearch) → critical
- Port 5432, 3306 (Postgres, MySQL) exposed publicly → high

Manifest cross-check:
- Ports open on live host but not declared in manifest → Finding: "Undeclared open port detected."
- Ports in manifest but not open → informational note only.

**Acceptance criteria:**
- Top-1000 TCP scan completes in under 60 seconds with asyncio concurrency of 500 simultaneous connects.
- Each dangerous open port produces a Finding with severity per classification above.
- Banner grab runs only on confirmed open ports. Banner attached to Finding as evidence.
- ICMP correctly distinguishes host-down from ICMP-filtered by sending a TCP probe to a known-open port to confirm host is alive.

**Copilot context note:** `async def scan_port(host, port)` is the atomic unit — returns `PortResult(port, status, banner)`. `async def scan_all_ports(host, ports, concurrency)` runs them with a semaphore. Banner grabber is `def grab_banner(host, port) -> str` — synchronous, called only on open ports after async scan completes. Dangerous port classifier is a dict lookup in `config.py`.

---

#### Module 3B — TLS/SSL Probe (Layer 4/5)

**What it does:**
Inspects TLS configuration by actually completing handshakes with various protocol versions and cipher preferences. Does not rely on headers — makes real socket connections.

**Checks:**

Protocol version support:
- Attempt TLS 1.3 handshake → expected to succeed on modern servers
- Attempt TLS 1.2 handshake → acceptable, note it
- Attempt TLS 1.1 handshake → deprecated (RFC 8996), medium finding
- Attempt TLS 1.0 handshake → deprecated (RFC 8996), high finding
- Attempt SSLv3 handshake → broken (POODLE), critical finding

Cipher suite enumeration:
- For each supported TLS version, enumerate accepted ciphers by offering one at a time
- Flag weak ciphers: RC4, DES, 3DES, NULL, EXPORT, ANON cipher suites
- Flag missing forward secrecy: RSA key exchange without ECDHE/DHE → high finding

Certificate inspection:
- Expiry: expired → critical, within 30 days → high, within 90 days → medium
- Self-signed → high finding
- Hostname mismatch → critical finding
- Weak public key: RSA < 2048 bits → high
- Certificate validity period > 398 days → low finding
- Missing intermediate in chain → medium finding

HSTS:
- `Strict-Transport-Security` header missing → medium finding
- `max-age` < 31536000 (1 year) → low finding
- Missing `includeSubDomains` → low finding

Perfect Forward Secrecy:
- RSA-only key exchange (no ECDHE/DHE) → high finding

Heartbleed (CVE-2014-0160):
- Send malformed heartbeat to TLS 1.0/1.1 endpoints
- Memory leak in response → critical finding with evidence

**Acceptance criteria:**
- Protocol version checks work by actually completing (or failing) a handshake with each version using Python `ssl` module with version pinning.
- Cipher enumeration offers each cipher individually and records server accept/reject.
- Certificate parsing extracts: CN, SANs, issuer, expiry, public key type and size.
- Heartbleed check only runs if TLS 1.0 or 1.1 is confirmed supported.
- True negative: a correctly configured TLS 1.3-only server with valid cert produces zero findings.

**Copilot context note:** Each check is a separate function: `check_protocol_version(host, port, version)`, `enumerate_cipher_suites(host, port, version)`, `inspect_certificate(host, port)`, `check_hsts(host)`, `check_heartbleed(host, port)`. All make independent socket connections. No shared state between checks.

---

#### Module 3C — HTTP Probe (Layer 7)

**What it does:**
Sends HTTP/HTTPS requests to the target and analyzes responses for security header gaps, CORS misconfigurations, information leakage, and basic injection surface detection. Uses routes from the Attack Surface Manifest if available; falls back to a default route list otherwise.

**Default routes (used when no manifest):**
`/`, `/api`, `/api/v1`, `/admin`, `/health`, `/login`, `/graphql`, `/swagger`, `/docs`, `/.env`, `/.git/config`

**Checks:**

Security headers (checked per route):
- `Content-Security-Policy` — missing → medium; `default-src *` → medium
- `X-Frame-Options` — missing → medium
- `X-Content-Type-Options: nosniff` — missing → low
- `Referrer-Policy` — missing → low; `unsafe-url` → medium
- `Permissions-Policy` — missing → info
- `Strict-Transport-Security` — missing on HTTPS → medium
- `Cache-Control` on authenticated routes — missing → low

CORS misconfiguration (three test cases per route):
- Reflect arbitrary origin: `Origin: https://evil.com` → if reflected back → high
- Credentialed cross-origin: above + `Access-Control-Allow-Credentials: true` → critical
- Null origin: `Origin: null` → if reflected → high

Information leakage:
- `Server:` header with version string → low finding
- `X-Powered-By:` present → low finding
- `/.env` returns 200 → critical
- `/.git/config` returns 200 → critical
- Error pages leaking stack traces → medium

HTTP methods:
- `TRACE` enabled → medium
- `PUT`/`DELETE` on non-API routes → medium

Basic XSS surface detection (passive — GET only, no state changes):
- Inject `<script>netsentinel</script>` into query parameters
- If reflected unescaped in response body → high finding

Basic SQLi surface detection (passive):
- Append `'` and `"` to query parameter values
- If response contains database error strings → high finding

**Acceptance criteria:**
- Probes all routes from manifest if available; falls back to default list.
- CORS test sends exactly three requests per route.
- Sensitive path check covers: `/.env`, `/.git/config`, `/wp-config.php`, `/config.php`, `/server-status`.
- XSS and SQLi checks are GET-only, no state-modifying requests.
- All HTTP requests include `User-Agent: NetSentinel-Scanner/1.0`.
- True negative: correctly hardened server returns zero header findings.

**Copilot context note:** `check_security_headers(response)` takes an `httpx.Response` and returns a list of Findings. `check_cors(session, url)` makes three requests and returns findings. `check_sensitive_paths(host)` iterates the path list. `check_xss_reflection(session, url, params)` and `check_sqli_errors(session, url, params)` are separate functions. All return findings — caller assembles them.

---

#### Module 3D — DNS Probe

**What it does:**
Probes DNS configuration of the target domain for misconfigurations, information leakage, and email security gaps. Uses `dnspython` for all queries.

**Checks:**

Zone transfer (AXFR):
- Query SOA record to find authoritative nameservers
- Attempt AXFR to each nameserver
- Successful transfer → critical finding with full zone data as evidence

Record enumeration:
- Query A, AAAA, MX, NS, TXT, CNAME, SOA records — informational, included in manifest
- MX records pointing to non-existent hosts → medium finding

Email security:
- SPF: missing → medium; `~all` instead of `-all` → low; `+all` → critical
- DMARC (`_dmarc.<domain>`): missing → medium; `p=none` → low
- DKIM: check common selectors (`default._domainkey`, `google._domainkey`, `mail._domainkey`) — none found → medium

Subdomain enumeration:
- 1000-entry wordlist of common subdomains
- Concurrent DNS queries with asyncio (200 simultaneous)
- Resolved subdomains listed as informational
- Subdomains resolving to internal RFC1918 addresses → high finding

Open resolver check:
- Send recursive query for external domain to target's nameservers
- If external query resolves → high finding (DNS amplification risk)

**Acceptance criteria:**
- Zone transfer attempted to every NS record found, not just the first.
- SPF, DMARC, DKIM checks parse raw TXT record content and evaluate policy strictness.
- Subdomain enumeration runs with asyncio concurrency of 200 simultaneous queries.
- Open resolver check sends query for a known external domain and checks for a real answer.
- Findings include raw DNS record as evidence.

**Copilot context note:** `attempt_zone_transfer(domain, nameservers)` tries AXFR per NS. `check_spf(domain)`, `check_dmarc(domain)`, `check_dkim(domain, selectors)` are independent functions each returning a Finding or None. `enumerate_subdomains(domain, wordlist)` uses asyncio. `check_open_resolver(nameservers)` sends a query for a known external domain to each NS.

---

### Component 4 — Scoring Engine

**What it does:**
Takes the complete list of Finding objects from both static analysis and all live probe modules. Computes per-domain scores, an overall weighted grade, OWASP Top 10 coverage, and CVSS summary statistics. Deterministic — same findings always produce the same score.

**Per-domain score formula:**
```
domain_score = max(0, 100 - sum(penalty for each finding in domain))

Penalty by severity:
  critical  → 25 points
  high      → 15 points
  medium    →  8 points
  low       →  3 points
  info      →  0 points

Floor at 0. Domain score cannot go negative.
Multiple findings of the same type are each penalised independently.
```

**Overall weighted score:**
```
weighted_score = (network × 0.25) + (tls × 0.30) + (http × 0.25) + (dns × 0.20)
```

**Letter grade:**
```
A  →  90–100
B  →  75–89
C  →  60–74
D  →  45–59
F  →  0–44
```

**OWASP Top 10 2021 mapping:**

| OWASP ID | Category | Primary modules |
|---|---|---|
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

**Score output (appended to scan JSON):**
```json
{
  "scores": {
    "network": 60,
    "tls": 85,
    "http": 45,
    "dns": 70,
    "weighted_overall": 65.25,
    "grade": "C"
  },
  "owasp_coverage": {
    "A01": {"status": "fail", "finding_count": 2},
    "A02": {"status": "pass", "finding_count": 0},
    "A05": {"status": "fail", "finding_count": 4}
  },
  "summary": {
    "total_findings": 10,
    "by_severity": {"critical": 1, "high": 3, "medium": 4, "low": 2, "info": 0},
    "highest_cvss": 9.1,
    "highest_cvss_finding": "Open port 23 (Telnet) detected"
  }
}
```

**Acceptance criteria:**
- Score is fully deterministic — identical finding lists always produce identical scores.
- Every finding has an `owasp_id` field before entering the scoring engine.
- Per-domain scores, weighted overall, and letter grade all present in output.
- OWASP coverage correctly distinguishes pass / fail / untested.
- Score computation is a pure function — takes findings list, returns score object, no side effects.

**Copilot context note:** `compute_domain_score(findings, domain)` is the atomic unit. `compute_overall_score(domain_scores, weights)` applies the weighted formula. `compute_owasp_coverage(findings)` groups findings by `owasp_id`. `generate_score_report(findings)` calls all three and returns the complete score object. All weights and OWASP mappings live in `config.py`.

---

### Component 5 — Persistent Dashboard

**What it does:**
A local Python HTTP server spun up on scan completion. Serves a single-page interactive dashboard. Browser opens automatically. Scan history persists across sessions.

**Storage:**
```
~/.netsentinel/
  index.json              ← metadata for all scans (id, target, host, date, grade)
  scans/
    <scan-id>.json        ← full scan result per run
```

**Dashboard tabs:**

Overview tab:
- Large prominent letter grade + weighted score.
- Four domain score bars — color-coded: green ≥80, yellow 60–79, red <60.
- OWASP Top 10 2021 grid — 10 tiles, each green (pass), red (fail), or grey (untested).
- Findings donut chart by severity.
- Scan metadata strip: target, host, date, total duration.

Findings tab:
- Sortable, filterable table of all findings.
- Filter by domain, severity, OWASP category. Sort by CVSS score (default), severity, domain.
- Row click → side drawer with: full description, CVSS visual breakdown, OWASP badge, raw evidence, remediation, external references.

History tab:
- Table of all past scans: scan ID, target, host, date, grade, total findings.
- Click any row → loads that scan's Overview and Findings.
- Delete button per row — removes JSON file and index entry.

Compare tab:
- Select two or more scans from history.
- Side-by-side domain score bars with delta indicators (▲ improved / ▼ degraded / — unchanged).
- Finding count comparison by severity.
- This is the primary demo view for the GitHub repo rating showpiece.

**Acceptance criteria:**
- Dashboard loads in under 2 seconds on localhost.
- All filtering, sorting, and tab switching is client-side — no server roundtrips after initial load.
- CVSS vector string parsed client-side and rendered as labeled metric breakdown.
- History persists correctly across sessions.
- Deleting a scan removes both JSON file and index entry.
- Dashboard is single `dashboard.html` — no npm, no build step, Chart.js bundled inline, no CDN calls.
- Auto-opens in default browser via `webbrowser.open()` (cross-platform).

**Copilot context note:** Single `dashboard.html` served by minimal Python `http.server`. Server endpoint `/api/scans` reads from `index.json`. `/api/scans/<id>` returns full scan JSON. All rendering is vanilla JS. Chart.js for donut chart and score bars only.

---

## 7. Data Flow

```
netsentinel scan --target <repo> --host <host>
        │
        ├─── Input validation (host reachable, repo accessible)
        │
        ▼
┌─────────────────────┐
│   Static Analyzer   │  reads codebase — never executes code
│                     │
│  extract_ports()          ──┐
│  extract_routes()            │
│  extract_secrets()           ├──► Attack Surface Manifest (JSON)
│  extract_tls_config()        │
│  extract_dns_config()   ────┘
└──────────┬──────────┘
           │  manifest passed to live engine
           ▼
┌──────────────────────────────────────────────────┐
│              Live Probing Engine                 │
│  (modules run concurrently via threading)        │
│                                                  │
│  Thread 1: Module 3A — Network Probe             │
│    └── asyncio port scanner (500 concurrent)     │
│    └── banner grabber                            │
│    └── ICMP probe                                │
│                                                  │
│  Thread 2: Module 3B — TLS Probe                 │
│    └── protocol version checks                   │
│    └── cipher enumeration                        │
│    └── certificate inspection                    │
│                                                  │
│  Thread 3: Module 3C — HTTP Probe                │
│    └── security header checks                    │
│    └── CORS tests                                │
│    └── sensitive path checks                     │
│    └── XSS/SQLi surface detection                │
│                                                  │
│  Thread 4: Module 3D — DNS Probe                 │
│    └── zone transfer attempt                     │
│    └── SPF/DMARC/DKIM checks                     │
│    └── subdomain enumeration (asyncio)           │
│    └── open resolver check                       │
│                                                  │
│  All findings → thread-safe queue                │
└──────────────────────┬───────────────────────────┘
                       │  findings list
                       ▼
             ┌──────────────────┐
             │  Scoring Engine  │
             │                  │
             │  domain scores   │
             │  overall grade   │
             │  OWASP coverage  │
             │  CVSS summary    │
             └────────┬─────────┘
                      │
                      ▼
           ┌────────────────────────┐
           │  Scan Result (JSON)    │
           │  ~/.netsentinel/scans/ │
           │  <scan-id>.json        │
           │  index.json updated    │
           └──────────┬─────────────┘
                      │
                      ▼
          ┌─────────────────────────┐
          │   Dashboard Server      │
          │   localhost:8742        │
          │   webbrowser.open()     │
          └─────────────────────────┘
```

---

## 8. Test Strategy

### 8.1 Negative test targets (tool should catch real things)

| Target | Setup | Primary modules validated | Expected grade |
|---|---|---|---|
| **OpenClaw** | Docker container | All modules | F |
| **Metasploitable3** | Local VM via Vagrant | Network (open ports), TLS (weak config), HTTP (missing headers) | D–F |
| **DVWA** | Docker / `demo.dvwa.co.uk` | HTTP (XSS/SQLi surface, CORS, headers) | D |

### 8.2 Positive test targets (tool should give good grades)

| Target | Live URL | Primary modules validated | Expected grade |
|---|---|---|---|
| **Caddy** | `caddyserver.com` | TLS (automatic modern TLS, HSTS, PFS) | A on TLS |
| **Fastify** | Fastify demo deployment | HTTP (helmet defaults, no version disclosure) | A–B on HTTP |

### 8.3 Cross-validation baseline

Before trusting your tool's output, cross-validate against known-good tools on the same targets:

| Your module | Cross-validate against | Method |
|---|---|---|
| TLS Probe | `testssl.sh` | Run both against `badssl.com` subdomains, compare findings |
| Network Probe | `nmap` top-1000 scan | Compare open port lists |
| DNS Probe | `dnsrecon` | Compare zone transfer and record enumeration results |
| HTTP Probe | `securityheaders.com` | Compare header findings |

### 8.4 BadSSL TLS test matrix

| BadSSL subdomain | Expected finding | Severity |
|---|---|---|
| `expired.badssl.com` | Certificate expired | Critical |
| `wrong.host.badssl.com` | Hostname mismatch | Critical |
| `self-signed.badssl.com` | Self-signed certificate | High |
| `untrusted-root.badssl.com` | Untrusted root CA | High |
| `rc4.badssl.com` | RC4 cipher suite accepted | High |
| `tls1.badssl.com` | TLS 1.0 accepted | High |
| `tls1-1.badssl.com` | TLS 1.1 accepted | Medium |
| `sha256.badssl.com` | No findings (true negative) | — |
| `mozilla-modern.badssl.com` | No findings (true negative) | — |

### 8.5 Per-module unit test cases

**Module 3A — Network Probe:**
- Port 23 open → Finding severity `critical`, title contains "Telnet"
- Port 6379 open → Finding severity `critical`, title contains "Redis"
- Port 443 open → no Finding (expected)
- Port 9999 closed → no Finding
- ICMP blocked but host alive (confirmed via TCP) → info Finding, not false positive critical

**Module 3B — TLS Probe:**
- All BadSSL subdomains per table above
- TLS 1.3 only server → zero protocol findings
- ECDHE cipher preferred → no PFS finding
- Certificate valid, matching hostname, < 398 days → zero cert findings

**Module 3C — HTTP Probe:**
- `Content-Security-Policy` absent → medium Finding
- `X-Frame-Options` absent → medium Finding
- CORS reflected arbitrary origin → high Finding
- CORS reflected + credentials → critical Finding
- `Server: Apache/2.2.14` present → low Finding
- `/.env` returns 200 → critical Finding
- All headers correct, no sensitive paths → zero findings (true negative)

**Module 3D — DNS Probe:**
- Zone transfer allowed → critical Finding with zone data in evidence
- SPF `+all` → critical Finding
- SPF missing → medium Finding
- DMARC `p=none` → low Finding
- DMARC missing → medium Finding
- Open resolver → high Finding
- Correctly configured domain → zero findings (true negative)

**Scoring Engine:**
- Zero findings → all domain scores 100, grade A
- One critical finding in TLS domain → TLS score ≤ 75
- Four criticals across all domains → overall score ≤ 45, grade F
- Same findings list run twice → identical scores (deterministic)
- OWASP coverage correctly shows "untested" for categories with no checks run

---

## 9. Implementation Phases

### Phase 1 — CLI + Static Analyzer
Wire up CLI entry point. Implement static analyzer for TypeScript, Python, Java. Produce Attack Surface Manifest. Print manifest to stdout.

**Done when:** `netsentinel scan --target ./my-repo --static-only` runs, prints a valid Attack Surface Manifest JSON, exits cleanly.

**Key milestone:** Run against a real TypeScript Express repo — correctly extracts routes, ports from `docker-compose.yml`, any hardcoded secrets.

### Phase 2 — Live Probing Engine (all four modules)
Implement Modules 3A–3D. Wire them to take either a manifest or bare host. Emit findings to stdout. Modules run concurrently.

**Done when:** `netsentinel scan --host demo.dvwa.co.uk --live-only` runs all four modules, prints findings with severity and CVSS scores.

**Key milestone:** TLS module correctly identifies expired cert on `badssl.com/expired`. Network module catches dangerous open ports on Metasploitable3.

### Phase 3 — Scoring Engine + JSON output
Compute scores, write JSON to `~/.netsentinel/scans/`. Print score table to terminal. `netsentinel list` shows history.

**Done when:** Every scan ends with a score table in stdout and a valid `<scan-id>.json` written.

### Phase 4 — Dashboard
Build HTML dashboard. Wire to JSON files. Implement persistent history. Auto-open browser.

**Done when:** `netsentinel scan` completes and automatically opens `localhost:8742` with fully rendered Overview, Findings, and History tabs.

**Key milestone:** Run two scans (OpenClaw and Caddy), open Compare tab, verify score delta is correct and visually clear.

### Phase 5 — GitHub Integration + Compare + Polish
Add GitHub URL cloning to `--target`. Fully wire Compare tab. Run all five test targets. Polish demo flow.

**Done when:** `netsentinel scan --target https://github.com/user/repo --host <demo-url>` runs end to end. Compare tab works across all five test targets.

---

## 10. Tooling & Stack

### Core stack (locked)

| Layer | Tool | Reason |
|---|---|---|
| Language | Python 3.11+ | Best network library ecosystem, asyncio built-in |
| CLI framework | `typer` | Cleaner than `click`, auto-generates help text |
| Port scanner concurrency | `asyncio` | Handles 500+ simultaneous socket connects efficiently |
| Module concurrency | `threading` | Four modules in parallel, simpler than asyncio for this level |
| HTTP probing | `httpx` | HTTP/2 support, async capable, better than `requests` here |
| TLS probing | `ssl` (stdlib) + raw socket | Direct protocol control for version/cipher enumeration |
| DNS | `dnspython` | Full DNS query control, AXFR support |
| Static analysis | `ast` (stdlib) + regex | Python AST for Python targets, regex for TS/Java |
| GitHub clone | `subprocess git clone` | Clone to temp dir, analyze, clean up |
| Dashboard server | `http.server` (stdlib) | No external deps, sufficient for localhost |
| Dashboard UI | Vanilla JS + Chart.js (bundled inline) | No build step, no npm, no CDN calls |
| Data storage | JSON files in `~/.netsentinel/` | Simple, portable, human-readable |
| Config | `config.py` — single source of truth | All constants in one place for Copilot context |

### GitHub Copilot CLI workflow

1. Define all data models first in `models.py` — `Finding`, `AttackSurfaceManifest`, `ScanConfig`, `ScanReport`, `Score`. Copilot references these across every file automatically.

2. Write `config.py` early and completely — port risk classifications, CVSS thresholds, OWASP mappings, scoring weights, dangerous port list, secret regex patterns. Every module imports from here.

3. Each module file starts with a module-level docstring: what it does, its inputs, its outputs, its concurrency model. Copilot uses this as primary context for suggestions.

4. Write acceptance criteria as inline comments above each function stub before asking Copilot to implement:
   ```python
   # Accepts: host (str), port (int)
   # Returns: PortResult(port, status='open'|'closed'|'filtered', banner=str|None)
   # Uses asyncio. Timeout: 1 second. Does not throw on timeout — returns 'filtered'.
   async def scan_port(host: str, port: int) -> PortResult:
       ...
   ```

5. Use verb-first, domain-specific function names throughout: `probe_tls_version()`, `extract_exposed_ports()`, `score_domain_findings()`, `enumerate_cipher_suites()`.

6. Commit frequently — Copilot CLI gives better suggestions when it can see a clean, complete file tree.

### Optional Phase 5+ enhancement

Wire the Anthropic API into the dashboard for AI-powered remediation. When a user clicks a finding, a "Get detailed fix" button calls the API with the finding JSON and returns a contextual, framework-aware fix suggestion. One API call per finding click — significantly more impressive for demo.

---

## 11. Project File Structure (target)

```
netsentinel/
├── netsentinel/
│   ├── __init__.py
│   ├── cli.py                  # typer CLI — subcommand handlers
│   ├── config.py               # all constants — port classifications, OWASP mappings, weights, regex patterns
│   ├── models.py               # Finding, AttackSurfaceManifest, ScanConfig, ScanReport, Score
│   ├── static_analyzer.py      # Component 2 — file tree extraction
│   ├── probing/
│   │   ├── __init__.py
│   │   ├── engine.py           # orchestrates all four modules concurrently
│   │   ├── network.py          # Module 3A — port scan, banner grab, ICMP
│   │   ├── tls.py              # Module 3B — TLS/SSL inspection
│   │   ├── http.py             # Module 3C — HTTP header/CORS/injection probing
│   │   └── dns.py              # Module 3D — DNS zone transfer, SPF/DMARC, subdomain enum
│   ├── scoring.py              # Component 4 — score computation, OWASP coverage
│   ├── storage.py              # read/write ~/.netsentinel/ scan history
│   └── dashboard/
│       ├── server.py           # minimal http.server wrapper
│       └── dashboard.html      # single-file dashboard, all JS inline, Chart.js bundled
├── tests/
│   ├── test_network.py
│   ├── test_tls.py
│   ├── test_http.py
│   ├── test_dns.py
│   └── test_scoring.py
├── wordlists/
│   └── subdomains-1000.txt     # subdomain enumeration wordlist
├── pyproject.toml
└── README.md
```
