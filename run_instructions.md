# NetSentinel — Run Instructions

## What It Does

NetSentinel is a Python CLI security auditing tool with two independent analysis modes:

- **Static mode** (`--static-only`): reads source code (local path or GitHub URL) without executing it. Extracts ports, routes, secrets, TLS/DNS config, and generates a dependency SBOM (Software Bill of Materials).
- **Live mode** (`--live-only`): probes a running host using 4 concurrent threads — network port scan (top 1000 ports via asyncio, 500 concurrent sockets), TLS/SSL inspection, HTTP header analysis, and DNS record enumeration.
- **Combined mode** (default): runs both, then cross-checks open ports against what the static analysis declared.

After any scan, it saves results to `~/.netsentinel/scans/<scan-id>.json` and spins up a local Flask-based dashboard at **http://localhost:8742**.

---

## Setup

> **Windows note:** `python` and `pip` are not in PATH by default. Use `py` (the Python Launcher) and the venv's own executables instead.

### 1. Check Python is available

```powershell
py --version   # must be >= 3.10
```

### 2. Create a virtual environment

```powershell
py -m venv .venv
```

### 3. Install the package and all dependencies

Do **not** activate the venv — call the venv's executables directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip install toml gitpython asyncio-throttle
```

The first command installs core deps from `pyproject.toml`.  
The second installs extras that are in `requirements.txt` but not `pyproject.toml`.

### 4. Verify installation

```powershell
.\.venv\Scripts\netsentinel.exe --version
```

Expected output: `NetSentinel, version 0.1.0`

### Using the CLI

Replace `netsentinel` in all examples below with the full venv path:

```powershell
.\.venv\Scripts\netsentinel.exe <command>
```

Or activate the venv first (then plain `netsentinel` works):

```powershell
.\.venv\Scripts\Activate.ps1   # run once per terminal session
netsentinel --version
```

---

## Commands

### `scan` — Run a security scan

```
netsentinel scan [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--target, -t` | Local path or GitHub URL (`https://github.com/user/repo`) |
| `--host, -h` | IP address or domain (e.g. `example.com` or `localhost:8080`) |
| `--port, -p` | Specific port to focus on |
| `--live-only` | Skip static analysis (no `--target` needed) |
| `--static-only` | Skip live probing (no `--host` needed) |

### `report` — Open dashboard for a past scan

```
netsentinel report --last
netsentinel report --scan-id <full-scan-id>
```

### `list` — Show all past scans

```
netsentinel list
```

### `compare` — Side-by-side comparison of two scans

```
netsentinel compare <scan-id-1> <scan-id-2>
```

---

## Running the Modes

### Static-only scan (local codebase)

Scans source code without hitting any live host. Works offline.

```powershell
netsentinel scan --target . --static-only
```

Or against a GitHub repo:

```powershell
netsentinel scan --target https://github.com/user/repo --static-only
```

What happens:
1. Validates the path/URL is accessible.
2. Walks all `.py`, `.js`, `.ts`, `.yaml`, `.json`, `.env`, `Dockerfile`, etc. files.
3. Extracts: exposed ports, API routes, hardcoded secrets (regex patterns), TLS config, DNS config, outbound hosts, SBOM dependencies.
4. Scores findings and saves to `~/.netsentinel/`.
5. Launches dashboard at http://localhost:8742.

### Live-only scan (running host)

Probes a host that is currently reachable. Requires network access.

```powershell
netsentinel scan --host example.com --live-only
```

Or with a specific port:

```powershell
netsentinel scan --host localhost:8080 --live-only
```

What happens:
1. Validates host reachability (tries ports 80, 443, 22 then ICMP ping).
2. Launches 4 concurrent threads:
   - **Network**: async TCP scan of top-1000 ports + 500 concurrent sockets, 1s timeout per port, 3s banner grab.
   - **TLS**: SSL/TLS handshake on ports 443 and 8443, checks certificate validity, cipher suites, protocol versions.
   - **HTTP**: checks headers (HSTS, CSP, X-Frame-Options, etc.) on ports 80, 443, 8080, 8443.
   - **DNS**: (skipped for raw IP addresses) enumerates A, MX, TXT, SPF, DKIM, DMARC, DNSSEC records.
3. Cross-checks open ports against manifest (if static analysis also ran).
4. Saves and launches dashboard.

### Combined scan (full audit)

```powershell
netsentinel scan --target . --host localhost:8080
```

Runs static analysis first, then uses discovered ports/routes to inform the live probe (e.g., HTTP probe hits declared API routes, TLS probe checks declared TLS ports).

### Quick local test (scan this repo itself, static only)

```powershell
netsentinel scan --target . --static-only
```

---

## Dashboard

After any scan command, the dashboard starts automatically at **http://localhost:8742**.

- `/` — Landing page
- `/dashboard` — Full scan results viewer

The dashboard is a simple Python `http.server` (no Flask required at runtime). It reads from `~/.netsentinel/` on each request:
- `GET /api/scans` — lists all scans from `index.json`
- `GET /api/scans/<id>` — returns full JSON for one scan

Press **Ctrl+C** in the terminal to stop the dashboard server.

To re-open the dashboard for a past scan without re-running:

```powershell
netsentinel report --last
```

---

## Running Tests

```powershell
# All tests
pytest

# Unit tests only (fast, no network)
pytest tests/unit/

# Integration tests (may hit network)
pytest tests/integration/

# With coverage
pytest --cov=netsentinel
```

---

## Storage Layout

All scan data is persisted at:

```
~/.netsentinel/
├── index.json              # list of all scans (scan_id, date, grade, etc.)
└── scans/
    └── <scan-id>.json      # full scan result per scan
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Port 8742 is already in use` | Another dashboard is running. Kill it or wait for Ctrl+C to take effect. |
| `Host may not be reachable` warning | Tool continues anyway — the host may still respond to specific probes. |
| `Static analysis failed` | Check that the target path exists and contains supported file types. |
| TLS probe returns no findings | Host may not have TLS on ports 443/8443. Use `--live-only` against a known HTTPS host. |
| DNS probe skipped | Expected when `--host` is a raw IP address (e.g. `192.168.1.1`). Use a domain name for DNS analysis. |
