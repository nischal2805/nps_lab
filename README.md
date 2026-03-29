# NetSentinel

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](https://github.com/netsentinel/netsentinel)

**Network Security Auditing Tool — Static Attack Surface Extraction + Live Multi-Layer Probing**

NetSentinel combines static code analysis with live network probing to deliver a complete security audit in one command. Point it at a codebase (local directory or GitHub repo URL) and a live host, and get CVSS 3.1-scored findings mapped to OWASP Top 10 2021, presented in an interactive browser dashboard.

---

## ✨ Features

### 🔍 Comprehensive Coverage
- **Four Network Domains**: Network/Transport (ports, services, ICMP), TLS/SSL, HTTP application layer, DNS
- **Static Analysis**: Attack surface extraction from TypeScript, Python, and Java codebases — never executes code
- **Live Probing**: Multi-layer concurrent probing across all network domains

### 📊 Standards-Based Scoring
- **CVSS 3.1**: Every finding scored with complete vector breakdown
- **OWASP Top 10 2021**: Automatic mapping to all 10 categories
- **Domain Scores**: Per-domain scores (0-100) with weighted overall grade (A-F)

### 🎯 Interactive Dashboard
- **Persistent History**: All scans saved — compare across targets and timeframes
- **Filterable Findings**: Sort by severity, domain, CVSS score, or OWASP category
- **Side-by-Side Comparison**: Compare multiple targets in parallel (demo showpiece)
- **Zero Dependencies**: Single HTML file, no build step, no CDN calls

### 🚀 Developer-Friendly
- **GitHub URL Support**: Direct scanning from GitHub repos
- **Flexible Modes**: Static-only, live-only, or combined analysis
- **Real-Time Progress**: Live status updates during scan execution
- **Remediation Guidance**: Actionable fix recommendations for every finding

---

## 📦 Installation

### Prerequisites
- **Python 3.10+** (3.11 or 3.12 recommended)
- **uv** package manager (recommended) — [install from astral.sh](https://astral.sh/uv)

### Using uv (Recommended)

```bash
# Clone the repository
git clone https://github.com/netsentinel/netsentinel.git
cd netsentinel

# Create virtual environment and install
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"

# Verify installation
netsentinel --help
```

### Using pip (Alternative)

```bash
# Clone the repository
git clone https://github.com/netsentinel/netsentinel.git
cd netsentinel

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Verify installation
netsentinel --help
```

### Docker Installation

```bash
# Build the image
docker build -t netsentinel .

# Run a scan (results saved to ./results)
docker run --rm -v $(pwd)/results:/root/.netsentinel netsentinel scan \
  --target https://github.com/user/repo \
  --host example.com
```

---

## 🚀 Quick Start

### Full Scan (Static + Live)

```bash
# Scan a GitHub repository and live host
netsentinel scan --target https://github.com/user/repo --host example.com

# Scan a local codebase and live host
netsentinel scan --target ./my-app --host 192.168.1.100
```

### Live-Only Mode

```bash
# Probe a live host without static analysis
netsentinel scan --host example.com --live-only

# Focus on specific port
netsentinel scan --host example.com --port 443 --live-only
```

### Static-Only Mode

```bash
# Extract attack surface from code only
netsentinel scan --target https://github.com/user/repo --static-only
netsentinel scan --target ./my-app --static-only
```

### View Results

```bash
# Open dashboard to most recent scan
netsentinel report --last

# Open specific scan by ID
netsentinel report --scan-id abc123-def456

# List all past scans
netsentinel list

# Compare two scans side-by-side
netsentinel compare <scan-id-1> <scan-id-2>
```

---

## 📖 CLI Reference

### Commands

#### `netsentinel scan`
Execute a security audit with static analysis and/or live probing.

**Flags:**
- `--target <path|url>` — Local directory or GitHub HTTPS URL to codebase (optional if `--live-only`)
- `--host <ip|domain>` — IP address or domain of live target (optional if `--static-only`)
- `--port <port>` — Specific port to focus probing on (default: top 1000 ports)
- `--live-only` — Skip static analysis, probe live host only
- `--static-only` — Skip live probing, extract attack surface from code only

**Examples:**
```bash
netsentinel scan --target ./my-app --host staging.example.com
netsentinel scan --target https://github.com/org/repo --host 10.0.0.5 --port 8080
netsentinel scan --host production.example.com --live-only
netsentinel scan --target ./backend --static-only
```

#### `netsentinel report`
Open the dashboard to view scan results.

**Flags:**
- `--last` — Open most recent scan
- `--scan-id <id>` — Open specific scan by ID

**Examples:**
```bash
netsentinel report --last
netsentinel report --scan-id f3a8b9c1-4d5e-6789-abcd-ef0123456789
```

#### `netsentinel compare`
Open dashboard in comparison mode for multiple scans.

**Arguments:**
- `<scan-id-1> <scan-id-2> [<scan-id-3>...]` — Two or more scan IDs to compare

**Examples:**
```bash
netsentinel compare abc123 def456
netsentinel compare scan-1 scan-2 scan-3
```

#### `netsentinel list`
Print summary of all past scans.

**Output:**
- Scan ID, target, host, date, overall grade, total findings

**Examples:**
```bash
netsentinel list
```

### Short Alias

All commands are available via the `nts` alias:

```bash
nts scan --target ./app --host localhost
nts report --last
nts list
```

---

## 🏗️ Architecture

NetSentinel is built from five components in strict sequential dependency order:

### 1. **CLI Entry Point** (`netsentinel.cli`)
- Command parsing and validation
- Pipeline orchestration
- Real-time progress reporting
- Auto-launch dashboard on completion

### 2. **Static Analyzer** (`netsentinel.static_analyzer`)
- Read-only file traversal (never executes code)
- Attack surface extraction: ports, routes, secrets, TLS/DNS config
- Language support: TypeScript, Python, Java
- GitHub repository cloning

### 3. **Live Probing Engine** (Modules 3A-3D)
Four concurrent probe modules:
- **3A — Network Probe**: Port scanning (asyncio), banner grabbing, ICMP
- **3B — TLS Probe**: Protocol version checks, cipher enumeration, certificate inspection
- **3C — HTTP Probe**: Security headers, CORS, sensitive paths, XSS/SQLi surface
- **3D — DNS Probe**: Zone transfer, SPF/DMARC/DKIM, subdomain enumeration, open resolver

### 4. **Scoring Engine** (`netsentinel.scoring_engine`)
- Per-domain scores (0-100)
- Weighted overall score with letter grade (A-F)
- OWASP Top 10 2021 mapping
- CVSS 3.1 summary statistics

### 5. **Persistent Dashboard** (`netsentinel.dashboard`)
- Single-page HTML application (no build step)
- Python HTTP server on localhost
- Scan history persistence (`~/.netsentinel/`)
- Real-time filtering and sorting

### Directory Structure

```
netsentinel/
├── cli.py                  # CLI entry point and command handlers
├── static_analyzer.py      # Attack surface extraction
├── probes/
│   ├── network.py          # Module 3A — Port scanning, ICMP
│   ├── tls.py              # Module 3B — TLS/SSL inspection
│   ├── http.py             # Module 3C — HTTP security checks
│   └── dns.py              # Module 3D — DNS probing
├── scoring_engine.py       # CVSS scoring and grading
├── dashboard/
│   ├── server.py           # HTTP server
│   └── dashboard.html      # Single-page dashboard UI
├── models.py               # Data structures (Finding, ScanConfig, etc.)
└── config.py               # Constants, weights, OWASP mappings
```

### Technology Stack

- **Language**: Python 3.10+
- **Concurrency**: 
  - `asyncio` for port scanning (thousands of concurrent connections)
  - `threading` for probe module orchestration
- **Key Dependencies**:
  - `click` — CLI framework
  - `pydantic` — Data validation
  - `httpx` — HTTP client
  - `dnspython` — DNS queries
  - `cryptography` — TLS inspection
  - `flask` — Dashboard server

---

## 🧪 Testing

### Run All Tests

```bash
pytest
```

### Run with Coverage

```bash
pytest --cov=netsentinel --cov-report=term-missing
```

### Run Specific Test Modules

```bash
# Static analyzer tests
pytest tests/test_static_analyzer.py

# Network probe tests
pytest tests/probes/test_network.py

# Scoring engine tests
pytest tests/test_scoring_engine.py
```

### Integration Tests

```bash
# Run against test targets (requires test environment setup)
pytest tests/integration/
```

**Test Targets:**
- **Metasploitable3**: Network + TLS + HTTP coverage
- **DVWA (Damn Vulnerable Web App)**: HTTP layer testing
- **BadSSL.com**: TLS/SSL configuration testing

---

## 🛠️ Development

### Setting Up Dev Environment

```bash
# Clone and install with dev dependencies
git clone https://github.com/netsentinel/netsentinel.git
cd netsentinel
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Code Quality Tools

```bash
# Format code with Black
black netsentinel/ tests/

# Sort imports with isort
isort netsentinel/ tests/

# Lint with Ruff
ruff check netsentinel/ tests/

# Type checking with mypy
mypy netsentinel/
```

### Pre-Commit Checks

```bash
# Run all quality checks before committing
black --check netsentinel/ tests/ && \
isort --check netsentinel/ tests/ && \
ruff check netsentinel/ tests/ && \
mypy netsentinel/ && \
pytest
```

### Adding New Checks

1. **Add finding type to `models.py`**:
   ```python
   class Finding(BaseModel):
       id: str
       domain: Literal["network", "tls", "http", "dns", "static"]
       # ... add new fields if needed
   ```

2. **Implement check function in appropriate probe module**:
   ```python
   def check_new_vulnerability(host: str, port: int) -> Finding | None:
       # Implementation
       return finding if vulnerability_detected else None
   ```

3. **Add CVSS scoring logic to `config.py`**:
   ```python
   FINDING_CVSS_MAPPINGS = {
       "new_vulnerability": {
           "score": 7.5,
           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
           "owasp_id": "A05"
       }
   }
   ```

4. **Add tests**:
   ```python
   def test_new_vulnerability_detection():
       finding = check_new_vulnerability("test.example.com", 443)
       assert finding.severity == "high"
       assert finding.cvss_score == 7.5
   ```

---

## 🐳 Docker Usage

### Build the Image

```bash
docker build -t netsentinel .
```

### Run a Scan

```bash
# Scan with results saved to local directory
docker run --rm \
  -v $(pwd)/results:/root/.netsentinel \
  netsentinel scan \
  --target https://github.com/user/repo \
  --host example.com

# Windows PowerShell:
docker run --rm `
  -v ${PWD}/results:/root/.netsentinel `
  netsentinel scan `
  --target https://github.com/user/repo `
  --host example.com
```

### Access Dashboard

```bash
# Run scan and keep container alive for dashboard access
docker run -it --rm \
  -v $(pwd)/results:/root/.netsentinel \
  -p 8080:8080 \
  netsentinel scan \
  --target https://github.com/user/repo \
  --host example.com

# Dashboard available at http://localhost:8080
```

---

## 🐛 Troubleshooting

### Issue: "Host unreachable" error
**Solution**: Verify the target host is accessible from your network. Try:
```bash
ping <host>
curl -I http://<host>
```

### Issue: GitHub clone fails with authentication error
**Solution**: Ensure the GitHub URL is public or you have SSH keys configured. Use HTTPS URLs for public repos:
```bash
netsentinel scan --target https://github.com/user/repo --host example.com
```

### Issue: Port scan taking too long
**Solution**: Reduce concurrency or specify a single port:
```bash
netsentinel scan --host example.com --port 443
```

### Issue: Dashboard won't open automatically
**Solution**: Manually open the dashboard URL printed in the terminal, or use:
```bash
netsentinel report --last
```

### Issue: Permission denied on Linux/macOS
**Solution**: Some network operations require elevated privileges:
```bash
sudo netsentinel scan --host example.com --live-only
```

### Issue: SSL/TLS handshake failures
**Solution**: Target may not support older TLS versions. This is expected behavior and will be reflected in findings. Check:
```bash
openssl s_client -connect <host>:443 -tls1_2
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-check`)
3. Make your changes with tests
4. Run quality checks (`black`, `ruff`, `mypy`, `pytest`)
5. Commit with clear messages
6. Push and open a Pull Request

---

## 🔗 Related Projects

- [OWASP ZAP](https://www.zaproxy.org/) — Active web app security scanner
- [Nmap](https://nmap.org/) — Network discovery and security auditing
- [SSLyze](https://github.com/nabla-c0d3/sslyze) — SSL/TLS scanning library
- [Snyk](https://snyk.io/) — Dependency vulnerability scanning

---

## 📚 Documentation

- [Product Requirements Document](NetSentinel_PRD.md) — Complete technical specification
- [CVSS 3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [OWASP Top 10 2021](https://owasp.org/Top10/)

---

**Built with ❤️ for security engineers, developers, and penetration testers.**
