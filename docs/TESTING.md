# NetSentinel Testing Guide

This document covers all testing approaches for NetSentinel, from unit tests to full integration testing with Docker containers.

---

## Quick Reference

```bash
# Run all unit tests
python -m pytest tests/unit/ -v

# Run all tests with coverage
python -m pytest --cov=netsentinel --cov-report=term-missing

# Run manual integration tests (against real services)
python tests/manual_test.py

# Run Docker integration tests
docker-compose -f docker-compose.test.yml up -d
python -m pytest tests/integration/ -v
```

---

## Test Categories

### 1. Unit Tests (`tests/unit/`)

Unit tests verify individual functions and classes in isolation using mocks. They don't require network access.

**Run unit tests:**
```bash
# All unit tests
python -m pytest tests/unit/ -v --tb=short

# Specific module
python -m pytest tests/unit/test_network_probe.py -v

# With coverage
python -m pytest tests/unit/ --cov=netsentinel --cov-report=term-missing
```

**Unit test files:**
- `test_network_probe.py` — Port scanning, ICMP, banner grabbing
- `test_scoring.py` — CVSS scoring, grade calculation
- `test_static_analyzer.py` — Code analysis, secret detection

**Writing new unit tests:**
```python
from unittest.mock import patch, MagicMock
import pytest

from netsentinel.probes.http_probe import check_security_headers

class TestSecurityHeaders:
    def test_missing_hsts_header(self):
        """Test detection of missing HSTS header."""
        # Arrange
        mock_response = MagicMock()
        mock_response.headers = {"Content-Type": "text/html"}
        
        # Act
        with patch("httpx.Client.get", return_value=mock_response):
            findings = check_security_headers(...)
        
        # Assert
        assert any("HSTS" in f.title for f in findings)
```

---

### 2. Integration Tests (`tests/integration/`)

Integration tests verify components work together correctly. Some tests require network access or Docker.

**Run integration tests:**
```bash
# All integration tests
python -m pytest tests/integration/ -v

# Skip network-dependent tests
python -m pytest tests/integration/ -v -m "not network"
```

**Integration test files:**
- `test_cli_commands.py` — CLI command orchestration
- `test_full_scan_workflow.py` — End-to-end scan pipeline
- `test_probe_orchestration.py` — Multi-probe coordination
- `test_static_analyzer_real_repos.py` — Real codebase analysis

---

### 3. Manual Integration Tests (`tests/manual_test.py`)

The manual test script tests probes against real external services to verify they work in production conditions.

**Run manual tests:**
```bash
python tests/manual_test.py
```

**Test targets:**
| Service | Purpose | Expected Findings |
|---------|---------|-------------------|
| `httpbin.org` | HTTP header checks | Missing security headers |
| `badssl.com` | Good TLS config | Minimal findings |
| `expired.badssl.com` | Expired certificate | Certificate errors |
| `self-signed.badssl.com` | Self-signed cert | Trust issues |
| `google.com` | DNS records | Properly configured |
| `example.com` | Missing email records | SPF/DMARC findings |

**Expected output:**
```
============================================================
  NetSentinel Manual Integration Tests
============================================================

Testing probes against real external services...

============================================================
  HTTP Probe Tests
============================================================

  [✓ PASS] HTTP probe against httpbin.org
         Duration: 1234ms
         Findings: 5
         Message:  Found security issues (expected for httpbin.org)

  [✓ PASS] HTTP redirect detection (httpbin.org:80)
         Duration: 456ms
         Findings: 3
         Message:  Redirect handling works (3 findings)

...

============================================================
  Test Summary
============================================================

  Total:    7 tests
  Passed:   7
  Failed:   0
  Duration: 12345ms

  ✓ All tests passed!
```

---

### 4. Docker Integration Tests

Test against intentionally vulnerable and secure Docker containers for controlled testing.

#### Setup Test Containers

```bash
# Start test containers
docker-compose -f docker-compose.test.yml up -d

# Verify containers are running
docker-compose -f docker-compose.test.yml ps

# Container endpoints:
# - DVWA (vulnerable):  http://localhost:8080
# - Caddy (secure):     http://localhost:8081, https://localhost:8443
```

#### Run Scans Against Containers

```bash
# Scan vulnerable DVWA container (expect F grade)
netsentinel scan --host localhost:8080 --live-only

# Scan secure Caddy container (expect A/B grade)
netsentinel scan --host localhost:8081 --live-only

# Scan with TLS (Caddy HTTPS)
netsentinel scan --host localhost:8443 --live-only
```

#### Expected Results

**DVWA (Vulnerable - Expected Grade: D or F):**
- Missing security headers
- Weak cookie configuration
- Information disclosure
- 15+ findings expected

**Caddy (Secure - Expected Grade: A or B):**
- Proper HSTS configuration
- Strong TLS configuration
- Security headers present
- 0-3 findings expected

#### Cleanup

```bash
docker-compose -f docker-compose.test.yml down -v
```

---

## Example Scan Commands

### Basic Scans

```bash
# Scan a local web server
netsentinel scan --host localhost:8080 --live-only

# Scan with specific port
netsentinel scan --host example.com --port 443 --live-only

# Scan multiple domains
netsentinel scan --host api.example.com --live-only
netsentinel scan --host www.example.com --live-only
```

### Static Analysis

```bash
# Analyze local codebase
netsentinel scan --target ./myapp --static-only

# Analyze GitHub repository
netsentinel scan --target https://github.com/user/repo --static-only

# Combined static + live scan
netsentinel scan --target ./myapp --host myapp.example.com
```

### Full Scans

```bash
# Full scan: static analysis + live probing
netsentinel scan --target ./backend --host api.example.com

# GitHub repo + production host
netsentinel scan --target https://github.com/org/service --host service.example.com

# Scan with focused port
netsentinel scan --target ./app --host app.example.com --port 8443
```

### Viewing Results

```bash
# Open most recent scan
netsentinel report --last

# List all scans
netsentinel list

# Open specific scan by ID
netsentinel report --scan-id abc123-def456

# Compare two scans
netsentinel compare scan-id-1 scan-id-2
```

---

## Expected Probe Outputs

### Network Probe Findings

| Finding | Severity | Example Target |
|---------|----------|----------------|
| Open Telnet port (23) | Critical | Legacy systems |
| Open FTP port (21) | High | File servers |
| Open SMB port (445) | Critical | Windows systems |
| Undeclared open port | Medium | Any misconfigured host |

### TLS Probe Findings

| Finding | Severity | Example Target |
|---------|----------|----------------|
| TLS 1.0 supported | High | Legacy servers |
| TLS 1.1 supported | Medium | Older configurations |
| Expired certificate | Critical | Misconfigured HTTPS |
| Self-signed certificate | High | Internal/dev servers |
| Weak cipher suites | Medium | Older TLS configs |
| Certificate expiring soon (<30 days) | Medium | Any HTTPS site |
| Missing HSTS header | Medium | HTTP sites |

### HTTP Probe Findings

| Finding | Severity | Example Target |
|---------|----------|----------------|
| Missing X-Frame-Options | Medium | Most web apps |
| Missing Content-Security-Policy | Medium | Many web apps |
| Missing X-Content-Type-Options | Low | Common omission |
| Insecure cookie (no Secure flag) | Medium | HTTP-only apps |
| CORS misconfiguration (wildcard) | High | APIs |
| Sensitive file exposed (/.env) | Critical | Misconfigured servers |
| Server version disclosure | Low | Default configs |

### DNS Probe Findings

| Finding | Severity | Example Target |
|---------|----------|----------------|
| Zone transfer allowed | Critical | Misconfigured DNS |
| Missing SPF record | Medium | Any domain |
| Missing DMARC record | Medium | Any domain |
| Weak SPF (no all) | Medium | Permissive SPF |
| DNSSEC not enabled | Low | Most domains |
| Open DNS resolver | High | Public DNS servers |

---

## Troubleshooting Tests

### Common Issues

**Tests timeout or hang:**
```bash
# Run with shorter timeout
python -m pytest tests/unit/ -v --timeout=30
```

**Network tests fail:**
```bash
# Skip network-dependent tests
python -m pytest tests/ -v -m "not network"

# Check connectivity
ping httpbin.org
curl -I https://badssl.com
```

**Docker tests fail:**
```bash
# Verify containers are running
docker-compose -f docker-compose.test.yml ps

# Check container logs
docker-compose -f docker-compose.test.yml logs dvwa
docker-compose -f docker-compose.test.yml logs caddy

# Restart containers
docker-compose -f docker-compose.test.yml restart
```

**Import errors:**
```bash
# Ensure package is installed in development mode
pip install -e ".[dev]"

# Or with uv
uv pip install -e ".[dev]"
```

### Debug Mode

```bash
# Run with verbose output
python -m pytest tests/unit/ -v -s

# Run single test with debug output
python -m pytest tests/unit/test_network_probe.py::TestScanPort::test_scan_port_open -v -s

# Enable logging
python -m pytest tests/ -v --log-cli-level=DEBUG
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -e ".[dev]"
      
      - name: Run unit tests
        run: |
          python -m pytest tests/unit/ -v --tb=short
      
      - name: Run integration tests
        run: |
          python -m pytest tests/integration/ -v --tb=short -m "not docker"
      
      - name: Upload coverage
        run: |
          python -m pytest --cov=netsentinel --cov-report=xml
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: local
    hooks:
      - id: pytest-unit
        name: pytest unit tests
        entry: python -m pytest tests/unit/ -q
        language: system
        pass_filenames: false
        always_run: true
```

---

## Coverage Goals

| Module | Target Coverage |
|--------|-----------------|
| `netsentinel/probes/network.py` | 85%+ |
| `netsentinel/probes/tls_probe.py` | 80%+ |
| `netsentinel/probes/http_probe.py` | 80%+ |
| `netsentinel/probes/dns_probe.py` | 75%+ |
| `netsentinel/scoring.py` | 90%+ |
| `netsentinel/static_analyzer.py` | 85%+ |
| `netsentinel/cli.py` | 70%+ |
| **Overall** | **80%+** |

Check current coverage:
```bash
python -m pytest --cov=netsentinel --cov-report=html
# Open htmlcov/index.html in browser
```
