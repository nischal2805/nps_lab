# NetSentinel — Project Setup Configuration

## MCP Servers Required

### 1. GitHub MCP ✅ (Already Connected)
**Purpose:** Testing static analyzer on real repos, cloning targets for analysis
**Usage:**
- Clone repos for static analysis testing
- Test against real codebases (TypeScript/Python/Java projects)
- Future: GitHub repo security comparison showcase

### 2. Filesystem MCP (Recommended)
**Purpose:** Advanced file operations during static analysis
**Installation:**
```bash
# Add to MCP settings
npm install -g @modelcontextprotocol/server-filesystem
```
**Configuration:**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "D:\\Ongoing\\nps_lab"]
    }
  }
}
```

### 3. Python MCP / Brave Search MCP (Optional but useful)
**Purpose:** Real-time documentation lookup for Python security libraries
**Libraries we'll need docs for:**
- `dnspython` - DNS probing
- `asyncio` - Port scanner concurrency
- `ssl` module - TLS handshake inspection
- `httpx` - HTTP probing
- `scapy` - Raw packet crafting (if needed)

---

## Skills/Agents Required

### Critical (Use These Throughout)

1. **`security-reviewer`** ⚠️ MANDATORY
   - **Why:** We're building a security tool — ironic if it has vulns
   - **When:** After every code change, especially network/socket code
   - **Use for:** Reviewing all socket operations, input validation, file I/O

2. **`python-reviewer`** 🔍 MANDATORY
   - **Why:** Entire codebase is Python
   - **When:** After writing any Python code
   - **Use for:** Pythonic patterns, type hints, error handling

3. **`tdd-guide`** ✅ HIGHLY RECOMMENDED
   - **Why:** Security tools must be reliable; TDD prevents false positives/negatives
   - **When:** Before implementing each component
   - **Use for:** Writing tests first for each probe module

### Development Phase

4. **`blueprint`** 📋 (Use Once at Start)
   - **Why:** Multi-component project with strict dependencies
   - **When:** Before starting implementation
   - **Use for:** Creating detailed step-by-step construction plan

5. **`planner`** 📝 (Use for Complex Features)
   - **Why:** Each component (static analyzer, probe modules) is complex
   - **When:** Before implementing each major component
   - **Use for:** Breaking down components into implementable chunks

### Testing & Quality

6. **`e2e-runner`** 🧪 (For Dashboard)
   - **Why:** Dashboard needs E2E tests (tab switching, filtering, comparisons)
   - **When:** After dashboard is built
   - **Use for:** Browser-based testing of dashboard.html

7. **`refactor-cleaner`** 🧹 (Periodic)
   - **Why:** Will accumulate helper functions and utils
   - **When:** After major milestones
   - **Use for:** Removing dead code, consolidating duplicates

---

## Development Dependencies (Python)

Create `requirements.txt`:

```txt
# Network probing
dnspython>=2.4.0
httpx>=0.25.0
scapy>=2.5.0  # For raw packet crafting

# Concurrency
asyncio-throttle>=1.0.1

# Static analysis
tree-sitter>=0.20.0
tree-sitter-python>=0.20.0
tree-sitter-typescript>=0.20.0
tree-sitter-java>=0.20.0
gitpython>=3.1.0  # For git history secret scanning

# CLI
click>=8.1.0
rich>=13.0.0  # For pretty terminal output

# Security
cryptography>=41.0.0  # For TLS inspection
pycvss>=1.7.0  # For CVSS score calculation

# Dashboard
Jinja2>=3.1.0  # For HTML templating if needed

# Testing
pytest>=7.4.0
pytest-asyncio>=0.21.0
pytest-cov>=4.1.0
pytest-mock>=3.11.0
```

---

## Project Structure (To Be Created)

```
nps_lab/
├── .github/
│   ├── copilot-instructions.md  ✅ Done
│   └── workflows/
│       ├── ci.yml               ⏳ TODO
│       └── security-scan.yml    ⏳ TODO
│
├── netsentinel/
│   ├── __init__.py
│   ├── cli.py                   # Component 1
│   ├── config.py                # All constants
│   ├── static_analyzer.py       # Component 2
│   ├── probes/
│   │   ├── __init__.py
│   │   ├── network.py           # Module 3A
│   │   ├── tls_probe.py         # Module 3B
│   │   ├── http_probe.py        # Module 3C
│   │   └── dns_probe.py         # Module 3D
│   ├── scoring.py               # Component 4
│   ├── dashboard/
│   │   ├── server.py
│   │   └── dashboard.html       # Component 5
│   └── models/
│       ├── finding.py
│       ├── manifest.py
│       └── scan_result.py
│
├── tests/
│   ├── unit/
│   │   ├── test_static_analyzer.py
│   │   ├── test_network_probe.py
│   │   ├── test_tls_probe.py
│   │   ├── test_http_probe.py
│   │   ├── test_dns_probe.py
│   │   └── test_scoring.py
│   ├── integration/
│   │   └── test_full_scan.py
│   └── fixtures/
│       └── sample_repos/
│
├── test_targets/
│   ├── openclaw/                # Negative test target
│   └── vulnerable_app/          # Custom test app
│
├── setup.py
├── requirements.txt
├── requirements-dev.txt
├── pytest.ini
├── .gitignore
└── README.md
```

---

## Model Recommendation

### Recommended: **Claude Opus 4.5** for Initial Build

**Why Opus:**
1. **Security-critical code** — network socket operations, TLS handshakes, CVSS scoring must be perfect
2. **Complex concurrency** — asyncio port scanner with threading for probe modules requires deep understanding
3. **Multiple domain expertise** — networking, cryptography, DNS, HTTP, static analysis in one project
4. **Test-driven development** — Opus writes better tests for security edge cases
5. **Architecture complexity** — 5 interdependent components with strict ordering

**When to Switch to Sonnet:**
- Refactoring/cleanup tasks
- Documentation updates
- Dashboard HTML/CSS/JS (simpler UI work)
- Running tests and fixing minor issues

**Cost-Benefit:**
- Initial build with Opus ensures correctness (critical for security tool)
- Switch to Sonnet for iteration once core is solid
- You don't want false positives/negatives in a security scanner — Opus gets it right first time

---

## Initialization Checklist

Before starting implementation:

- [ ] MCP servers configured (GitHub ✅, Filesystem if needed)
- [ ] Model set to **Opus 4.5**
- [ ] Skills ready: `security-reviewer`, `python-reviewer`, `tdd-guide`, `blueprint`
- [ ] Run `blueprint` skill to create master plan
- [ ] Create Python virtual environment
- [ ] Create `requirements.txt` (see above)
- [ ] Initialize git repository
- [ ] Create project structure
- [ ] Write first test (TDD mode)

---

## Next Steps

1. **Use `blueprint` skill** to create detailed implementation plan
2. **Set model to Opus 4.5**
3. **Start with Component 1 (CLI)** using TDD
4. Invoke `security-reviewer` and `python-reviewer` after each component
5. Build sequentially: CLI → Static Analyzer → Probes → Scoring → Dashboard

