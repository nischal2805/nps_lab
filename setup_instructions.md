# NetSentinel — Setup & Run Instructions

## What Was Built

NetSentinel is a Python CLI security auditing tool with a full AI-powered web dashboard.

### Architecture
- **CLI** (`netsentinel scan / report / list / compare`) — unchanged, uses same scan engine
- **Dashboard** — Flask web app at `http://localhost:8742`
- **AI** — Gemini API (`google-genai` SDK) for widget explanations, chat, PDF narrative, compare analysis
- **PDF** — `reportlab`-generated downloadable reports with logo, charts, findings table

---

## Prerequisites

- Windows 10/11
- Python 3.10+ installed (the `py` launcher must work: `py --version`)
- Git
- A Gemini API key from [Google AI Studio](https://aistudio.google.com/)

---

## One-Time Setup

### 1. Clone / open the repo
```powershell
# Already done if you're reading this
cd "E:\2nd Year\GitHub\nps_lab"
```

### 2. Create virtual environment
```powershell
py -m venv .venv
```

### 3. Install all dependencies
```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip install toml gitpython asyncio-throttle google-genai reportlab python-dotenv
```

### 4. Configure Gemini API key
Open `.env` in the repo root and replace the placeholder:
```
GEMINI_API_KEY=your_actual_api_key_here
```
Get a free key at [aistudio.google.com](https://aistudio.google.com/) — click "Get API key".

### 5. Verify installation
```powershell
.\.venv\Scripts\netsentinel.exe --version
# Expected: NetSentinel, version 0.1.0
```

---

## Running the Dashboard

### Option A — via CLI scan (auto-launches dashboard after scan)
```powershell
# Activate venv first (once per terminal session)
.\.venv\Scripts\Activate.ps1

# Static scan on a local folder
netsentinel scan --target . --static-only

# Live probe on a host
netsentinel scan --host example.com --live-only

# Full scan (both)
netsentinel scan --target . --host example.com
```
After the scan finishes, the dashboard opens at **http://localhost:8742** automatically.

### Option B — start dashboard server directly (no scan needed)
```powershell
.\.venv\Scripts\python.exe -c "
from netsentinel.dashboard.server import start_server
start_server(8742, True)
"
```
Then open `http://localhost:8742/dashboard` in your browser.

### Option C — re-open dashboard for past scans
```powershell
netsentinel report --last
```

---

## Using the Dashboard

### Left Sidebar — New Scan
- Select scan type: **Full** (static + live), **Static** (code only), **Live** (host only)
- Enter target path (`./myapp` or `https://github.com/user/repo`) and/or host (`example.com`)
- Click **Run Scan** — a progress overlay appears while scanning
- Results load automatically when complete

### Overview Tab
| Widget | What it shows |
|--------|--------------|
| Score cards | Overall, Network, TLS, HTTP, DNS scores |
| Security Posture radar | Domain scores vs industry average |
| Severity Distribution donut | Finding counts by severity |
| Domain Scores bar | Per-domain score with benchmark |
| Benchmark Comparison | Current score vs industry avg and top 10% |
| OWASP Heatmap | Finding counts by OWASP category and severity |

**Every widget has a sparkle button** (top-right corner). Click it for an AI explanation of what the metric means, what the current value indicates, and the top recommended action.

### Findings Tab
- All findings sorted Critical → High → Medium → Low → Info
- Filter by severity using the pill buttons
- Click any finding to expand the full description + remediation
- Sparkle button on each finding gives an AI deep-dive

### History Tab
- Line chart of score trend across all scans
- Circular donut cards per scan showing grade and finding count

### Compare Tab
- Select two scans from the dropdowns and click Compare
- Radar chart overlay of both scans
- Score delta table
- AI-generated comparative analysis (what improved, what regressed, priority actions)

### AI Chat Sidebar
- Click the green circle button (bottom-right) to open
- Select model: **Flash** (fast), **Pro** (powerful), **Lite** (cheapest)
- Context-aware: knows the current scan's scores, findings, and grades
- Ask anything: "What's my biggest risk?", "How do I fix the TLS findings?", "Compare this to typical e-commerce sites"

### Download Report (PDF)
- Click **Download Report** in the top-right of the dashboard
- AI generates an executive summary narrative first (requires Gemini API key)
- PDF includes: cover page, executive summary, domain scores chart, severity pie chart, benchmark table, full findings list
- Downloads automatically to your browser's downloads folder

---

## Stopping the Server

Press **Ctrl+C** in the terminal where the server is running.

If port 8742 is already in use when you try to start:
```powershell
# Find and kill the process using port 8742
$pid = (netstat -ano | Select-String ":8742") | ForEach-Object { ($_ -split '\s+')[-1] } | Select-Object -First 1
Stop-Process -Id $pid -Force
```

---

## Running Tests

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/ -v
.\.venv\Scripts\python.exe -m pytest tests/ -v   # includes integration
```

---

## Scan Data Storage

All scan results are persisted at:
```
%USERPROFILE%\.netsentinel\
├── index.json              ← scan list (ID, date, grade, findings count)
└── scans\
    └── <scan-id>.json      ← full result per scan
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `GEMINI_API_KEY not configured` | Add your key to `.env` in the repo root |
| `Port 8742 already in use` | Kill the old process (see Stopping the Server above) |
| AI features return errors | Verify API key is correct; check internet connectivity |
| PDF has no AI narrative | Non-fatal — PDF still generates with findings table; fix API key |
| Scan from UI fails validation | Static scan needs Target, Live needs Host, Full needs both |
| `python` not found | Use `py` (Python Launcher) instead, or activate the venv first |
