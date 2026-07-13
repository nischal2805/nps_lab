# NetSentinel — Pull & Run Guide

Quick-start for anyone who just cloned or pulled the latest changes.

---

## What You Need First

- **Python 3.10+** — download from [python.org](https://www.python.org/downloads/) if not installed
- **Git** — to clone the repo (already done if you're reading this)
- **A Gemini API key** — free at [aistudio.google.com](https://aistudio.google.com/) → click "Get API key"

---

## Step 1 — Get the Code

```powershell
git clone https://github.com/pvjambur/nps_lab.git
cd nps_lab
```

If you already have it, just pull:

```powershell
git pull
```

---

## Step 2 — Create a Virtual Environment

```powershell
py -m venv .venv
```

> On Windows, use `py` (not `python`). If `py` fails, open "Python 3.x" from the Start menu and Python Launcher should be in PATH after reinstalling.

---

## Step 3 — Install Dependencies

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip install toml gitpython asyncio-throttle google-genai reportlab python-dotenv
```

---

## Step 4 — Add Your Gemini API Key

Create a file called `.env` in the root of the repo (same folder as `requirements.txt`):

```
GEMINI_API_KEY=paste_your_key_here
```

That's it. The app loads it automatically — you never need to set environment variables manually.

> Keep this file private. Never commit it to git (it's already in `.gitignore`).

---

## Step 5 — Run the App

### Option A — Start the dashboard directly (easiest)

```powershell
.\.venv\Scripts\python.exe -c "from netsentinel.dashboard.server import start_server; start_server(8742, True)"
```

Then open **http://localhost:8742** in your browser. Run scans from the sidebar inside the dashboard.

### Option B — Run a scan from the command line

```powershell
.\.venv\Scripts\Activate.ps1

# Scan a local folder (static analysis)
netsentinel scan --target "E:\path\to\your\project" --static-only

# Probe a live host (network scan)
netsentinel scan --host example.com --live-only

# Full scan — both at once
netsentinel scan --target . --host example.com
```

The dashboard opens automatically after the scan finishes.

---

## That's It

| Task | Command |
|------|---------|
| Start dashboard | `.\.venv\Scripts\python.exe -c "from netsentinel.dashboard.server import start_server; start_server(8742, True)"` |
| Static scan | `netsentinel scan --target "path/to/code" --static-only` |
| Live scan | `netsentinel scan --host yourdomain.com --live-only` |
| View past scans | Open http://localhost:8742/dashboard — history in the left sidebar |
| Download AI report | Click "Download Report" inside the dashboard |

---

## If Something Goes Wrong

**`py` not recognized** — Download Python from python.org and check "Add to PATH" during install.

**`Port 8742 already in use`** — Kill the old server:
```powershell
$p = (netstat -ano | Select-String ":8742") | ForEach-Object { ($_ -split '\s+')[-1] } | Select-Object -First 1
Stop-Process -Id $p -Force
```

**AI features say "API key not configured"** — Make sure `.env` is in the repo root and the key has no extra spaces or quotes.

**`Module not found` errors** — Re-run Step 3.
