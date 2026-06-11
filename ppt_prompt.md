# NetSentinel — 10-Slide PowerPoint Prompt

Copy the entire block below into Gamma, Beautiful.ai, or any AI slide generator.

---

```
Create a 10-slide professional PowerPoint presentation for a project called NetSentinel.

GLOBAL DESIGN RULES
───────────────────
• Color palette:
  - Background: #010804 (near-black with a green tint)
  - Primary accent: #00ff6e (neon green — use for headings, icons, highlights)
  - Secondary accent: #10b981 (emerald green — use for subtext, borders)
  - Glass cards: rgba(0,255,110,0.06) fill with rgba(0,255,110,0.18) border, backdrop blur
  - Text: #ffffff (headings), #b8f0d0 (body)
  - Critical severity: #ff3344 | High: #ff8800 | Medium: #ffc300 | Low/Info: #00ff6e
• Typography: Bold sans-serif headings (e.g. Inter Black or Montserrat ExtraBold); clean body font
• Layout: Dark glassmorphism — every content block sits in a frosted-glass card on the dark background
• Subtle animated particle-network background on every slide (faint green dots and connecting lines)
• All diagrams, icons, and charts use the same green/black palette — no blue, no purple
• Icons: flat neon-green line icons throughout
• Each slide has a thin neon-green top-border accent line across the full width
• Slide number bottom-right, always visible, small


═══════════════════════════════════════════════════════════════
SLIDE 1 — TITLE SLIDE
═══════════════════════════════════════════════════════════════

HEADLINE (large, centered, white):
  NetSentinel

SUBHEADLINE (neon green, centered, smaller):
  Advanced Network Security Intelligence Platform

TAGLINE (body text, centered, dimmed):
  Static Analysis · Live Probing · CVSS 3.1 Scoring · OWASP Top 10

VISUAL — center of slide:
  A large glowing 3D-style network sphere made of dots and connecting lines in neon green.
  The sphere should look like a scan sweeping over a globe.
  Behind it: faint hexagonal grid pattern.
  Below the sphere: four small glowing pill badges side by side:
    [🔍 Static Analysis]  [🌐 Network Probe]  [🔐 TLS Probe]  [📡 DNS Probe]

BOTTOM STRIP (dark glass bar):
  Left:  "CVSS 3.1 Compliant"   Center: "OWASP Top 10 2021"   Right: "Grade A → F"

DESIGN NOTE: This slide should feel like a cybersecurity product landing page — dramatic, glowing, professional.


═══════════════════════════════════════════════════════════════
SLIDE 2 — PROBLEM STATEMENT
═══════════════════════════════════════════════════════════════

HEADLINE: The Security Blind Spot

LEFT HALF — "The Problem" section with glass card:
  Large bold stat: "73%" in neon green
  Text below: of web applications have at least one critical vulnerability

  Then three pain-point rows, each with a red ✗ icon:
  ✗  Static scanners miss live network misconfigurations
  ✗  Network scanners don't analyze source code secrets
  ✗  No unified CVSS scoring across code + network + DNS
  ✗  Manual OWASP compliance mapping wastes hours

RIGHT HALF — Visual infographic:
  Three separate circles labeled:
    Circle 1 (red-tinted): "Code Scanner" — only shows code issues
    Circle 2 (yellow-tinted): "Network Scanner" — only shows open ports
    Circle 3 (blue-tinted): "Compliance Tool" — only shows policy gaps
  These circles do NOT overlap — they are separated.
  Caption below: "Existing tools operate in silos — none see the full picture"
  Arrow pointing right toward the next slide (off-screen): "NetSentinel solves this →"

DESIGN NOTE: Use red accents sparingly on this slide only to emphasize the pain.


═══════════════════════════════════════════════════════════════
SLIDE 3 — SOLUTION OVERVIEW  (System Architecture)
═══════════════════════════════════════════════════════════════

HEADLINE: One Tool. Complete Attack Surface.

TOP STRIP — three input badges in a row:
  [📁 Local Codebase]   [🐙 GitHub Repository]   [🌍 Live Host / IP]
  Connected by arrows pointing down to a single central node:
  [⚡ NetSentinel Engine]

MAIN VISUAL — horizontal pipeline diagram with 4 stages:

  Stage 1 — Glass card: STATIC ANALYSIS
    Icon: magnifying glass over code
    Sub-items: Ports · Routes · Secrets · SBOM
    Languages: Python · TypeScript · Java · Go

  Stage 2 — Glass card: LIVE PROBING (4 concurrent threads shown as stacked cards)
    🌐 Network Probe
    🔐 TLS Probe
    📡 HTTP Probe
    🌍 DNS Probe
    Badge: "500 concurrent sockets"

  Stage 3 — Glass card: SCORING ENGINE
    Icon: gauge/speedometer
    CVSS 3.1 Calculation
    Domain Weights: Network 25% · TLS 30% · HTTP 25% · DNS 20%

  Stage 4 — Glass card: DASHBOARD
    Icon: monitor with graph
    Grade A–F display
    Findings table
    OWASP grid

  Arrows between each stage in neon green.

BOTTOM NOTE (small): "All four live probe modules run concurrently via Python threading"

DESIGN NOTE: This is the most important technical slide — make the pipeline flow left to right with clear separation.


═══════════════════════════════════════════════════════════════
SLIDE 4 — STATIC CODE ANALYSIS
═══════════════════════════════════════════════════════════════

HEADLINE: Attack Surface Extraction — Without Execution

SPLIT LAYOUT — Left 40% / Right 60%

LEFT — Vertical stack of glass cards (what it detects):
  Card 1: 🔌 Open Ports
    "Detected from Dockerfile, docker-compose.yml, .env, source code"
  Card 2: 🛣️ API Routes
    "Express · Flask · FastAPI · Django · Spring · Next.js"
  Card 3: 🔑 Hardcoded Secrets
    "AWS keys · Stripe tokens · GitHub tokens · Private keys"
    Red badge: "Regex pattern matching — 6 secret types"
  Card 4: 📦 Vulnerable Dependencies
    "SBOM generation — checks packages against known CVEs"
    (requirements.txt · package.json · pom.xml · build.gradle)

RIGHT — Code-inspection visual:
  Mock code editor panel (dark, monospace font) showing:
    Line 12: export AWS_KEY="AKIAIOSFODNN7EXAMPLE"   ← red glow highlight + ⚠️ icon
    Line 28: app.listen(3000)                         ← yellow glow + 🔌 icon
    Line 44: app.get('/admin/users', handler)         ← green glow + 🛣️ icon
  Below the editor: animated scan line sweeping top to bottom

  Language badges below (flat pill icons):
    Python  TypeScript  JavaScript  Java  Go  Ruby  PHP

BOTTOM STAT ROW (three glass pills):
  [Scans code WITHOUT execution]  [Supports GitHub cloning]  [Finds secrets before push]

DESIGN NOTE: The code editor visual is the hero element of this slide.


═══════════════════════════════════════════════════════════════
SLIDE 5 — LIVE PROBE ENGINE
═══════════════════════════════════════════════════════════════

HEADLINE: Four Concurrent Probes. Zero Stone Unturned.

TOP — Concurrency diagram:
  Central node: "Target Host"
  Four arrows radiating outward to four cards simultaneously (fan-out shape):
  Each arrow labeled "Thread N"

  Card 1 — 🌐 NETWORK PROBE
    500 async socket connections
    Scans Nmap Top 1000 TCP ports
    Banner grabbing: SSH · FTP · Redis · MongoDB · MySQL · RDP
    Dangerous ports flagged: Telnet(23) · SMB(445) · Redis(6379) · MongoDB(27017)

  Card 2 — 🔐 TLS / SSL PROBE
    Protocol: TLS 1.0 / 1.1 / 1.2 / 1.3 detection
    Weak ciphers: RC4, DES, MD5, SHA1
    Certificate: validity · self-signed · SANs · expiry
    OCSP stapling check

  Card 3 — 📡 HTTP SECURITY PROBE
    Security headers: CSP · HSTS · X-Frame-Options
    Referrer-Policy · Permissions-Policy · X-Content-Type
    CORS arbitrary origin reflection
    50+ sensitive path exposure checks (.env · .git · wp-config.php)
    Cookie flags: Secure · HttpOnly · SameSite

  Card 4 — 🌍 DNS INTELLIGENCE PROBE
    Zone transfer (AXFR) detection
    SPF / DKIM / DMARC validation
    Subdomain enumeration: 500+ wordlist
    CAA record verification
    DNS rebinding detection

BOTTOM BAR (green): "All 4 probes run in parallel threads → complete scan in seconds"

DESIGN NOTE: Use a "fan-out" radial diagram for the concurrency — it visually shows parallelism better than a list.


═══════════════════════════════════════════════════════════════
SLIDE 6 — CVSS 3.1 SCORING ENGINE
═══════════════════════════════════════════════════════════════

HEADLINE: Industry-Standard Scoring. Objective Grades.

LEFT HALF — CVSS 3.1 breakdown visual:

  Title: "CVSS 3.1 Base Score Metrics"
  8 metric pills in a 2×4 grid, each showing metric name + example value:
    AV: Network     AC: Low
    PR: None        UI: None
    S: Changed      C: High
    I: High         A: Low
  
  Below: Formula box (glass):
    Score = f(AV, AC, PR, UI, S, C, I, A)
    Range: 0.0 → 10.0

  Severity bands — horizontal colored bar:
    [0.0──────3.9]  LOW (green)
    [4.0──────6.9]  MEDIUM (yellow)
    [7.0──────8.9]  HIGH (orange)
    [9.0─────10.0]  CRITICAL (red)

RIGHT HALF — Grade system visual:

  Five large grade tiles stacked vertically with colored glows:
    A  (90–100)  neon green glow   — "Excellent security posture"
    B  (75–89)   emerald glow      — "Minor issues, low risk"
    C  (60–74)   yellow glow       — "Notable gaps, action needed"
    D  (45–59)   orange glow       — "Significant vulnerabilities"
    F  (<45)     red glow          — "Critical, immediate action"

  Below the grade tiles — Domain weight pie/donut chart:
    TLS     30%  (largest slice, neon green)
    Network 25%  (emerald)
    HTTP    25%  (teal)
    DNS     20%  (dark green)
    Label: "Weighted scoring reflects real-world risk importance"

  Penalty table (small glass table):
    Critical finding  −25 pts
    High finding      −15 pts
    Medium finding    −8 pts
    Low finding       −3 pts

DESIGN NOTE: The grade tiles with colored glows are the visual anchor of this slide.


═══════════════════════════════════════════════════════════════
SLIDE 7 — OWASP TOP 10 COVERAGE
═══════════════════════════════════════════════════════════════

HEADLINE: Complete OWASP Top 10 2021 Compliance Mapping

TOP — intro text:
  "Every finding is automatically mapped to one of the 10 OWASP categories"

MAIN VISUAL — 10-tile grid (2 rows × 5 columns), each tile is a glass card:
  Each tile contains: OWASP ID (large, neon green) + Category name + which probe detects it

  A01  Broken Access Control          → HTTP Probe, Static Analysis
  A02  Cryptographic Failures         → TLS Probe
  A03  Injection                      → Static Analysis (route extraction)
  A04  Insecure Design                → Static Analysis, SBOM
  A05  Security Misconfiguration      → HTTP Probe, Network Probe
  A06  Vulnerable & Outdated Components → SBOM (requirements.txt, package.json)
  A07  Identification & Auth Failures → HTTP Probe (cookie flags, CORS)
  A08  Software & Data Integrity Failures → Static Analysis (secret patterns)
  A09  Security Logging & Monitoring  → HTTP Probe (missing headers)
  A10  Server-Side Request Forgery    → Static Analysis (outbound hosts)

  Tile states:
    PASS tile = subtle green border + "✓ Pass" label in neon green
    FAIL tile = subtle red border + "✗ N findings" label in red

BOTTOM SECTION — two stat boxes:
  Box 1 (glass): "10 / 10 OWASP categories covered — no blind spots"
  Box 2 (glass): "Per-category pass/fail status visible in dashboard instantly"

DESIGN NOTE: The 10-tile grid is the centerpiece. Show a mix of pass (green-tinted) and fail (red-tinted) tiles to make it realistic.


═══════════════════════════════════════════════════════════════
SLIDE 8 — INTERACTIVE DASHBOARD
═══════════════════════════════════════════════════════════════

HEADLINE: Real-Time Intelligence Dashboard

LAYOUT — full-width mock dashboard screenshot (occupies 75% of slide)

  Mock UI elements to show (dark glass theme matching the actual tool):

  Header bar:
    ⚡ NetSentinel  |  Host: example.com  |  Date: 2024-01-15  |  Duration: 47s
    [Overview] [Findings ●17] [History] [Compare]   ← tab bar

  Overview Tab contents visible:
    Left: Large glowing grade letter "C" in orange-yellow with score "67/100" below
    Middle row: 5 severity count cards:
      [2 CRITICAL red]  [4 HIGH orange]  [6 MEDIUM yellow]  [5 LOW green]  [0 INFO]
    Bottom row: 4 domain score bars:
      Network  72  ████████░░
      TLS      61  ██████░░░░
      HTTP     55  █████░░░░░
      DNS      78  ████████░░
    Right panel: OWASP grid (10 tiles, green/red states)

  Floating side drawer (partially visible on right edge):
    Finding detail panel showing:
      Title: "TLS 1.1 Deprecated Protocol"
      [HIGH]  [tls]  [A02]
      CVSS Score: 7.4
      Evidence: TLS 1.1 handshake succeeded on port 443
      Remediation: Disable TLS 1.0 and 1.1...

BOTTOM — 4 feature callout pills below the mockup:
  [🔍 Filterable Findings Table]
  [📊 Domain Score Cards]
  [🕐 Scan History]
  [⚖️ Side-by-Side Compare]

DESIGN NOTE: This slide should look like a real product screenshot. The mock UI should be pixel-perfect and convincing.


═══════════════════════════════════════════════════════════════
SLIDE 9 — RESULTS & DEMONSTRATION
═══════════════════════════════════════════════════════════════

HEADLINE: Sample Scan Results — Real Output

LAYOUT — Three scan result cards side by side

Card 1 — "Secure Application" (good result):
  Grade: A  (neon green glow)
  Score: 94/100
  Host: secure-app.example.com
  Duration: 38s
  Findings breakdown:
    0 Critical  0 High  1 Medium  2 Low  3 Info
  OWASP: 9/10 Pass
  Domain scores (small bars):
    Network 96 · TLS 98 · HTTP 91 · DNS 92

Card 2 — "Typical Web App" (average result):
  Grade: C  (yellow glow)
  Score: 67/100
  Host: webapp.example.com
  Duration: 52s
  Findings breakdown:
    2 Critical  4 High  6 Medium  5 Low  0 Info
  Top findings listed:
    🔴 Hardcoded AWS Secret Key (CVSS 9.8)
    🔴 Telnet Port 23 Exposed (CVSS 9.1)
    🟠 TLS 1.1 Deprecated (CVSS 7.4)
    🟠 Missing Content Security Policy (CVSS 7.1)
  OWASP: 6/10 Pass

Card 3 — "Legacy System" (poor result):
  Grade: F  (red glow)
  Score: 31/100
  Host: legacy.example.com
  Duration: 61s
  Findings breakdown:
    5 Critical  8 High  11 Medium  3 Low
  Top findings:
    🔴 Redis 6379 Exposed (CVSS 9.8)
    🔴 MongoDB 27017 Exposed (CVSS 9.8)
    🔴 Zone Transfer Enabled (CVSS 9.3)
    🔴 SPF +all — Spoofing Risk (CVSS 9.1)
  OWASP: 3/10 Pass

BOTTOM BAR:
  "Scan pipeline: validate → static analysis → 4 live probes → CVSS scoring → grade → dashboard launch"
  Visual: Horizontal 5-step arrow pipeline in neon green

DESIGN NOTE: The three cards should visually contrast — green glow, yellow glow, red glow — to show the full range of possible outcomes.


═══════════════════════════════════════════════════════════════
SLIDE 10 — CONCLUSION & FUTURE SCOPE
═══════════════════════════════════════════════════════════════

HEADLINE: What NetSentinel Achieves

TOP HALF — Summary grid (2 × 3 glass tiles):

  Tile 1: 🔍  Static + Live  —  Combines code-level and network-level analysis in one pipeline
  Tile 2: ⚡  4 Concurrent Probes  —  Network · TLS · HTTP · DNS run simultaneously via threading
  Tile 3: 📊  CVSS 3.1  —  Full base score calculation per the FIRST specification
  Tile 4: 🏷️  OWASP Mapped  —  Every finding tagged to OWASP Top 10 2021 automatically
  Tile 5: 🌐  Any Target  —  Accepts local code, GitHub URLs, or live hosts
  Tile 6: 📱  Zero-Install UI  —  Browser dashboard, no build step, persistent scan history

MIDDLE — Technical stats bar (horizontal, glass background):
  [1000+ Ports Scanned]  [500 Concurrent Sockets]  [6 Secret Patterns]  [50+ Sensitive Paths]  [500+ Subdomain Wordlist]

BOTTOM HALF — SPLIT:

  Left — Current Limitations (glass card, amber border):
    ⚠  No authenticated scanning (requires credentials)
    ⚠  No UDP full-range scan (only targeted UDP ports)
    ⚠  Static analysis covers Python, TS, Java — partial Go/Ruby/PHP
    ⚠  No continuous monitoring — manual CLI trigger only

  Right — Future Scope (glass card, green border):
    🚀  CI/CD pipeline integration (GitHub Actions hook)
    🚀  Authenticated API scanning (Bearer token support)
    🚀  Risk trending over time (delta graphs across scans)
    🚀  Slack / email alerting when grade drops below threshold
    🚀  Plugin system for custom probe modules

FINAL LINE (centered, large, neon green, italic):
  "From source code to security grade — in one command."

DESIGN NOTE: End on a confident, clean note. The final quote should be the visual anchor — large, glowing, centered.
```

---

## Quick tips for best results

| Tool | How to use this prompt |
|---|---|
| **Gamma.app** | Paste the full block above into the "Generate" input. Select "Detailed outline" mode. Choose a dark theme as base. |
| **Beautiful.ai** | Use "Smart Slide" and paste one slide block at a time. |
| **Canva AI** | Use the "Magic Design" feature with the full block. Then apply a dark custom color theme. |
| **ChatGPT / Claude** | Ask: "Using the outline below, create detailed speaker notes for each slide" and paste the block. |
| **PowerPoint Copilot** | Paste into the Copilot chat inside PowerPoint with "Create a presentation from this outline." |

## Color codes to paste directly

```
Background:       #010804
Neon green:       #00ff6e
Emerald green:    #10b981
Critical red:     #ff3344
High orange:      #ff8800
Medium yellow:    #ffc300
Low/info green:   #00ff6e
Card fill:        rgba(0, 255, 110, 0.06)
Card border:      rgba(0, 255, 110, 0.18)
Body text:        #b8f0d0
Heading text:     #ffffff
```
