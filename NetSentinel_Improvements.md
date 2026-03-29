# NetSentinel — Post-Build Improvement Ideas

**Status:** Reference document — improvements to consider after live testing is complete
**Source:** Docker Scout ecosystem analysis + scoring methodology research
**Version:** 1.0

---

## Improvement 1 — CVE Database Enrichment for Banner Findings

**What the problem is right now:**
When your network probe detects a service version from banner grabbing (e.g. `Apache/2.2.14`, `OpenSSH 7.2`, `nginx/1.14.0`), you surface it as a version disclosure finding. But you stop there. You don't tell the user *what is actually wrong with that version* — which CVEs affect it, how severe they are, whether there are working exploits in the wild.

**What the improvement is:**
After banner grabbing identifies a service and version, cross-reference it against a CVE/vulnerability database to pull known vulnerabilities for that exact version. Surface these as additional findings with real CVE IDs, CVSS scores pulled directly from NVD, and links to exploit databases.

**Which database to use:**
OSV (Open Source Vulnerabilities) — `osv.dev`. Fully free, no API key required, covers most open source software, has a clean REST API. Google maintains it. This is what Trivy uses internally.

NVD (National Vulnerability Database) — `nvd.nist.gov`. The authoritative source, has a free API (rate limited, needs an API key but free to get). CVSS scores on NVD are the gold standard.

**How it would work:**
```
Banner grab detects: "Apache/2.2.14"
        ↓
Parse: vendor=apache, product=httpd, version=2.2.14
        ↓
Query OSV API: GET https://api.osv.dev/v1/query
        ↓
Returns: list of CVEs affecting Apache httpd 2.2.14
        ↓
Each CVE becomes a Finding with:
  - CVE ID (e.g. CVE-2011-3192)
  - CVSS score from NVD
  - Description
  - Reference links
  - Whether a public exploit exists (check Exploit-DB)
```

**Impact on your demo:**
Currently running against Metasploitable3 shows "Apache version disclosed." After this improvement it shows "Apache 2.2.14 — 14 known CVEs including CVE-2011-3192 (CVSS 7.8, DoS via Range header, public exploit available)." Dramatically more compelling.

**Effort:** Medium. OSV API is simple REST, response parsing is straightforward. The hard part is normalizing banner strings into vendor/product/version triples reliably — service banners are inconsistent.

---

## Improvement 2 — Exploitability Multiplier in Scoring Engine

**What the problem is right now:**
Your scoring engine penalizes findings uniformly by severity tier (critical = -25, high = -15, etc.). Two critical findings get the same penalty regardless of whether one has a weaponized exploit actively used in ransomware campaigns and the other is a theoretical edge case requiring physical access. This makes your grade less meaningful.

**What the improvement is:**
Add an exploitability context multiplier on top of the existing CVSS severity penalty. This is the direction the industry is moving — it's called VEX (Vulnerability Exploitability eXchange) at the standards level, but you can implement a simplified version.

**The multiplier table:**
```
Exploitability context              Multiplier    Source signal
─────────────────────────────────────────────────────────────────
Known public exploit exists         × 1.5         CVSS ExploitMaturity = Functional/High
Exploit in active use (CISA KEV)    × 2.0         CISA Known Exploited Vulnerabilities list
No known exploit, theoretical       × 0.5         CVSS ExploitMaturity = Unproven
Requires local access               × 0.7         CVSS AttackVector = Local
Requires user interaction           × 0.8         CVSS UserInteraction = Required
```

**CISA KEV** (Known Exploited Vulnerabilities catalog) — `cisa.gov/known-exploited-vulnerabilities-catalog`. Free JSON download, updated regularly. If a CVE is in this list it means it's being actively exploited in the wild right now. A finding tied to a KEV entry should score much worse than a theoretical finding.

**How the revised penalty formula looks:**
```
base_penalty = severity_penalty (existing: critical=25, high=15, etc.)
final_penalty = base_penalty × exploitability_multiplier
domain_score = max(0, 100 - sum(final_penalty for each finding))
```

**Example:**
- Telnet port open (critical, -25) + active exploit known → penalty becomes -37.5 → domain score drops faster
- Self-signed cert (high, -15) + no known exploit, theoretical → penalty becomes -7.5 → less impact on score

**Impact on your demo:**
Your grades become much more defensible. When someone asks "why did this score an F?" you can say "because three of its findings have active exploits in the CISA KEV catalog, which doubles their penalty weight." That's a real answer, not just "it had a lot of critical findings."

**Effort:** Low-Medium. The multiplier logic in `scoring.py` is a small change. The data sources (CISA KEV JSON, CVSS ExploitMaturity field) are already structured and free to consume. The main work is deciding which signal to use per finding type.

---

## Improvement 3 — SBOM Generation from Static Analyzer

**What the problem is right now:**
Your static analyzer extracts ports, routes, secrets, and TLS config from the codebase. It does not extract the dependency tree — what packages the application uses and what versions. This means you're missing an entire class of vulnerability: known-vulnerable dependencies that the app ships with.

**What the improvement is:**
Extend the static analyzer to generate a lightweight SBOM (Software Bill of Materials) — a structured list of all dependencies found in the codebase — and cross-reference each one against OSV to find known vulnerabilities. This is exactly what Docker Scout does for container images, but you'd do it at the source code level.

**What to parse per language:**
```
TypeScript/JavaScript  →  package.json (dependencies + devDependencies)
Python                 →  requirements.txt, pyproject.toml, Pipfile
Java                   →  pom.xml (Maven), build.gradle (Gradle)
```

**Output added to Attack Surface Manifest:**
```json
"dependencies": [
  {
    "name": "express",
    "version": "4.17.1",
    "ecosystem": "npm",
    "vulnerabilities": [
      {
        "id": "GHSA-rv95-896h-c2vc",
        "cvss_score": 7.5,
        "title": "qs vulnerable to Prototype Poisoning",
        "fixed_in": "4.17.3"
      }
    ]
  }
]
```

**Which API to use:**
OSV API supports batch queries — send all your dependencies in one request, get back all known vulnerabilities. No rate limiting for reasonable use. GitHub Advisory Database is also queryable via the GitHub GraphQL API (free, needs GitHub token).

**Impact on your demo:**
Static analysis goes from "found hardcoded secrets and some routes" to "found hardcoded secrets, routes, and 7 vulnerable dependencies including one with a CVSS 9.8 affecting all versions of lodash < 4.17.21." This is the gap between what you have and what Snyk/Dependabot does — and you'd be doing it as one part of a broader tool.

**Effort:** Medium. Parsing `package.json` and `requirements.txt` is trivial. The OSV batch API is well-documented. The main effort is normalizing package names and versions across ecosystems (npm vs PyPI vs Maven have different naming conventions).

---

## Improvement 4 — CISA KEV Integration as a Finding Enrichment Layer

**What the problem is:**
Right now when your tool finds a vulnerability, it reports it in isolation. There's no signal for whether this vulnerability is being actively exploited by real attackers right now — which is often more important than the theoretical CVSS score.

**What the improvement is:**
Download the CISA Known Exploited Vulnerabilities catalog (a single JSON file, updated daily) and check every CVE-tagged finding against it. If the finding maps to a CVE in the KEV catalog, add a prominent "ACTIVELY EXPLOITED" badge to the finding in the dashboard and apply the ×2.0 scoring multiplier from Improvement 2.

**The data source:**
```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```
Free, no auth, updated daily. Cache it locally at scan time and refresh if older than 24 hours.

**What it looks like in the dashboard:**
```
[CRITICAL] [ACTIVELY EXPLOITED 🔴] Open port 445 (SMB) — EternalBlue
CVE-2017-0144 · CVSS 9.8 · CISA KEV: Added 2021-11-03
"This vulnerability is being actively exploited by ransomware operators."
```

**Impact on your demo:**
This is the single most visually impactful improvement. The "ACTIVELY EXPLOITED" badge on a finding immediately communicates real-world risk in a way that a CVSS number doesn't. Anyone watching the demo — technical or not — understands what that means.

**Effort:** Low. Downloading and caching a JSON file, then doing a CVE ID lookup against it per finding. Maybe 50 lines of code total. Highest impact-to-effort ratio of all improvements listed here.

---

## Improvement 5 — testssl.sh Parity Checklist for TLS Module

**What the problem is:**
Your TLS module is solid based on the PRD spec, but you don't yet know how it compares to `testssl.sh` — the gold standard open source TLS scanner. Until you cross-validate, you don't know what you're missing.

**What the improvement is:**
Run `testssl.sh` against the same BadSSL subdomains your TLS module targets. Compare outputs line by line. For every check testssl.sh does that yours doesn't, decide: implement it, or explicitly document it as out of scope.

**Specific checks testssl.sh does that are likely gaps in yours:**
- ROBOT attack (Return Of Bleichenbacher's Oracle Threat) — RSA PKCS#1 v1.5 padding oracle
- BEAST attack — CBC mode vulnerability in TLS 1.0
- LUCKY13 — timing attack on CBC mode
- BREACH — HTTP compression + TLS combination attack
- FREAK — export-grade RSA key downgrade
- Logjam — weak DH parameters (< 2048 bits)
- DROWN — SSLv2 cross-protocol attack

You don't need to implement all of these — but knowing which ones you're missing lets you either add them or honestly say "we cover the OWASP Top 10 TLS checks, legacy attack vectors like BEAST and ROBOT are out of scope for v1."

**Effort:** Zero code effort — this is a testing and documentation exercise. Run testssl.sh, diff the outputs, update your known limitations section.

---

## Summary Table

| # | Improvement | Impact | Effort | Do when |
|---|---|---|---|---|
| 1 | CVE database enrichment for banner findings | High | Medium | After live testing confirms banner grabbing works |
| 2 | Exploitability multiplier in scoring | High | Low-Medium | After live testing confirms scoring is working |
| 3 | SBOM generation from static analyzer | Medium | Medium | After static analysis is validated on real repos |
| 4 | CISA KEV integration | High | Low | Can do this now — highest ROI |
| 5 | testssl.sh parity checklist | Medium | Zero code | Do before demo — just run and diff |

**Recommended order:** 4 → 5 → 2 → 1 → 3

Start with CISA KEV (4) because it's low effort, high visual impact, and works on your existing findings without changing any probe logic. Then do the testssl.sh diff (5) to know your TLS gaps before the demo. Then scoring multiplier (2) to make your grades more defensible. CVE enrichment (1) and SBOM (3) are the bigger ones for after the demo.
