"""Groq AI client for NetSentinel AI features."""
import json
import logging
import os

logger = logging.getLogger(__name__)

try:
    from groq import Groq
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False
    logger.warning("groq not installed — AI features disabled. Run: pip install groq")

MODELS = {
    "flash": "openai/gpt-oss-120b",
    "pro":   "openai/gpt-oss-120b",
    "lite":  "openai/gpt-oss-120b",
}
DEFAULT_MODEL = MODELS["flash"]


def _client():
    if not _AVAILABLE:
        raise RuntimeError("groq package not installed. Run: pip install groq")
    key = os.getenv("GROQ_API_KEY", "")
    if not key or key == "your_groq_api_key_here":
        raise RuntimeError("GROQ_API_KEY not configured. Add your key to the .env file.")
    return Groq(api_key=key)


def _top_findings(scan: dict, n: int = 5) -> str:
    findings = scan.get("findings", [])[:n]
    lines = []
    for f in findings:
        if isinstance(f, dict):
            sev   = f.get("severity", "unknown").upper()
            title = f.get("title", "Unknown finding")
            desc  = (f.get("description") or "")[:100]
            lines.append(f"  [{sev}] {title}: {desc}")
    return "\n".join(lines) or "  None"


def _gen(prompt: str, model_name: str = DEFAULT_MODEL) -> str:
    c = _client()
    resp = c.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1024,
    )
    return resp.choices[0].message.content


def explain_widget(widget_type: str, data: dict, scan: dict, model_name: str = DEFAULT_MODEL) -> str:
    """Explain a single dashboard widget in security analyst language."""
    ctx = {
        "target":  scan.get("target") or "N/A",
        "host":    scan.get("host")   or "N/A",
        "grade":   (scan.get("scores") or {}).get("grade", "N/A"),
        "overall": (scan.get("scores") or {}).get("weighted_overall", 0),
    }
    prompt = f"""You are NetSentinel's senior security analyst. Explain this dashboard metric clearly.

Widget: {widget_type}
Data: {json.dumps(data, indent=2)}
Scan context: {json.dumps(ctx, indent=2)}
Top findings:
{_top_findings(scan)}

Provide exactly:
1. What this metric measures (1 sentence)
2. What the current value means for this target (2 sentences, be specific)
3. Top 2 issues found (bullet points, or "None found" if clean)
4. Single most important recommended action

Under 160 words. No emojis. Professional security tone."""
    try:
        return _gen(prompt, model_name)
    except Exception as e:
        logger.error(f"explain_widget failed: {e}")
        return f"AI explanation unavailable: {e}"


def chat(message: str, history: list, scan: dict, model_name: str = DEFAULT_MODEL) -> str:
    """Context-aware multi-turn chat about a scan."""
    scores  = scan.get("scores") or {}
    summary = scan.get("summary") or {}
    by_sev  = summary.get("by_severity") or {}

    system_content = f"""You are NetSentinel's AI security analyst. Answer questions about this scan precisely.

Scan: {scan.get("target") or "N/A"} / {scan.get("host") or "N/A"}
Grade: {scores.get("grade", "N/A")}  Overall: {scores.get("weighted_overall", 0):.0f}/100
Scores — Network: {scores.get("network", 0)}, TLS: {scores.get("tls", 0)}, HTTP: {scores.get("http", 0)}, DNS: {scores.get("dns", 0)}
Findings — Critical: {by_sev.get("critical", 0)}, High: {by_sev.get("high", 0)}, Medium: {by_sev.get("medium", 0)}, Low: {by_sev.get("low", 0)}

Top findings:
{_top_findings(scan, 8)}

Be specific, actionable, professional. Reference actual findings. No emojis."""

    messages = [{"role": "system", "content": system_content}]
    for msg in (history or [])[-12:]:
        role = "user" if msg["role"] == "user" else "assistant"
        messages.append({"role": role, "content": msg["content"]})
    messages.append({"role": "user", "content": message})

    try:
        c = _client()
        resp = c.chat.completions.create(
            model=model_name,
            messages=messages,
            max_tokens=1024,
        )
        return resp.choices[0].message.content
    except Exception as e:
        logger.error(f"chat failed: {e}")
        return f"AI unavailable: {e}"


def compare_scans(scan1: dict, scan2: dict, model_name: str = DEFAULT_MODEL) -> str:
    """Generate AI analysis comparing two scans."""
    def _brief(s: dict) -> dict:
        sc  = s.get("scores") or {}
        su  = s.get("summary") or {}
        bsv = su.get("by_severity") or {}
        return {
            "target":   s.get("target") or "N/A",
            "host":     s.get("host")   or "N/A",
            "date":     (s.get("completed_at") or "")[:10],
            "grade":    sc.get("grade", "N/A"),
            "overall":  round(sc.get("weighted_overall", 0)),
            "network":  sc.get("network", 0),
            "tls":      sc.get("tls", 0),
            "http":     sc.get("http", 0),
            "dns":      sc.get("dns", 0),
            "total":    su.get("total_findings", 0),
            "critical": bsv.get("critical", 0),
            "high":     bsv.get("high", 0),
        }

    prompt = f"""You are NetSentinel's AI analyst. Compare these two security scans professionally.

Scan A: {json.dumps(_brief(scan1), indent=2)}
Scan B: {json.dumps(_brief(scan2), indent=2)}

Structure your response with these exact sections:

**Overall Assessment** (2-3 sentences)

**Improvements** (what improved and why it matters)

**Regressions** (what degraded and the security risk introduced)

**Domain Analysis** (brief per-domain: Network, TLS, HTTP, DNS)

**Priority Actions** (numbered top 3 actions to close the gap)

Under 450 words. No emojis. Professional executive tone."""
    try:
        return _gen(prompt, model_name)
    except Exception as e:
        logger.error(f"compare_scans failed: {e}")
        return f"AI comparison unavailable: {e}"


def generate_report_narrative(scan: dict, model_name: str = DEFAULT_MODEL) -> str:
    """Generate executive summary text for the PDF report."""
    scores  = scan.get("scores") or {}
    summary = scan.get("summary") or {}
    by_sev  = summary.get("by_severity") or {}

    prompt = f"""You are writing an executive security report for NetSentinel.

Target: {scan.get("target") or "N/A"}
Host: {scan.get("host") or "N/A"}
Date: {(scan.get("completed_at") or "")[:10]}
Grade: {scores.get("grade", "N/A")}  Score: {scores.get("weighted_overall", 0):.0f}/100
Network: {scores.get("network", 0)}  TLS: {scores.get("tls", 0)}  HTTP: {scores.get("http", 0)}  DNS: {scores.get("dns", 0)}
Critical: {by_sev.get("critical", 0)}  High: {by_sev.get("high", 0)}  Medium: {by_sev.get("medium", 0)}  Total: {summary.get("total_findings", 0)}

Top findings:
{_top_findings(scan, 10)}

Write a professional report with these sections:

**Executive Summary**
(3-4 sentences: overall posture, primary risk, business impact, urgency)

**Key Risk Areas**
(4-5 bullet points on the most critical findings)

**Recommended Actions**
(Numbered priority list of top 5 remediations)

**Risk Assessment**
(1 paragraph on business impact if issues remain unaddressed)

Under 500 words. Formal tone for C-level and security teams. No emojis."""
    try:
        return _gen(prompt, model_name)
    except Exception as e:
        logger.error(f"generate_report_narrative failed: {e}")
        return f"AI narrative unavailable. Check GROQ_API_KEY.\n\nError: {e}"
