"""Flask dashboard server for NetSentinel."""
import asyncio
import json
import logging
import threading
import uuid
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Optional

from flask import Flask, Response, jsonify, request, send_file

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent.parent / '.env')

logger = logging.getLogger(__name__)

DASHBOARD_DIR = Path(__file__).parent
STORAGE_DIR   = Path.home() / '.netsentinel'

app = Flask(__name__, static_folder=None)
app.config['JSON_SORT_KEYS'] = False

# In-memory job tracker  {job_id: {status, step, progress, scan_id, error}}
_jobs: dict = {}
_jobs_lock = threading.Lock()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _job_update(job_id: str, **kw):
    with _jobs_lock:
        _jobs.setdefault(job_id, {}).update(kw)


def _load_scan(scan_id: str) -> Optional[dict]:
    f = STORAGE_DIR / 'scans' / f'{scan_id}.json'
    if not f.exists():
        return None
    return json.loads(f.read_text('utf-8'))


def _list_scans() -> list:
    idx = STORAGE_DIR / 'index.json'
    if not idx.exists():
        return []
    return json.loads(idx.read_text('utf-8'))


# ── Background scan worker ────────────────────────────────────────────────────

def _run_scan_job(job_id: str, body: dict):
    try:
        from netsentinel.models import ScanConfig, ScanResult, Scores, ScoreSummary, OWASPCoverage
        from netsentinel.static_analyzer import analyze_with_findings
        from netsentinel.probes.engine import run_live_probes
        from netsentinel.scoring import generate_score_report

        target    = body.get('target') or None
        host      = body.get('host') or None
        scan_type = body.get('type', 'both')

        if not target:
            target = None
        if not host:
            host = None

        # Parse host:port
        port = None
        if host and ':' in host:
            try:
                h, p = host.rsplit(':', 1)
                port = int(p)
                host = h
            except ValueError:
                pass

        config = ScanConfig(
            target=target if scan_type in ('static', 'both') else None,
            host=host   if scan_type in ('live',   'both') else None,
            port=port,
            live_only=(scan_type == 'live'),
            static_only=(scan_type == 'static'),
        )

        errors = config.validate()
        if errors:
            _job_update(job_id, status='error', error='; '.join(errors))
            return

        _job_update(job_id, status='running', step='Initializing…', progress=5)

        manifest   = None
        findings   = []
        started_at = datetime.utcnow().isoformat() + 'Z'

        if config.requires_static_analysis:
            _job_update(job_id, step='Running static analysis…', progress=15)
            manifest, static_findings = analyze_with_findings(config.target, config.scan_id)
            findings.extend(static_findings)
            _job_update(job_id, step=f'Static analysis done ({len(static_findings)} findings)', progress=50)

        if config.requires_live_probing:
            _job_update(job_id, step='Running live probes (network / TLS / HTTP / DNS)…', progress=55)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                live_findings = loop.run_until_complete(run_live_probes(config, manifest))
                findings = live_findings
            finally:
                loop.close()
            _job_update(job_id, step=f'Live probes done ({len(findings)} findings)', progress=80)

        _job_update(job_id, step='Calculating security scores…', progress=88)
        score_report  = generate_score_report(findings)
        scores        = Scores(**score_report['scores'])
        summary       = ScoreSummary(**score_report['summary'])
        owasp_coverage = [OWASPCoverage(**item) for item in score_report['owasp_coverage']]

        completed_at = datetime.utcnow().isoformat() + 'Z'
        start_dt = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
        end_dt   = datetime.fromisoformat(completed_at.replace('Z', '+00:00'))
        duration = (end_dt - start_dt).total_seconds()

        STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        (STORAGE_DIR / 'scans').mkdir(parents=True, exist_ok=True)

        result = ScanResult(
            scan_id=config.scan_id,
            target=config.target,
            host=config.host,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            manifest=manifest.to_dict() if manifest else None,
            findings=[f.to_dict() if hasattr(f, 'to_dict') else f for f in findings],
            scores=scores,
            owasp_coverage=owasp_coverage,
            summary=summary,
        )
        result.save(str(STORAGE_DIR))

        _job_update(job_id, status='complete', scan_id=config.scan_id, progress=100, step='Scan complete')

    except Exception as exc:
        logger.exception(f'Scan job {job_id} failed')
        _job_update(job_id, status='error', error=str(exc))


# ── Static file routes ────────────────────────────────────────────────────────

@app.route('/')
def index():
    f = DASHBOARD_DIR / 'landing.html'
    return Response(f.read_text('utf-8'), mimetype='text/html')


@app.route('/dashboard')
def dashboard():
    f = DASHBOARD_DIR / 'dashboard.html'
    return Response(f.read_text('utf-8'), mimetype='text/html')


@app.route('/logo.png')
def logo():
    f = DASHBOARD_DIR / 'logo.png'
    if f.exists():
        return send_file(str(f), mimetype='image/png')
    return '', 404


# ── Scan API ──────────────────────────────────────────────────────────────────

@app.route('/api/scans')
def list_scans():
    return jsonify(_list_scans())


@app.route('/api/scans/<scan_id>')
def get_scan(scan_id: str):
    data = _load_scan(scan_id)
    if data is None:
        return jsonify({'error': f'Scan not found: {scan_id}'}), 404
    return jsonify(data)


@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    body = request.get_json(force=True) or {}
    job_id = str(uuid.uuid4())
    _job_update(job_id, status='queued', step='Queued', progress=0)
    t = threading.Thread(target=_run_scan_job, args=(job_id, body), daemon=True)
    t.start()
    return jsonify({'job_id': job_id})


@app.route('/api/jobs/<job_id>')
def job_status(job_id: str):
    with _jobs_lock:
        job = dict(_jobs.get(job_id, {}))
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify(job)


# ── AI routes ─────────────────────────────────────────────────────────────────

@app.route('/api/explain', methods=['POST'])
def explain():
    body = request.get_json(force=True) or {}
    scan_id     = body.get('scan_id', '')
    widget_type = body.get('widget_type', 'unknown')
    data        = body.get('data', {})
    model_name  = body.get('model', '')

    scan = _load_scan(scan_id) or {}

    from netsentinel.dashboard.gemini_client import explain_widget, DEFAULT_MODEL
    text = explain_widget(widget_type, data, scan, model_name or DEFAULT_MODEL)
    return jsonify({'explanation': text})


@app.route('/api/chat', methods=['POST'])
def chat():
    body       = request.get_json(force=True) or {}
    scan_id    = body.get('scan_id', '')
    message    = body.get('message', '')
    history    = body.get('history', [])
    model_name = body.get('model', '')

    scan = _load_scan(scan_id) or {}

    from netsentinel.dashboard.gemini_client import chat as ai_chat, DEFAULT_MODEL
    text = ai_chat(message, history, scan, model_name or DEFAULT_MODEL)
    return jsonify({'response': text})


@app.route('/api/compare', methods=['POST'])
def compare():
    body = request.get_json(force=True) or {}
    id1  = body.get('scan_id_1', '')
    id2  = body.get('scan_id_2', '')
    model_name = body.get('model', '')

    scan1 = _load_scan(id1)
    scan2 = _load_scan(id2)

    if not scan1 or not scan2:
        return jsonify({'error': 'One or both scans not found'}), 404

    from netsentinel.dashboard.gemini_client import compare_scans, DEFAULT_MODEL
    text = compare_scans(scan1, scan2, model_name or DEFAULT_MODEL)
    return jsonify({'analysis': text})


# ── PDF route ─────────────────────────────────────────────────────────────────

@app.route('/api/scans/<scan_id>/pdf')
def download_pdf(scan_id: str):
    scan = _load_scan(scan_id)
    if scan is None:
        return jsonify({'error': 'Scan not found'}), 404

    # Try AI narrative (non-fatal if fails)
    narrative = None
    try:
        from netsentinel.dashboard.gemini_client import generate_report_narrative
        narrative = generate_report_narrative(scan)
    except Exception as e:
        logger.warning(f'AI narrative skipped: {e}')

    from netsentinel.dashboard.pdf_generator import generate_pdf
    pdf_bytes = generate_pdf(scan, narrative)

    safe_id = scan_id[:8]
    return Response(
        pdf_bytes,
        mimetype='application/pdf',
        headers={'Content-Disposition': f'attachment; filename="netsentinel-{safe_id}.pdf"'},
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def start_server(port: int = 8742, open_browser: bool = True):
    """Start the Flask dashboard server. Called from CLI."""
    if open_browser:
        def _open():
            import time; time.sleep(0.8)
            webbrowser.open(f'http://localhost:{port}')
        threading.Thread(target=_open, daemon=True).start()

    # Suppress Flask dev-server banner
    import logging as _logging
    _logging.getLogger('werkzeug').setLevel(_logging.WARNING)

    app.run(host='0.0.0.0', port=port, threaded=True, use_reloader=False)


if __name__ == '__main__':
    start_server()
