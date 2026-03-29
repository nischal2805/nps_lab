"""Integration tests for the complete scan workflow."""
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

import pytest

from netsentinel.models import AttackSurfaceManifest, Finding, PortEntry, SecretEntry
from netsentinel.probes.engine import run_live_probes
from netsentinel.scoring import generate_score_report
from netsentinel.static_analyzer import analyze


@pytest.mark.integration
class TestFullScanWorkflow:
    """Test complete scan workflow end-to-end."""

    def test_static_analysis_to_scoring(self, tmp_path: Path) -> None:
        """Test complete workflow from static analysis to scoring."""
        # 1. Create test repo
        (tmp_path / "app.py").write_text("""
API_KEY = "sk-test-key-123"
app.run(port=8080)
""")
        
        # 2. Run static analysis
        scan_id = str(uuid.uuid4())
        manifest = analyze(str(tmp_path), scan_id)
        
        # 3. Verify manifest
        assert isinstance(manifest, AttackSurfaceManifest)
        assert manifest.scan_id == scan_id
        
        # 4. Create findings
        findings = [Finding(
            id="f1",
            domain="network",
            title="Open port",
            severity="medium",
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            owasp_id="A05",
            description="Test finding",
        )]
        
        # 5. Score
        report = generate_score_report(findings)
        assert report is not None
        assert 'scores' in report
        assert 0 <= report['scores']['weighted_overall'] <= 100

    @pytest.mark.asyncio
    async def test_full_pipeline_with_mocked_probes(self, tmp_path: Path) -> None:
        """Test full pipeline with mocked probes."""
        from netsentinel.models import ScanConfig
        
        (tmp_path / "app.py").write_text("print('test')")
        scan_id = str(uuid.uuid4())
        manifest = analyze(str(tmp_path), scan_id)
        
        config = ScanConfig(
            scan_id=scan_id,
            target_path=str(tmp_path),
            target_host="192.0.2.1",
            live_probe=True,
            static_only=False,
            live_only=False,
            top_ports=100,
            custom_ports=None,
            timeout=30.0,
            concurrency=50,
        )
        
        with patch('netsentinel.probes.network.probe_network', new_callable=AsyncMock) as mock_net:
            with patch('netsentinel.probes.tls_probe.probe_tls') as mock_tls:
                with patch('netsentinel.probes.http_probe.probe_http') as mock_http:
                    with patch('netsentinel.probes.dns_probe.probe_dns', new_callable=AsyncMock) as mock_dns:
                        mock_net.return_value = []
                        mock_tls.return_value = []
                        mock_http.return_value = []
                        mock_dns.return_value = []
                        
                        findings = await run_live_probes(config=config, manifest=manifest)
                        assert isinstance(findings, list)

    def test_error_handling(self) -> None:
        """Test error handling."""
        with pytest.raises(ValueError):
            analyze("/nonexistent/path", str(uuid.uuid4()))
        
        report = generate_score_report([])
        assert report['summary']['total_findings'] == 0
