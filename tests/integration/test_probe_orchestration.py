"""Integration tests for probe orchestration."""
import queue
from typing import List
from unittest.mock import AsyncMock, patch

import pytest

from netsentinel.models import AttackSurfaceManifest, Finding, PortEntry, ScanConfig
from netsentinel.probes.engine import run_live_probes, _network_thread, _tls_thread


@pytest.fixture
def test_manifest() -> AttackSurfaceManifest:
    """Create a test manifest."""
    from datetime import datetime
    return AttackSurfaceManifest(
        scan_id="test-scan-001",
        target="192.0.2.1",
        extracted_at=datetime.now().isoformat(),
        language_detected=["python"],
        ports=[
            PortEntry(port=22, protocol="tcp", source_file="app.py", line=1),
            PortEntry(port=443, protocol="tcp", source_file="Dockerfile", line=5),
        ],
        routes=[],
        secrets_found=[],
        outbound_hosts=[],
    )


@pytest.fixture
def test_config() -> ScanConfig:
    """Create test config."""
    return ScanConfig(
        scan_id="test-scan-001",
        target_path="/test/repo",
        target_host="192.0.2.1",
        live_probe=True,
        static_only=False,
        live_only=False,
        top_ports=100,
        custom_ports=None,
        timeout=30.0,
        concurrency=50,
    )


@pytest.mark.integration
@pytest.mark.asyncio
class TestProbeOrchestration:
    """Test probe orchestration."""

    async def test_all_probes_run_concurrently(
        self, test_config: ScanConfig, test_manifest: AttackSurfaceManifest
    ) -> None:
        """Test that all probes run concurrently."""
        with patch('netsentinel.probes.network.probe_network', new_callable=AsyncMock) as mock_net:
            with patch('netsentinel.probes.tls_probe.probe_tls') as mock_tls:
                with patch('netsentinel.probes.http_probe.probe_http') as mock_http:
                    with patch('netsentinel.probes.dns_probe.probe_dns', new_callable=AsyncMock) as mock_dns:
                        mock_net.return_value = []
                        mock_tls.return_value = []
                        mock_http.return_value = []
                        mock_dns.return_value = []
                        
                        findings = await run_live_probes(config=test_config, manifest=test_manifest)
                        
                        assert mock_net.called
                        assert mock_tls.called
                        assert mock_http.called
                        assert mock_dns.called
                        assert isinstance(findings, list)


@pytest.mark.integration
class TestIndividualThreadFunctions:
    """Test individual thread workers."""

    def test_network_thread_worker(self, test_manifest: AttackSurfaceManifest) -> None:
        """Test network thread worker."""
        findings_queue = queue.Queue()
        
        with patch('netsentinel.probes.network.probe_network', new_callable=AsyncMock) as mock_probe:
            mock_probe.return_value = [
                Finding(
                    id="net-1",
                    domain="network",
                    title="Test finding",
                    severity="low",
                    cvss_score=3.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    owasp_id="A05",
                    description="Test",
                )
            ]
            
            _network_thread(
                findings_queue=findings_queue,
                host="192.0.2.1",
                scan_id="test-scan",
                manifest=test_manifest,
                ports_to_scan=[22, 80, 443],
            )
            
            assert findings_queue.qsize() == 1

    def test_tls_thread_worker(self) -> None:
        """Test TLS thread worker."""
        findings_queue = queue.Queue()
        
        with patch('netsentinel.probes.tls_probe.probe_tls') as mock_probe:
            mock_probe.return_value = [
                Finding(
                    id="tls-1",
                    domain="tls",
                    title="TLS issue",
                    severity="medium",
                    cvss_score=5.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    owasp_id="A02",
                    description="Test",
                )
            ]
            
            _tls_thread(
                findings_queue=findings_queue,
                host="192.0.2.1",
                scan_id="test-scan",
                tls_ports=[443, 8443],
            )
            
            assert mock_probe.call_count == 2
            assert findings_queue.qsize() == 2
