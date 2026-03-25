"""Unit tests for the network probe module."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netsentinel.models import AttackSurfaceManifest, PortEntry
from netsentinel.probes.network import (
    ICMPResult,
    PortResult,
    calculate_cvss_for_port,
    check_undeclared_ports,
    classify_ports,
    generate_cvss_vector,
    get_cvss_breakdown,
    get_icmp_summary,
    get_open_ports_summary,
    get_port_description,
    get_port_remediation,
    grab_banner,
    grab_banners,
    probe_icmp,
    probe_network,
    scan_port,
    scan_tcp_ports,
)


class TestPortResult:
    """Tests for PortResult dataclass."""

    def test_port_result_creation(self):
        """Test creating a PortResult."""
        result = PortResult(port=80, status="open")
        assert result.port == 80
        assert result.status == "open"
        assert result.banner is None

    def test_port_result_with_banner(self):
        """Test PortResult with banner."""
        result = PortResult(port=22, status="open", banner="SSH-2.0-OpenSSH")
        assert result.port == 22
        assert result.status == "open"
        assert result.banner == "SSH-2.0-OpenSSH"


class TestICMPResult:
    """Tests for ICMPResult dataclass."""

    def test_icmp_result_alive(self):
        """Test alive ICMP result."""
        result = ICMPResult(alive=True, ttl=64, os_hint="Linux/Unix", latency_ms=1.5)
        assert result.alive is True
        assert result.ttl == 64
        assert result.os_hint == "Linux/Unix"
        assert result.latency_ms == 1.5

    def test_icmp_result_dead(self):
        """Test dead host ICMP result."""
        result = ICMPResult(alive=False)
        assert result.alive is False
        assert result.ttl is None
        assert result.os_hint is None


class TestCVSSHelpers:
    """Tests for CVSS helper functions."""

    def test_calculate_cvss_for_known_port(self):
        """Test CVSS calculation for known dangerous ports."""
        assert calculate_cvss_for_port(23) == 9.1  # Telnet - critical
        assert calculate_cvss_for_port(445) == 9.8  # SMB - critical
        assert calculate_cvss_for_port(21) == 7.5  # FTP - high

    def test_calculate_cvss_for_unknown_port(self):
        """Test CVSS calculation for unknown port."""
        assert calculate_cvss_for_port(12345) == 5.3  # Default medium

    def test_generate_cvss_vector_for_known_port(self):
        """Test CVSS vector generation for known port."""
        vector = generate_cvss_vector(23)
        assert vector.startswith("CVSS:3.1/")
        assert "AV:N" in vector  # Network attack vector

    def test_generate_cvss_vector_for_unknown_port(self):
        """Test CVSS vector generation for unknown port."""
        vector = generate_cvss_vector(99999)
        assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

    def test_get_cvss_breakdown(self):
        """Test CVSS breakdown retrieval."""
        breakdown = get_cvss_breakdown(23)
        assert breakdown.attack_vector == "Network"
        assert breakdown.attack_complexity == "Low"
        assert breakdown.confidentiality == "High"

    def test_get_port_description_known(self):
        """Test port description for known port."""
        desc = get_port_description(23, "Telnet")
        assert "Telnet" in desc
        assert "plaintext" in desc.lower()

    def test_get_port_description_unknown(self):
        """Test port description for unknown port."""
        desc = get_port_description(12345, "Unknown")
        assert "Unknown" in desc
        assert "12345" in desc

    def test_get_port_remediation_known(self):
        """Test remediation for known port."""
        remediation = get_port_remediation(23)
        assert "SSH" in remediation
        assert "Disable" in remediation

    def test_get_port_remediation_unknown(self):
        """Test remediation for unknown port."""
        remediation = get_port_remediation(12345)
        assert "12345" in remediation
        assert "firewall" in remediation.lower()


class TestScanPort:
    """Tests for scan_port function."""

    @pytest.mark.asyncio
    async def test_scan_port_open(self):
        """Test scanning an open port."""
        with patch("asyncio.open_connection") as mock_conn:
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_conn.return_value = (MagicMock(), mock_writer)

            result = await scan_port("127.0.0.1", 80, timeout=1.0)

            assert result.port == 80
            assert result.status == "open"

    @pytest.mark.asyncio
    async def test_scan_port_closed(self):
        """Test scanning a closed port."""
        with patch("asyncio.open_connection") as mock_conn:
            mock_conn.side_effect = ConnectionRefusedError()

            result = await scan_port("127.0.0.1", 81, timeout=1.0)

            assert result.port == 81
            assert result.status == "closed"

    @pytest.mark.asyncio
    async def test_scan_port_filtered(self):
        """Test scanning a filtered port (timeout)."""
        with patch("asyncio.open_connection") as mock_conn:
            mock_conn.side_effect = asyncio.TimeoutError()

            result = await scan_port("127.0.0.1", 82, timeout=1.0)

            assert result.port == 82
            assert result.status == "filtered"


class TestScanTCPPorts:
    """Tests for scan_tcp_ports function."""

    @pytest.mark.asyncio
    async def test_scan_tcp_ports_returns_open_only(self):
        """Test that scan_tcp_ports returns only open ports."""
        with patch("netsentinel.probes.network.scan_port") as mock_scan:
            # Simulate mixed results
            async def fake_scan(host, port, timeout):
                if port == 80:
                    return PortResult(80, "open")
                elif port == 81:
                    return PortResult(81, "closed")
                else:
                    return PortResult(port, "filtered")

            mock_scan.side_effect = fake_scan

            results = await scan_tcp_ports("127.0.0.1", [80, 81, 82], concurrency=10)

            assert len(results) == 1
            assert results[0].port == 80
            assert results[0].status == "open"


class TestClassifyPorts:
    """Tests for classify_ports function."""

    def test_classify_dangerous_port(self):
        """Test classification of dangerous ports."""
        open_ports = [PortResult(port=23, status="open")]
        banners = {23: "Linux telnetd"}
        scan_id = "test-scan-123"

        findings = classify_ports(open_ports, banners, scan_id)

        assert len(findings) == 1
        assert findings[0].domain == "network"
        assert "Telnet" in findings[0].title
        assert findings[0].severity == "critical"
        assert findings[0].cvss_score == 9.1
        assert findings[0].evidence.banner == "Linux telnetd"

    def test_classify_multiple_dangerous_ports(self):
        """Test classification of multiple dangerous ports."""
        open_ports = [
            PortResult(port=23, status="open"),
            PortResult(port=21, status="open"),
            PortResult(port=80, status="open"),  # Not dangerous
        ]
        banners = {}
        scan_id = "test-scan-456"

        findings = classify_ports(open_ports, banners, scan_id)

        assert len(findings) == 2  # Only 23 and 21 are dangerous
        ports_found = {f.evidence.raw_request.split()[-1] for f in findings}
        assert "23" in ports_found
        assert "21" in ports_found

    def test_classify_non_dangerous_port(self):
        """Test that non-dangerous ports don't generate findings."""
        open_ports = [PortResult(port=80, status="open")]
        banners = {}
        scan_id = "test-scan-789"

        findings = classify_ports(open_ports, banners, scan_id)

        assert len(findings) == 0


class TestCheckUndeclaredPorts:
    """Tests for check_undeclared_ports function."""

    def test_detect_undeclared_port(self):
        """Test detection of undeclared ports."""
        open_ports = [
            PortResult(port=80, status="open"),
            PortResult(port=8080, status="open"),
        ]

        manifest = AttackSurfaceManifest(
            scan_id="test",
            target="test-target",
            extracted_at="2024-01-01T00:00:00Z",
            ports=[PortEntry(port=80, protocol="tcp", source_file="docker-compose.yml", line=10)],
        )

        findings = check_undeclared_ports(open_ports, manifest, "test-scan")

        assert len(findings) == 1
        assert findings[0].title == "Undeclared open port 8080 detected"
        assert findings[0].severity == "medium"

    def test_no_undeclared_ports(self):
        """Test when all ports are declared."""
        open_ports = [PortResult(port=80, status="open")]

        manifest = AttackSurfaceManifest(
            scan_id="test",
            target="test-target",
            extracted_at="2024-01-01T00:00:00Z",
            ports=[PortEntry(port=80, protocol="tcp", source_file="Dockerfile", line=5)],
        )

        findings = check_undeclared_ports(open_ports, manifest, "test-scan")

        assert len(findings) == 0


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_get_open_ports_summary_empty(self):
        """Test summary for no open ports."""
        summary = get_open_ports_summary([])
        assert summary == "No open ports detected"

    def test_get_open_ports_summary_with_ports(self):
        """Test summary with open ports."""
        ports = [
            PortResult(port=443, status="open"),
            PortResult(port=80, status="open"),
            PortResult(port=22, status="open"),
        ]
        summary = get_open_ports_summary(ports)
        assert "3 open ports" in summary
        assert "22" in summary
        assert "80" in summary
        assert "443" in summary

    def test_get_icmp_summary_dead(self):
        """Test ICMP summary for dead host."""
        result = ICMPResult(alive=False)
        summary = get_icmp_summary(result)
        assert "down" in summary.lower() or "filtered" in summary.lower()

    def test_get_icmp_summary_alive(self):
        """Test ICMP summary for alive host."""
        result = ICMPResult(alive=True, ttl=64, os_hint="Linux/Unix", latency_ms=1.5)
        summary = get_icmp_summary(result)
        assert "up" in summary.lower()
        assert "TTL=64" in summary
        assert "Linux/Unix" in summary
        assert "1.5ms" in summary


class TestProbeNetwork:
    """Tests for the main probe_network function."""

    @pytest.mark.asyncio
    async def test_probe_network_integration(self):
        """Test probe_network orchestration with mocked components."""
        with patch("netsentinel.probes.network.probe_icmp") as mock_icmp, \
             patch("netsentinel.probes.network.scan_tcp_ports") as mock_tcp, \
             patch("netsentinel.probes.network.scan_udp_ports") as mock_udp, \
             patch("netsentinel.probes.network.grab_banners") as mock_banners:

            mock_icmp.return_value = ICMPResult(alive=True, ttl=64, os_hint="Linux/Unix")
            mock_tcp.return_value = [PortResult(port=23, status="open")]
            mock_udp.return_value = []
            mock_banners.return_value = {23: "Linux telnetd"}

            findings = await probe_network(
                host="127.0.0.1",
                scan_id="test-scan",
                ports=[22, 23, 80],
            )

            # Should have at least one finding for Telnet
            assert len(findings) >= 1
            telnet_finding = next((f for f in findings if "Telnet" in f.title), None)
            assert telnet_finding is not None
            assert telnet_finding.severity == "critical"

    @pytest.mark.asyncio
    async def test_probe_network_with_manifest(self):
        """Test probe_network with manifest cross-checking."""
        with patch("netsentinel.probes.network.probe_icmp") as mock_icmp, \
             patch("netsentinel.probes.network.scan_tcp_ports") as mock_tcp, \
             patch("netsentinel.probes.network.scan_udp_ports") as mock_udp, \
             patch("netsentinel.probes.network.grab_banners") as mock_banners:

            mock_icmp.return_value = ICMPResult(alive=True)
            mock_tcp.return_value = [
                PortResult(port=80, status="open"),
                PortResult(port=8080, status="open"),  # Undeclared
            ]
            mock_udp.return_value = []
            mock_banners.return_value = {}

            manifest = AttackSurfaceManifest(
                scan_id="test",
                target="test-target",
                extracted_at="2024-01-01T00:00:00Z",
                ports=[PortEntry(port=80, protocol="tcp", source_file="docker-compose.yml", line=10)],
            )

            findings = await probe_network(
                host="127.0.0.1",
                scan_id="test-scan",
                manifest=manifest,
                ports=[80, 8080],
            )

            # Should have finding for undeclared port 8080
            undeclared = [f for f in findings if "Undeclared" in f.title]
            assert len(undeclared) == 1
            assert "8080" in undeclared[0].title
