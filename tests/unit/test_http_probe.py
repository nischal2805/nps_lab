"""
Unit tests for HTTP probe module.

Tests cover:
- Security headers detection
- CORS misconfiguration detection
- Cookie security checks
- HTTP methods enumeration
- Scheme detection (http vs https)
"""
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

import httpx

from netsentinel.probes.http_probe import (
    probe_http,
    check_security_headers,
    check_cors,
    check_cookie_security,
    check_http_methods,
    check_sensitive_paths,
    check_info_leakage,
    _determine_scheme,
    HTTPS_PORTS,
)


class TestSchemeDetection:
    """Test HTTP/HTTPS scheme detection based on port."""

    def test_port_443_uses_https(self):
        """Port 443 should use HTTPS."""
        assert _determine_scheme(443) == 'https'

    def test_port_8443_uses_https(self):
        """Port 8443 should use HTTPS."""
        assert _determine_scheme(8443) == 'https'

    def test_port_4443_uses_https(self):
        """Port 4443 should use HTTPS."""
        assert _determine_scheme(4443) == 'https'

    def test_port_9443_uses_https(self):
        """Port 9443 should use HTTPS."""
        assert _determine_scheme(9443) == 'https'

    def test_port_80_uses_http(self):
        """Port 80 should use HTTP."""
        assert _determine_scheme(80) == 'http'

    def test_port_8080_uses_http(self):
        """Port 8080 should use HTTP."""
        assert _determine_scheme(8080) == 'http'

    def test_port_3000_uses_http(self):
        """Port 3000 (dev server) should use HTTP."""
        assert _determine_scheme(3000) == 'http'


class TestSecurityHeaders:
    """Test security header detection."""

    def test_missing_security_headers(self):
        """Test detection of missing security headers."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.headers = {}  # No security headers
        mock_client.get.return_value = mock_response

        findings = check_security_headers(
            mock_client,
            'http://example.com:80',
            ['/'],
            'test-scan-id'
        )

        # Should find missing headers
        assert len(findings) > 0
        titles = [f.title for f in findings]
        assert any('Content-Security-Policy' in t for t in titles)
        assert any('X-Frame-Options' in t for t in titles)

    def test_present_security_headers(self):
        """Test that present headers are not flagged."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.headers = {
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'strict-origin',
            'Permissions-Policy': 'geolocation=()',
            'Strict-Transport-Security': 'max-age=31536000',
        }
        mock_client.get.return_value = mock_response

        findings = check_security_headers(
            mock_client,
            'http://example.com:80',
            ['/'],
            'test-scan-id'
        )

        # Should not find any missing header issues
        missing_header_findings = [f for f in findings if 'Missing' in f.title]
        assert len(missing_header_findings) == 0

    def test_weak_csp_detected(self):
        """Test detection of weak CSP with default-src *."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.headers = {
            'content-security-policy': "default-src *",
        }
        mock_client.get.return_value = mock_response

        findings = check_security_headers(
            mock_client,
            'http://example.com:80',
            ['/'],
            'test-scan-id'
        )

        # Should find weak CSP
        csp_findings = [f for f in findings if 'Weak CSP' in f.title]
        assert len(csp_findings) > 0


class TestCORS:
    """Test CORS misconfiguration detection."""

    def test_cors_wildcard_detection(self):
        """Test detection of CORS wildcard origin."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'false',
        }
        mock_client.get.return_value = mock_response

        findings = check_cors(
            mock_client,
            'http://example.com:80',
            ['/api'],
            'test-scan-id'
        )

        # Should find wildcard CORS issue
        cors_findings = [f for f in findings if 'CORS' in f.title]
        assert len(cors_findings) > 0

    def test_cors_reflection_detection(self):
        """Test detection of arbitrary origin reflection."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.headers = {
            'Access-Control-Allow-Origin': 'https://evil.com',
            'Access-Control-Allow-Credentials': 'true',
        }
        mock_client.get.return_value = mock_response

        findings = check_cors(
            mock_client,
            'http://example.com:80',
            ['/api'],
            'test-scan-id'
        )

        # Should find critical CORS misconfiguration
        cors_findings = [f for f in findings if 'CORS misconfiguration' in f.title]
        assert len(cors_findings) > 0
        assert any(f.severity == 'critical' for f in cors_findings)


class TestCookieSecurity:
    """Test cookie security checks."""

    def test_insecure_cookie_detection(self):
        """Test detection of insecure cookies."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        
        # Create a mock cookie
        mock_cookie = MagicMock()
        mock_cookie.name = 'session_id'
        mock_cookie.secure = False
        
        mock_response.cookies.jar = [mock_cookie]
        mock_response.headers.get_list.return_value = ['session_id=abc123; Path=/']
        mock_client.get.return_value = mock_response

        findings = check_cookie_security(
            mock_client,
            'https://example.com:443',
            'test-scan-id'
        )

        # Should find cookie security issues
        cookie_findings = [f for f in findings if 'Cookie' in f.title]
        assert len(cookie_findings) > 0


class TestHTTPMethods:
    """Test dangerous HTTP methods detection."""

    def test_dangerous_methods_detection(self):
        """Test detection of dangerous HTTP methods."""
        mock_client = MagicMock()
        
        # Mock OPTIONS response
        mock_options_response = MagicMock()
        mock_options_response.headers = {
            'Allow': 'GET, POST, PUT, DELETE, TRACE, OPTIONS',
        }
        mock_client.options.return_value = mock_options_response
        
        # Mock TRACE response
        mock_trace_response = MagicMock()
        mock_trace_response.status_code = 200
        mock_client.request.return_value = mock_trace_response

        findings = check_http_methods(
            mock_client,
            'http://example.com:80',
            ['/'],
            'test-scan-id'
        )

        # Should find dangerous methods
        method_findings = [f for f in findings if 'HTTP method' in f.title or 'TRACE' in f.title]
        assert len(method_findings) > 0


class TestSensitivePaths:
    """Test sensitive path detection."""

    def test_exposed_env_file_detection(self):
        """Test detection of exposed .env file."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'DB_PASSWORD=secret123'
        mock_client.get.return_value = mock_response

        findings = check_sensitive_paths(
            mock_client,
            'http://example.com:80',
            'test-scan-id'
        )

        # Should find exposed sensitive files
        assert len(findings) > 0
        assert any('.env' in f.description or 'Environment' in f.title for f in findings)

    def test_404_paths_not_flagged(self):
        """Test that 404 responses don't generate findings."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.content = b'Not Found'
        mock_client.get.return_value = mock_response

        findings = check_sensitive_paths(
            mock_client,
            'http://example.com:80',
            'test-scan-id'
        )

        # Should not find any sensitive paths
        assert len(findings) == 0


class TestInfoLeakage:
    """Test information leakage detection."""

    def test_server_version_detection(self):
        """Test detection of server version disclosure."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.headers = {
            'Server': 'Apache/2.4.41 (Ubuntu)',
            'X-Powered-By': 'PHP/7.4.3',
        }
        mock_client.get.return_value = mock_response

        findings = check_info_leakage(
            mock_client,
            'http://example.com:80',
            'test-scan-id'
        )

        # Should find version disclosure
        assert len(findings) >= 2
        titles = [f.title for f in findings]
        assert any('Server version' in t for t in titles)
        assert any('Technology disclosed' in t for t in titles)


class TestProbeHTTP:
    """Integration tests for the main probe_http function."""

    @patch('netsentinel.probes.http_probe.httpx.Client')
    def test_probe_returns_findings(self, mock_client_class):
        """Test that probe_http returns findings from all checks."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b''
        mock_response.text = ''
        mock_response.cookies.jar = []
        
        # Create a proper mock for headers
        mock_headers = MagicMock()
        mock_headers.items.return_value = []
        mock_headers.get.return_value = ''
        mock_headers.get_list.return_value = []
        mock_headers.__contains__ = MagicMock(return_value=False)
        mock_headers.__getitem__ = MagicMock(return_value='')
        mock_response.headers = mock_headers
        
        mock_client.get.return_value = mock_response
        mock_client.options.return_value = mock_response
        mock_client.request.return_value = mock_response
        
        mock_client_class.return_value = mock_client

        findings = probe_http(
            host='example.com',
            port=80,
            scan_id='test-scan-id',
            routes=['/']
        )

        # Should return list of findings (could be empty if mocks prevent detection)
        assert isinstance(findings, list)

    @patch('netsentinel.probes.http_probe.httpx.Client')
    def test_probe_handles_connection_error(self, mock_client_class):
        """Test that probe_http handles connection errors gracefully."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")
        
        mock_client_class.return_value = mock_client

        # Should not raise, should return empty list
        findings = probe_http(
            host='nonexistent.local',
            port=80,
            scan_id='test-scan-id',
            routes=['/']
        )

        assert findings == []

    def test_https_ports_constant(self):
        """Verify HTTPS_PORTS contains expected ports."""
        assert 443 in HTTPS_PORTS
        assert 8443 in HTTPS_PORTS
        assert 80 not in HTTPS_PORTS
        assert 8080 not in HTTPS_PORTS
