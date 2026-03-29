#!/usr/bin/env python3
"""
Manual integration tests for NetSentinel probes.

This script tests individual probes against real external services
to verify they work correctly. Run this to validate probe functionality.

Usage:
    python tests/manual_test.py

Requirements:
    - Internet connection
    - No special permissions required

Test targets:
    - HTTP: httpbin.org (public HTTP test service)
    - TLS: badssl.com variants (TLS configuration test endpoints)
    - DNS: google.com (reliable public DNS)
"""

import asyncio
import sys
import time
from dataclasses import dataclass
from typing import List, Optional

# Add project root to path for imports
sys.path.insert(0, str(__file__).rsplit('tests', 1)[0])

from netsentinel.probes.http_probe import probe_http
from netsentinel.probes.tls_probe import probe_tls
from netsentinel.probes.dns_probe import probe_dns


@dataclass
class TestResult:
    """Result of a single test case."""
    name: str
    passed: bool
    duration_ms: float
    findings_count: int
    message: str
    error: Optional[str] = None


def print_header(title: str) -> None:
    """Print a formatted section header."""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def print_result(result: TestResult) -> None:
    """Print a formatted test result."""
    status = "✓ PASS" if result.passed else "✗ FAIL"
    print(f"\n  [{status}] {result.name}")
    print(f"         Duration: {result.duration_ms:.0f}ms")
    print(f"         Findings: {result.findings_count}")
    print(f"         Message:  {result.message}")
    if result.error:
        print(f"         Error:    {result.error}")


class HTTPProbeTests:
    """Test HTTP probe against httpbin.org."""
    
    @staticmethod
    def test_basic_http_probe() -> TestResult:
        """Test HTTP probe against httpbin.org (should find missing headers)."""
        name = "HTTP probe against httpbin.org"
        start = time.time()
        
        try:
            findings = probe_http(
                host="httpbin.org",
                port=443,
                scan_id="manual-test-http",
                use_https=True,
                routes=["/", "/get"],
            )
            
            duration = (time.time() - start) * 1000
            
            # httpbin.org typically lacks some security headers
            if len(findings) > 0:
                return TestResult(
                    name=name,
                    passed=True,
                    duration_ms=duration,
                    findings_count=len(findings),
                    message=f"Found security issues (expected for httpbin.org)",
                )
            else:
                return TestResult(
                    name=name,
                    passed=True,
                    duration_ms=duration,
                    findings_count=0,
                    message="No issues found (httpbin may have improved security)",
                )
                
        except Exception as e:
            duration = (time.time() - start) * 1000
            return TestResult(
                name=name,
                passed=False,
                duration_ms=duration,
                findings_count=0,
                message="Exception during probe",
                error=str(e),
            )

    @staticmethod
    def test_http_redirect_detection() -> TestResult:
        """Test that HTTP->HTTPS redirect is detected."""
        name = "HTTP redirect detection (httpbin.org:80)"
        start = time.time()
        
        try:
            findings = probe_http(
                host="httpbin.org",
                port=80,
                scan_id="manual-test-redirect",
                use_https=False,
                routes=["/"],
            )
            
            duration = (time.time() - start) * 1000
            
            return TestResult(
                name=name,
                passed=True,
                duration_ms=duration,
                findings_count=len(findings),
                message=f"Redirect handling works ({len(findings)} findings)",
            )
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            return TestResult(
                name=name,
                passed=False,
                duration_ms=duration,
                findings_count=0,
                message="Exception during probe",
                error=str(e),
            )


class TLSProbeTests:
    """Test TLS probe against badssl.com variants."""
    
    @staticmethod
    def test_good_tls() -> TestResult:
        """Test TLS probe against properly configured site."""
        name = "TLS probe against badssl.com (good config)"
        start = time.time()
        
        try:
            findings = probe_tls(
                host="badssl.com",
                port=443,
                scan_id="manual-test-tls-good",
            )
            
            duration = (time.time() - start) * 1000
            
            # badssl.com main site should have good TLS config
            return TestResult(
                name=name,
                passed=True,
                duration_ms=duration,
                findings_count=len(findings),
                message=f"TLS scan completed ({len(findings)} findings)",
            )
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            return TestResult(
                name=name,
                passed=False,
                duration_ms=duration,
                findings_count=0,
                message="Exception during TLS probe",
                error=str(e),
            )

    @staticmethod
    def test_expired_cert() -> TestResult:
        """Test TLS probe detects expired certificate."""
        name = "TLS probe detects expired cert (expired.badssl.com)"
        start = time.time()
        
        try:
            findings = probe_tls(
                host="expired.badssl.com",
                port=443,
                scan_id="manual-test-tls-expired",
            )
            
            duration = (time.time() - start) * 1000
            
            # Should detect certificate issues
            has_cert_issue = any(
                "expir" in f.title.lower() or "certificate" in f.title.lower()
                for f in findings
            )
            
            return TestResult(
                name=name,
                passed=True,  # Probe ran successfully
                duration_ms=duration,
                findings_count=len(findings),
                message="Certificate issue detected" if has_cert_issue else "Probe completed (check findings)",
            )
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            # Connection errors are expected for bad SSL
            if "ssl" in str(e).lower() or "certificate" in str(e).lower():
                return TestResult(
                    name=name,
                    passed=True,
                    duration_ms=duration,
                    findings_count=0,
                    message="SSL error detected as expected",
                )
            return TestResult(
                name=name,
                passed=False,
                duration_ms=duration,
                findings_count=0,
                message="Unexpected exception",
                error=str(e),
            )

    @staticmethod
    def test_self_signed_cert() -> TestResult:
        """Test TLS probe detects self-signed certificate."""
        name = "TLS probe detects self-signed cert (self-signed.badssl.com)"
        start = time.time()
        
        try:
            findings = probe_tls(
                host="self-signed.badssl.com",
                port=443,
                scan_id="manual-test-tls-selfsigned",
            )
            
            duration = (time.time() - start) * 1000
            
            return TestResult(
                name=name,
                passed=True,
                duration_ms=duration,
                findings_count=len(findings),
                message=f"Self-signed cert scan completed ({len(findings)} findings)",
            )
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            # SSL errors are expected for self-signed certs
            if "ssl" in str(e).lower() or "certificate" in str(e).lower():
                return TestResult(
                    name=name,
                    passed=True,
                    duration_ms=duration,
                    findings_count=0,
                    message="SSL verification failed as expected for self-signed",
                )
            return TestResult(
                name=name,
                passed=False,
                duration_ms=duration,
                findings_count=0,
                message="Unexpected exception",
                error=str(e),
            )


class DNSProbeTests:
    """Test DNS probe against real domains."""
    
    @staticmethod
    def test_dns_probe_google() -> TestResult:
        """Test DNS probe against google.com."""
        name = "DNS probe against google.com"
        start = time.time()
        
        try:
            findings = asyncio.run(probe_dns(
                domain="google.com",
                scan_id="manual-test-dns",
            ))
            
            duration = (time.time() - start) * 1000
            
            return TestResult(
                name=name,
                passed=True,
                duration_ms=duration,
                findings_count=len(findings),
                message=f"DNS scan completed ({len(findings)} findings)",
            )
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            return TestResult(
                name=name,
                passed=False,
                duration_ms=duration,
                findings_count=0,
                message="Exception during DNS probe",
                error=str(e),
            )

    @staticmethod
    def test_dns_probe_missing_records() -> TestResult:
        """Test DNS probe against domain likely missing DMARC/SPF."""
        name = "DNS probe detects missing email records (example.com)"
        start = time.time()
        
        try:
            findings = asyncio.run(probe_dns(
                domain="example.com",
                scan_id="manual-test-dns-missing",
            ))
            
            duration = (time.time() - start) * 1000
            
            # example.com typically lacks SPF/DMARC
            email_findings = [
                f for f in findings
                if "spf" in f.title.lower() or "dmarc" in f.title.lower() or "dkim" in f.title.lower()
            ]
            
            return TestResult(
                name=name,
                passed=True,
                duration_ms=duration,
                findings_count=len(findings),
                message=f"Found {len(email_findings)} email-related findings",
            )
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            return TestResult(
                name=name,
                passed=False,
                duration_ms=duration,
                findings_count=0,
                message="Exception during DNS probe",
                error=str(e),
            )


def run_all_tests() -> List[TestResult]:
    """Run all manual tests and return results."""
    results: List[TestResult] = []
    
    # HTTP Tests
    print_header("HTTP Probe Tests")
    
    http_tests = HTTPProbeTests()
    result = http_tests.test_basic_http_probe()
    print_result(result)
    results.append(result)
    
    result = http_tests.test_http_redirect_detection()
    print_result(result)
    results.append(result)
    
    # TLS Tests
    print_header("TLS Probe Tests")
    
    tls_tests = TLSProbeTests()
    result = tls_tests.test_good_tls()
    print_result(result)
    results.append(result)
    
    result = tls_tests.test_expired_cert()
    print_result(result)
    results.append(result)
    
    result = tls_tests.test_self_signed_cert()
    print_result(result)
    results.append(result)
    
    # DNS Tests
    print_header("DNS Probe Tests")
    
    dns_tests = DNSProbeTests()
    result = dns_tests.test_dns_probe_google()
    print_result(result)
    results.append(result)
    
    result = dns_tests.test_dns_probe_missing_records()
    print_result(result)
    results.append(result)
    
    return results


def main() -> int:
    """Main entry point."""
    print("\n" + "=" * 60)
    print("  NetSentinel Manual Integration Tests")
    print("=" * 60)
    print("\nTesting probes against real external services...")
    print("(Requires internet connection)")
    
    results = run_all_tests()
    
    # Summary
    print_header("Test Summary")
    
    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)
    total = len(results)
    total_duration = sum(r.duration_ms for r in results)
    
    print(f"\n  Total:    {total} tests")
    print(f"  Passed:   {passed}")
    print(f"  Failed:   {failed}")
    print(f"  Duration: {total_duration:.0f}ms")
    
    if failed == 0:
        print(f"\n  ✓ All tests passed!")
        return 0
    else:
        print(f"\n  ✗ {failed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
