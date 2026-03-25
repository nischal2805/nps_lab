"""
Live probing engine orchestrator for NetSentinel.

This module coordinates all 4 probe modules (network, TLS, HTTP, DNS) using
threading for concurrent execution. Each probe runs in its own thread and
writes findings to a thread-safe queue.

Architecture:
- Main function is async but uses threading for module orchestration
- Network probe uses asyncio internally (500 concurrent sockets)
- DNS probe uses asyncio internally (200 concurrent subdomain queries)
- TLS and HTTP probes are synchronous
- All findings collected via thread-safe queue.Queue
"""

import asyncio
import logging
import queue
import threading
from typing import List, Optional, Set

from netsentinel.config import TOP_1000_PORTS
from netsentinel.models import AttackSurfaceManifest, Finding, ScanConfig
from netsentinel.probes.dns_probe import probe_dns
from netsentinel.probes.http_probe import probe_http
from netsentinel.probes.network import probe_network
from netsentinel.probes.tls_probe import probe_tls

logger = logging.getLogger(__name__)


# Thread timeout (5 minutes max per probe)
THREAD_TIMEOUT = 300


def _network_thread(
    findings_queue: queue.Queue,
    host: str,
    scan_id: str,
    manifest: Optional[AttackSurfaceManifest],
    ports_to_scan: List[int],
) -> None:
    """
    Network probe thread worker.
    
    Runs the async network probe in a new event loop.
    Handles all exceptions to prevent thread crashes.
    """
    try:
        logger.info(f"Network probe thread started for {host}")
        
        # Create new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run network probe
        results = loop.run_until_complete(
            probe_network(
                host=host,
                scan_id=scan_id,
                manifest=manifest,
                ports=ports_to_scan,
                concurrency=500,
                port_timeout=1.0,
                banner_timeout=3.0,
            )
        )
        
        # Put all findings in queue
        for finding in results:
            findings_queue.put(finding)
        
        logger.info(f"Network probe completed: {len(results)} findings")
        
        loop.close()
        
    except Exception as e:
        logger.error(f"Network probe thread failed: {e}", exc_info=True)


def _tls_thread(
    findings_queue: queue.Queue,
    host: str,
    scan_id: str,
    tls_ports: List[int],
) -> None:
    """
    TLS probe thread worker.
    
    Probes all TLS ports sequentially (TLS handshakes are blocking).
    Handles all exceptions to prevent thread crashes.
    """
    try:
        logger.info(f"TLS probe thread started for {host}")
        
        all_findings: List[Finding] = []
        
        # Probe each TLS port
        for port in tls_ports:
            try:
                findings = probe_tls(host=host, port=port, scan_id=scan_id)
                all_findings.extend(findings)
            except Exception as e:
                logger.warning(f"TLS probe failed for port {port}: {e}")
        
        # Put all findings in queue
        for finding in all_findings:
            findings_queue.put(finding)
        
        logger.info(f"TLS probe completed: {len(all_findings)} findings")
        
    except Exception as e:
        logger.error(f"TLS probe thread failed: {e}", exc_info=True)


def _http_thread(
    findings_queue: queue.Queue,
    host: str,
    scan_id: str,
    http_ports: List[int],
    routes: Optional[List[str]],
) -> None:
    """
    HTTP probe thread worker.
    
    Probes all HTTP ports sequentially (HTTP requests are blocking).
    Handles all exceptions to prevent thread crashes.
    """
    try:
        logger.info(f"HTTP probe thread started for {host}")
        
        all_findings: List[Finding] = []
        
        # Probe each HTTP port
        for port in http_ports:
            try:
                findings = probe_http(
                    host=host,
                    port=port,
                    scan_id=scan_id,
                    routes=routes,
                )
                all_findings.extend(findings)
            except Exception as e:
                logger.warning(f"HTTP probe failed for port {port}: {e}")
        
        # Put all findings in queue
        for finding in all_findings:
            findings_queue.put(finding)
        
        logger.info(f"HTTP probe completed: {len(all_findings)} findings")
        
    except Exception as e:
        logger.error(f"HTTP probe thread failed: {e}", exc_info=True)


def _dns_thread(
    findings_queue: queue.Queue,
    domain: str,
    scan_id: str,
) -> None:
    """
    DNS probe thread worker.
    
    Runs the async DNS probe in a new event loop.
    Handles all exceptions to prevent thread crashes.
    """
    try:
        logger.info(f"DNS probe thread started for {domain}")
        
        # Create new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run DNS probe
        results = loop.run_until_complete(
            probe_dns(domain=domain, scan_id=scan_id)
        )
        
        # Put all findings in queue
        for finding in results:
            findings_queue.put(finding)
        
        logger.info(f"DNS probe completed: {len(results)} findings")
        
        loop.close()
        
    except Exception as e:
        logger.error(f"DNS probe thread failed: {e}", exc_info=True)


def _extract_manifest_ports(manifest: Optional[AttackSurfaceManifest]) -> Set[int]:
    """Extract unique port numbers from manifest."""
    if not manifest:
        return set()
    return {entry.port for entry in manifest.ports}


def _extract_manifest_routes(manifest: Optional[AttackSurfaceManifest]) -> Optional[List[str]]:
    """Extract route paths from manifest for HTTP probing."""
    if not manifest:
        return None
    return [route.path for route in manifest.routes]


async def run_live_probes(
    config: ScanConfig,
    manifest: Optional[AttackSurfaceManifest] = None,
) -> List[Finding]:
    """
    Run all live probes concurrently using threading.
    
    This is the main orchestrator for live probing. It:
    1. Extracts relevant data from manifest
    2. Determines which ports to scan for each probe
    3. Launches 4 concurrent threads (network, TLS, HTTP, DNS)
    4. Collects findings from thread-safe queue
    5. Cross-checks for undeclared open ports
    6. Returns combined findings list
    
    Args:
        config: ScanConfig with host and other settings
        manifest: Optional AttackSurfaceManifest from static analysis
    
    Returns:
        Combined list of Finding objects from all probes
    
    Raises:
        ValueError: If config.host is not set
    """
    if not config.host:
        raise ValueError("config.host is required for live probing")
    
    logger.info(f"Starting live probes for {config.host}")
    
    # Thread-safe queue for collecting findings
    findings_queue: queue.Queue = queue.Queue()
    
    # Extract manifest data
    manifest_ports = _extract_manifest_ports(manifest)
    manifest_routes = _extract_manifest_routes(manifest)
    
    # Build port lists for each probe
    # Network probe: manifest ports + TOP_1000_PORTS (deduplicated)
    network_ports = list(set(manifest_ports) | set(TOP_1000_PORTS))
    network_ports.sort()
    
    # TLS ports: 443, 8443, plus any from manifest
    tls_ports = list({443, 8443} | manifest_ports)
    tls_ports.sort()
    
    # HTTP ports: 80, 443, 8080, 8443, plus any from manifest
    http_ports = list({80, 443, 8080, 8443} | manifest_ports)
    http_ports.sort()
    
    # Start all probe threads
    threads = []
    
    # 1. Network probe thread
    network_t = threading.Thread(
        target=_network_thread,
        args=(findings_queue, config.host, config.scan_id, manifest, network_ports),
        daemon=True,
        name="network-probe",
    )
    threads.append(network_t)
    
    # 2. TLS probe thread
    tls_t = threading.Thread(
        target=_tls_thread,
        args=(findings_queue, config.host, config.scan_id, tls_ports),
        daemon=True,
        name="tls-probe",
    )
    threads.append(tls_t)
    
    # 3. HTTP probe thread
    http_t = threading.Thread(
        target=_http_thread,
        args=(findings_queue, config.host, config.scan_id, http_ports, manifest_routes),
        daemon=True,
        name="http-probe",
    )
    threads.append(http_t)
    
    # 4. DNS probe thread (if host looks like a domain)
    # Skip DNS probe if host is an IP address
    if not _is_ip_address(config.host):
        dns_t = threading.Thread(
            target=_dns_thread,
            args=(findings_queue, config.host, config.scan_id),
            daemon=True,
            name="dns-probe",
        )
        threads.append(dns_t)
    else:
        logger.info(f"Skipping DNS probe for IP address: {config.host}")
    
    # Start all threads
    logger.info(f"Launching {len(threads)} probe threads")
    for t in threads:
        t.start()
    
    # Wait for all threads to complete (with timeout)
    for t in threads:
        t.join(timeout=THREAD_TIMEOUT)
        if t.is_alive():
            logger.warning(f"Thread {t.name} exceeded timeout ({THREAD_TIMEOUT}s)")
    
    # Collect all findings from queue
    findings: List[Finding] = []
    while not findings_queue.empty():
        try:
            finding = findings_queue.get_nowait()
            findings.append(finding)
        except queue.Empty:
            break
    
    logger.info(f"Live probes completed: {len(findings)} total findings")
    
    # Cross-check: detect undeclared open ports
    # (ports found by network probe but not in manifest)
    undeclared_findings = _detect_undeclared_ports(findings, manifest)
    findings.extend(undeclared_findings)
    
    return findings


def _is_ip_address(host: str) -> bool:
    """Check if a string is an IP address (IPv4 or IPv6)."""
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _detect_undeclared_ports(
    findings: List[Finding],
    manifest: Optional[AttackSurfaceManifest],
) -> List[Finding]:
    """
    Cross-check network findings against manifest.
    
    Generate findings for ports that are open but were not declared
    in the static analysis manifest.
    
    Args:
        findings: All findings from probes
        manifest: Attack surface manifest from static analysis
    
    Returns:
        List of Finding objects for undeclared ports
    """
    if not manifest:
        # No manifest to compare against
        return []
    
    # Extract declared ports from manifest
    declared_ports = {entry.port for entry in manifest.ports}
    
    # Extract open ports from network findings
    # Look for findings with domain="network" and "open" in description
    open_ports: Set[int] = set()
    for finding in findings:
        if finding.domain == "network":
            # Try to extract port number from finding
            # Network findings typically have port in title like "Port 22 (SSH) Exposed"
            import re
            port_match = re.search(r'[Pp]ort\s+(\d+)', finding.title)
            if port_match:
                open_ports.add(int(port_match.group(1)))
    
    # Find undeclared ports
    undeclared = open_ports - declared_ports
    
    if not undeclared:
        return []
    
    logger.warning(f"Found {len(undeclared)} undeclared open ports: {sorted(undeclared)}")
    
    # Generate findings for undeclared ports
    undeclared_findings: List[Finding] = []
    for port in sorted(undeclared):
        from netsentinel.models import CVSSBreakdown, Evidence
        
        finding = Finding(
            domain="network",
            title=f"Undeclared Port {port} Open",
            description=(
                f"Port {port} is open but was not found in static analysis. "
                f"This suggests the port may be opened dynamically at runtime "
                f"or the static analysis missed this port declaration. "
                f"Review code to determine why this port is open."
            ),
            severity="medium",
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cvss_breakdown=CVSSBreakdown(
                attack_vector="Network",
                attack_complexity="Low",
                privileges_required="None",
                user_interaction="None",
                scope="Unchanged",
                confidentiality="Low",
                integrity="None",
                availability="None",
            ),
            owasp_category="Security Misconfiguration",
            owasp_id="A05",
            evidence=Evidence(banner=f"Port {port} responded to TCP connection"),
            remediation=(
                f"1. Review code to find where port {port} is opened\n"
                f"2. Document all network ports in code comments\n"
                f"3. If port is not needed, close it\n"
                f"4. If needed, ensure proper authentication and encryption"
            ),
            false_positive_risk="low",
            references=[
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            ],
        )
        undeclared_findings.append(finding)
    
    return undeclared_findings
