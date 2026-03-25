"""
Network probe module (Module 3A) for NetSentinel.

Performs network-layer security auditing:
- TCP port scanning with asyncio (500 concurrent connections)
- UDP targeted scanning for specific high-risk services
- ICMP probing with TTL-based OS fingerprinting
- Banner grabbing on open ports
- Dangerous port classification
- Manifest cross-checking for undeclared ports

All TCP scanning uses asyncio for high concurrency with minimal overhead.
"""

import asyncio
import re
import socket
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from netsentinel.config import DANGEROUS_PORTS, TOP_1000_PORTS, UDP_SCAN_PORTS
from netsentinel.models import AttackSurfaceManifest, CVSSBreakdown, Evidence, Finding


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class PortResult:
    """Result of scanning a single port."""

    port: int
    status: str  # 'open', 'closed', 'filtered'
    banner: Optional[str] = None


@dataclass
class ICMPResult:
    """Result of ICMP probe."""

    alive: bool
    ttl: Optional[int] = None
    os_hint: Optional[str] = None
    latency_ms: Optional[float] = None


# =============================================================================
# CVSS HELPERS
# =============================================================================


# CVSS configurations for dangerous ports
# Format: (base_score, severity, vector, breakdown_dict)
PORT_CVSS_CONFIG: Dict[int, Tuple[float, str, str, Dict[str, str]]] = {
    21: (
        7.5,
        "high",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        {
            "attack_vector": "Network",
            "attack_complexity": "Low",
            "privileges_required": "None",
            "user_interaction": "None",
            "scope": "Unchanged",
            "confidentiality": "High",
            "integrity": "None",
            "availability": "None",
        },
    ),
    23: (
        9.1,
        "critical",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        {
            "attack_vector": "Network",
            "attack_complexity": "Low",
            "privileges_required": "None",
            "user_interaction": "None",
            "scope": "Unchanged",
            "confidentiality": "High",
            "integrity": "High",
            "availability": "None",
        },
    ),
    25: (
        7.5,
        "high",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        {
            "attack_vector": "Network",
            "attack_complexity": "Low",
            "privileges_required": "None",
            "user_interaction": "None",
            "scope": "Unchanged",
            "confidentiality": "None",
            "integrity": "High",
            "availability": "None",
        },
    ),
    445: (
        9.8,
        "critical",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        {
            "attack_vector": "Network",
            "attack_complexity": "Low",
            "privileges_required": "None",
            "user_interaction": "None",
            "scope": "Unchanged",
            "confidentiality": "High",
            "integrity": "High",
            "availability": "High",
        },
    ),
    3389: (
        7.5,
        "high",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        {
            "attack_vector": "Network",
            "attack_complexity": "Low",
            "privileges_required": "None",
            "user_interaction": "None",
            "scope": "Unchanged",
            "confidentiality": "High",
            "integrity": "None",
            "availability": "None",
        },
    ),
    6379: (
        9.8,
        "critical",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        {
            "attack_vector": "Network",
            "attack_complexity": "Low",
            "privileges_required": "None",
            "user_interaction": "None",
            "scope": "Unchanged",
            "confidentiality": "High",
            "integrity": "High",
            "availability": "High",
        },
    ),
    27017: (
        9.8,
        "critical",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        {
            "attack_vector": "Network",
            "attack_complexity": "Low",
            "privileges_required": "None",
            "user_interaction": "None",
            "scope": "Unchanged",
            "confidentiality": "High",
            "integrity": "High",
            "availability": "High",
        },
    ),
    9200: (
        9.8,
        "critical",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        {
            "attack_vector": "Network",
            "attack_complexity": "Low",
            "privileges_required": "None",
            "user_interaction": "None",
            "scope": "Unchanged",
            "confidentiality": "High",
            "integrity": "High",
            "availability": "High",
        },
    ),
    5432: (
        7.5,
        "high",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        {
            "attack_vector": "Network",
            "attack_complexity": "Low",
            "privileges_required": "None",
            "user_interaction": "None",
            "scope": "Unchanged",
            "confidentiality": "High",
            "integrity": "None",
            "availability": "None",
        },
    ),
    3306: (
        7.5,
        "high",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        {
            "attack_vector": "Network",
            "attack_complexity": "Low",
            "privileges_required": "None",
            "user_interaction": "None",
            "scope": "Unchanged",
            "confidentiality": "High",
            "integrity": "None",
            "availability": "None",
        },
    ),
}


# Port descriptions for findings
PORT_DESCRIPTIONS: Dict[int, str] = {
    21: (
        "FTP (File Transfer Protocol) transmits credentials and data in plaintext. "
        "Attackers on the network can intercept usernames, passwords, and transferred files."
    ),
    23: (
        "Telnet transmits all data including credentials in plaintext. "
        "Any network observer can intercept login sessions and commands."
    ),
    25: (
        "SMTP (Simple Mail Transfer Protocol) without authentication can be abused as an open relay. "
        "Attackers can use it to send spam or phishing emails, damaging reputation and potentially "
        "leading to IP blacklisting."
    ),
    445: (
        "SMB (Server Message Block) exposed to the internet is extremely dangerous. "
        "It has been the vector for major attacks like WannaCry and EternalBlue. "
        "Remote code execution vulnerabilities are common in SMB implementations."
    ),
    3389: (
        "RDP (Remote Desktop Protocol) exposed to the internet is a common attack vector. "
        "It is frequently targeted by brute-force attacks and has had multiple critical "
        "vulnerabilities including BlueKeep (CVE-2019-0708)."
    ),
    6379: (
        "Redis exposed without authentication allows attackers to read/write any data, "
        "execute Lua scripts, and potentially achieve remote code execution through "
        "the CONFIG SET and MODULE LOAD commands."
    ),
    27017: (
        "MongoDB exposed without authentication allows attackers full database access. "
        "Thousands of MongoDB instances have been compromised and held for ransom due to "
        "this misconfiguration."
    ),
    9200: (
        "Elasticsearch exposed without authentication allows attackers to read, modify, "
        "or delete any indexed data. It also exposes cluster configuration and can leak "
        "sensitive information stored in indices."
    ),
    5432: (
        "PostgreSQL exposed to the internet increases the attack surface for credential "
        "brute-forcing and exploitation of database vulnerabilities. Database ports should "
        "only be accessible from trusted application servers."
    ),
    3306: (
        "MySQL exposed to the internet increases the attack surface for credential "
        "brute-forcing and exploitation of database vulnerabilities. Database ports should "
        "only be accessible from trusted application servers."
    ),
}


# Remediation guidance for dangerous ports
PORT_REMEDIATIONS: Dict[int, str] = {
    21: (
        "Disable FTP and migrate to SFTP or SCP for secure file transfers. "
        "If FTP is required, use FTPS (FTP over TLS) and restrict access via firewall rules."
    ),
    23: (
        "Disable Telnet immediately and replace with SSH using key-based authentication. "
        "There is no legitimate use case for Telnet on a production system."
    ),
    25: (
        "Configure SMTP authentication (SMTP AUTH) and enable TLS/STARTTLS. "
        "Restrict relay access to authenticated users only. Consider using a managed email service."
    ),
    445: (
        "Block SMB at the perimeter firewall (ports 445, 139). If file sharing is needed, "
        "use a VPN or implement SMB over QUIC. Ensure all systems are patched against known SMB vulnerabilities."
    ),
    3389: (
        "Do not expose RDP directly to the internet. Use a VPN, SSH tunnel, or Azure Bastion "
        "for remote access. Enable Network Level Authentication (NLA) and use strong passwords or MFA."
    ),
    6379: (
        "Bind Redis to localhost or private network interfaces only. Enable AUTH with a strong password. "
        "Use Redis ACLs for fine-grained access control. Consider Redis over TLS for encrypted connections."
    ),
    27017: (
        "Enable MongoDB authentication and create database users with minimal required privileges. "
        "Bind to localhost or private network only. Use TLS for connections. Enable audit logging."
    ),
    9200: (
        "Enable Elasticsearch security features (X-Pack Security or Open Distro). "
        "Configure role-based access control. Bind to localhost or private network. "
        "Use TLS for all connections. Put behind an authenticated reverse proxy for external access."
    ),
    5432: (
        "Configure PostgreSQL to listen only on localhost or private network interfaces. "
        "Use pg_hba.conf to restrict connections by IP. Require SSL for all connections. "
        "Never expose database ports directly to the internet."
    ),
    3306: (
        "Configure MySQL to bind only to localhost or private network interfaces. "
        "Use firewall rules to restrict database access to application servers only. "
        "Require SSL for all connections. Never expose database ports directly to the internet."
    ),
}


def calculate_cvss_for_port(port: int) -> float:
    """Get CVSS base score for a dangerous port."""
    if port in PORT_CVSS_CONFIG:
        return PORT_CVSS_CONFIG[port][0]
    return 5.3  # Default medium score for unlisted dangerous ports


def generate_cvss_vector(port: int) -> str:
    """Generate CVSS vector string for a port."""
    if port in PORT_CVSS_CONFIG:
        return PORT_CVSS_CONFIG[port][2]
    return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"


def get_cvss_breakdown(port: int) -> CVSSBreakdown:
    """Get CVSS breakdown for a port."""
    if port in PORT_CVSS_CONFIG:
        breakdown_dict = PORT_CVSS_CONFIG[port][3]
        return CVSSBreakdown(
            attack_vector=breakdown_dict["attack_vector"],
            attack_complexity=breakdown_dict["attack_complexity"],
            privileges_required=breakdown_dict["privileges_required"],
            user_interaction=breakdown_dict["user_interaction"],
            scope=breakdown_dict["scope"],
            confidentiality=breakdown_dict["confidentiality"],
            integrity=breakdown_dict["integrity"],
            availability=breakdown_dict["availability"],
        )
    return CVSSBreakdown(
        attack_vector="Network",
        attack_complexity="Low",
        privileges_required="None",
        user_interaction="None",
        scope="Unchanged",
        confidentiality="Low",
        integrity="None",
        availability="None",
    )


def get_port_description(port: int, service: str) -> str:
    """Get detailed description for a dangerous port finding."""
    if port in PORT_DESCRIPTIONS:
        return PORT_DESCRIPTIONS[port]
    return f"{service} service on port {port} is exposed to the network."


def get_port_remediation(port: int) -> str:
    """Get remediation guidance for a dangerous port."""
    if port in PORT_REMEDIATIONS:
        return PORT_REMEDIATIONS[port]
    return (
        f"Review whether port {port} needs to be exposed. If not, close it via firewall. "
        "If required, implement authentication, encryption, and access controls."
    )


# =============================================================================
# ICMP PROBE
# =============================================================================


async def probe_icmp(host: str, timeout: float = 5.0) -> ICMPResult:
    """
    Send ICMP echo request and extract TTL for OS fingerprinting.

    Uses subprocess to call ping (cross-platform).
    TTL hints:
    - ~64: Linux/Unix
    - ~128: Windows
    - ~255: Network device (router/switch)

    Args:
        host: Target IP address or hostname
        timeout: Timeout in seconds for ping

    Returns:
        ICMPResult with alive status, TTL, and OS hint
    """
    try:
        # Cross-platform ping command
        if sys.platform == "win32":
            # Windows: -n count, -w timeout (ms)
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
        else:
            # Unix/Linux: -c count, -W timeout (seconds)
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
        output = stdout.decode("utf-8", errors="ignore")

        if proc.returncode != 0:
            return ICMPResult(alive=False)

        # Parse TTL from output
        ttl_match = re.search(r"[Tt][Tt][Ll][=:]?\s*(\d+)", output)
        ttl = int(ttl_match.group(1)) if ttl_match else None

        # Parse latency
        latency = None
        if sys.platform == "win32":
            time_match = re.search(r"[Tt]ime[=<]?\s*(\d+)", output)
        else:
            time_match = re.search(r"time[=]?\s*([\d.]+)", output)
        if time_match:
            latency = float(time_match.group(1))

        # OS fingerprinting based on TTL
        os_hint = None
        if ttl:
            if ttl <= 64:
                os_hint = "Linux/Unix"
            elif ttl <= 128:
                os_hint = "Windows"
            else:
                os_hint = "Network Device"

        return ICMPResult(alive=True, ttl=ttl, os_hint=os_hint, latency_ms=latency)

    except asyncio.TimeoutError:
        return ICMPResult(alive=False)
    except Exception:
        return ICMPResult(alive=False)


# =============================================================================
# TCP PORT SCANNING
# =============================================================================


async def scan_port(host: str, port: int, timeout: float = 1.0) -> PortResult:
    """
    Scan a single TCP port - atomic unit.

    Args:
        host: Target IP or hostname
        port: Port number to scan
        timeout: Connection timeout in seconds

    Returns:
        PortResult with port status (open/closed/filtered)
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return PortResult(port, "open")
    except asyncio.TimeoutError:
        return PortResult(port, "filtered")
    except ConnectionRefusedError:
        return PortResult(port, "closed")
    except OSError:
        # Connection errors (network unreachable, etc.)
        return PortResult(port, "filtered")
    except Exception:
        return PortResult(port, "filtered")


async def scan_tcp_ports(
    host: str,
    ports: List[int],
    concurrency: int = 500,
    timeout: float = 1.0,
) -> List[PortResult]:
    """
    Scan multiple TCP ports with semaphore-controlled concurrency.

    Args:
        host: Target IP or hostname
        ports: List of ports to scan
        concurrency: Maximum concurrent connections (default 500)
        timeout: Per-port connection timeout

    Returns:
        List of PortResult for open ports only
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_with_semaphore(port: int) -> PortResult:
        async with semaphore:
            return await scan_port(host, port, timeout)

    tasks = [scan_with_semaphore(p) for p in ports]
    results = await asyncio.gather(*tasks)

    # Return only open ports
    return [r for r in results if r.status == "open"]


# =============================================================================
# UDP SCANNING
# =============================================================================


async def probe_udp_dns(host: str, timeout: float = 3.0) -> Optional[PortResult]:
    """
    Probe UDP port 53 (DNS) by sending a DNS query.

    An open DNS resolver responds to queries for external domains.
    """
    try:
        # DNS query for google.com (standard format)
        # Transaction ID + Flags + Questions + Answer/Authority/Additional RRs
        dns_query = (
            b"\x00\x01"  # Transaction ID
            b"\x01\x00"  # Flags: standard query
            b"\x00\x01"  # Questions: 1
            b"\x00\x00"  # Answer RRs: 0
            b"\x00\x00"  # Authority RRs: 0
            b"\x00\x00"  # Additional RRs: 0
            b"\x06google\x03com\x00"  # Query: google.com
            b"\x00\x01"  # Type: A
            b"\x00\x01"  # Class: IN
        )

        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.settimeout(timeout)

        await loop.sock_sendto(sock, dns_query, (host, 53))

        try:
            data = await asyncio.wait_for(
                loop.sock_recv(sock, 512),
                timeout=timeout,
            )
            sock.close()
            if data:
                return PortResult(53, "open", banner="DNS resolver")
        except asyncio.TimeoutError:
            sock.close()
            return None

    except Exception:
        return None


async def probe_udp_snmp(host: str, timeout: float = 3.0) -> Optional[PortResult]:
    """
    Probe UDP port 161 (SNMP) by sending an SNMP GetRequest.

    Unauthenticated SNMP with community string 'public' is a critical exposure.
    """
    try:
        # SNMPv1 GetRequest for sysDescr.0 with community 'public'
        snmp_query = bytes(
            [
                0x30,
                0x26,  # SEQUENCE, length 38
                0x02,
                0x01,
                0x00,  # INTEGER: version (0 = SNMPv1)
                0x04,
                0x06,
                0x70,
                0x75,
                0x62,
                0x6C,
                0x69,
                0x63,  # OCTET STRING: "public"
                0xA0,
                0x19,  # GetRequest PDU, length 25
                0x02,
                0x04,
                0x00,
                0x00,
                0x00,
                0x01,  # INTEGER: request-id
                0x02,
                0x01,
                0x00,  # INTEGER: error-status (0 = noError)
                0x02,
                0x01,
                0x00,  # INTEGER: error-index
                0x30,
                0x0B,  # SEQUENCE: variable bindings
                0x30,
                0x09,  # SEQUENCE: varbind
                0x06,
                0x05,
                0x2B,
                0x06,
                0x01,
                0x02,
                0x01,  # OID: 1.3.6.1.2.1 (system)
                0x05,
                0x00,  # NULL value
            ]
        )

        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)

        await loop.sock_sendto(sock, snmp_query, (host, 161))

        try:
            data = await asyncio.wait_for(
                loop.sock_recv(sock, 1024),
                timeout=timeout,
            )
            sock.close()
            if data:
                return PortResult(161, "open", banner="SNMP (community: public)")
        except asyncio.TimeoutError:
            sock.close()
            return None

    except Exception:
        return None


async def probe_udp_ntp(host: str, timeout: float = 3.0) -> Optional[PortResult]:
    """
    Probe UDP port 123 (NTP) by sending an NTP request.

    Open NTP can be used in amplification DDoS attacks.
    """
    try:
        # NTP version 3, mode 3 (client)
        ntp_query = b"\x1b" + b"\x00" * 47

        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)

        await loop.sock_sendto(sock, ntp_query, (host, 123))

        try:
            data = await asyncio.wait_for(
                loop.sock_recv(sock, 1024),
                timeout=timeout,
            )
            sock.close()
            if data and len(data) >= 48:
                return PortResult(123, "open", banner="NTP server")
        except asyncio.TimeoutError:
            sock.close()
            return None

    except Exception:
        return None


async def probe_udp_ike(host: str, timeout: float = 3.0) -> Optional[PortResult]:
    """
    Probe UDP port 500 (IKE/IPSec) by sending an IKE init.

    Unexpected VPN endpoint exposure can indicate misconfiguration.
    """
    try:
        # IKE SA_INIT (simplified)
        ike_query = (
            b"\x00" * 8  # Initiator SPI
            + b"\x00" * 8  # Responder SPI (zero for init)
            + b"\x21"  # Next payload: SA
            + b"\x20"  # Version: 2.0
            + b"\x22"  # Exchange type: IKE_SA_INIT
            + b"\x08"  # Flags: Initiator
            + b"\x00\x00\x00\x00"  # Message ID
            + b"\x00\x00\x00\x1c"  # Length: 28 bytes
        )

        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)

        await loop.sock_sendto(sock, ike_query, (host, 500))

        try:
            data = await asyncio.wait_for(
                loop.sock_recv(sock, 1024),
                timeout=timeout,
            )
            sock.close()
            if data:
                return PortResult(500, "open", banner="IKE/IPSec VPN")
        except asyncio.TimeoutError:
            sock.close()
            return None

    except Exception:
        return None


async def scan_udp_ports(
    host: str,
    ports: Optional[List[int]] = None,
    timeout: float = 3.0,
) -> List[PortResult]:
    """
    Targeted UDP scan for specific high-risk services.

    UDP scanning is inherently unreliable, so we use application-layer
    probes to definitively confirm service availability.

    Args:
        host: Target IP or hostname
        ports: List of ports to scan (defaults to UDP_SCAN_PORTS)
        timeout: Per-probe timeout

    Returns:
        List of PortResult for confirmed open UDP ports
    """
    if ports is None:
        ports = UDP_SCAN_PORTS

    results: List[PortResult] = []

    probe_map = {
        53: probe_udp_dns,
        161: probe_udp_snmp,
        123: probe_udp_ntp,
        500: probe_udp_ike,
    }

    tasks = []
    for port in ports:
        if port in probe_map:
            tasks.append(probe_map[port](host, timeout))

    if tasks:
        probe_results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in probe_results:
            if isinstance(result, PortResult):
                results.append(result)

    return results


# =============================================================================
# BANNER GRABBING
# =============================================================================


# HTTP ports that should receive an HTTP probe
HTTP_PORTS = {80, 443, 8080, 8000, 8443, 8888, 3000, 5000, 8008, 8081, 8082}


async def grab_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """
    Grab banner from an open TCP port.

    Sends appropriate probes based on the port type:
    - HTTP ports get a HEAD request
    - Other ports get a generic probe (CRLF)

    Args:
        host: Target IP or hostname
        port: Port to grab banner from
        timeout: Connection and read timeout

    Returns:
        Banner string or None if no banner received
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )

        # Send appropriate probe based on port
        if port in HTTP_PORTS:
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        else:
            # Generic probe - just send CRLF to solicit response
            writer.write(b"\r\n")

        await writer.drain()

        # Read response with timeout
        try:
            banner_bytes = await asyncio.wait_for(
                reader.read(1024),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            # Some services only respond after specific commands
            banner_bytes = b""

        writer.close()
        await writer.wait_closed()

        if banner_bytes:
            # Decode and clean up banner
            banner = banner_bytes.decode("utf-8", errors="ignore")
            # Remove null bytes and excessive whitespace
            banner = banner.replace("\x00", "").strip()
            return banner[:1024] if banner else None

        return None

    except Exception:
        return None


async def grab_banners(
    host: str,
    open_ports: List[PortResult],
    timeout: float = 3.0,
    concurrency: int = 20,
) -> Dict[int, str]:
    """
    Grab banners for all open ports with concurrency control.

    Args:
        host: Target IP or hostname
        open_ports: List of PortResult for open ports
        timeout: Per-banner grab timeout
        concurrency: Max concurrent banner grabs

    Returns:
        Dict mapping port numbers to banner strings
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def grab_with_semaphore(port_result: PortResult) -> Tuple[int, Optional[str]]:
        async with semaphore:
            banner = await grab_banner(host, port_result.port, timeout)
            return (port_result.port, banner)

    tasks = [grab_with_semaphore(pr) for pr in open_ports]
    results = await asyncio.gather(*tasks)

    return {port: banner for port, banner in results if banner}


# =============================================================================
# PORT CLASSIFICATION & FINDINGS
# =============================================================================


def classify_ports(
    open_ports: List[PortResult],
    banners: Dict[int, str],
    scan_id: str,
) -> List[Finding]:
    """
    Generate findings for dangerous open ports.

    Args:
        open_ports: List of open PortResult
        banners: Dict mapping ports to banners
        scan_id: UUID of the current scan

    Returns:
        List of Finding objects for dangerous ports
    """
    findings: List[Finding] = []

    for port_result in open_ports:
        port = port_result.port

        if port in DANGEROUS_PORTS:
            service, severity = DANGEROUS_PORTS[port]
            banner = banners.get(port)

            finding = Finding(
                scan_id=scan_id,
                domain="network",
                title=f"Open port {port} ({service}) detected",
                description=get_port_description(port, service),
                severity=severity,
                cvss_score=calculate_cvss_for_port(port),
                cvss_vector=generate_cvss_vector(port),
                cvss_breakdown=get_cvss_breakdown(port),
                owasp_category="A05:2021 – Security Misconfiguration",
                owasp_id="A05",
                evidence=Evidence(
                    raw_request=f"TCP SYN to {port}",
                    raw_response="SYN-ACK received — port open",
                    banner=banner,
                ),
                remediation=get_port_remediation(port),
                false_positive_risk="low",
                references=[
                    f"https://www.speedguide.net/port.php?port={port}",
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                ],
            )
            findings.append(finding)

    return findings


# =============================================================================
# MANIFEST CROSS-CHECK
# =============================================================================


def check_undeclared_ports(
    open_ports: List[PortResult],
    manifest: AttackSurfaceManifest,
    scan_id: str,
) -> List[Finding]:
    """
    Find ports open on live host but not declared in manifest.

    This helps identify shadow services, forgotten deployments,
    or discrepancies between documented and actual infrastructure.

    Args:
        open_ports: List of open PortResult from live scan
        manifest: Attack surface manifest from static analysis
        scan_id: UUID of the current scan

    Returns:
        List of Finding objects for undeclared ports
    """
    # Get declared ports from manifest
    declared_ports = {p.port for p in manifest.ports}
    findings: List[Finding] = []

    for port_result in open_ports:
        port = port_result.port

        if port not in declared_ports:
            finding = Finding(
                scan_id=scan_id,
                domain="network",
                title=f"Undeclared open port {port} detected",
                description=(
                    f"Port {port} is open on the live host but was not found in the "
                    f"codebase configuration (Dockerfiles, docker-compose, config files). "
                    f"This may indicate a shadow service, manual configuration, or deployment "
                    f"drift that should be reviewed."
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
                owasp_category="A05:2021 – Security Misconfiguration",
                owasp_id="A05",
                evidence=Evidence(
                    raw_request=f"TCP SYN to {port}",
                    raw_response="SYN-ACK received — port open",
                    banner=port_result.banner,
                ),
                remediation=(
                    f"Document port {port} in infrastructure configuration, or close it "
                    f"if it's not needed. Undocumented services increase attack surface "
                    f"and make security auditing difficult."
                ),
                false_positive_risk="medium",
                references=[
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                ],
            )
            findings.append(finding)

    return findings


# =============================================================================
# MAIN PROBE FUNCTION
# =============================================================================


async def probe_network(
    host: str,
    scan_id: str,
    manifest: Optional[AttackSurfaceManifest] = None,
    ports: Optional[List[int]] = None,
    concurrency: int = 500,
    port_timeout: float = 1.0,
    banner_timeout: float = 3.0,
) -> List[Finding]:
    """
    Run all network probes against the target.

    This is the main entry point for the network probe module.
    It orchestrates:
    1. ICMP probe for host liveness and OS fingerprinting
    2. TCP port scan with asyncio concurrency
    3. UDP targeted scan for high-risk services
    4. Banner grabbing on open TCP ports
    5. Dangerous port classification and finding generation
    6. Cross-check with manifest for undeclared ports

    Args:
        host: IP address or domain to probe
        scan_id: UUID for this scan
        manifest: Optional attack surface manifest for cross-checking
        ports: Optional list of ports to scan (defaults to TOP_1000_PORTS)
        concurrency: Max concurrent TCP connections (default 500)
        port_timeout: Timeout for each port probe
        banner_timeout: Timeout for banner grabbing

    Returns:
        List of Finding objects
    """
    findings: List[Finding] = []

    # Use default port list if not specified
    if ports is None:
        ports = TOP_1000_PORTS

    # 1. ICMP probe for host liveness
    icmp_result = await probe_icmp(host)

    # Generate finding for ICMP results if host appears down
    if not icmp_result.alive:
        # Host might be filtering ICMP - continue with port scan
        pass

    # 2. TCP port scan (asyncio, 500 concurrent by default)
    open_ports = await scan_tcp_ports(
        host,
        ports,
        concurrency=concurrency,
        timeout=port_timeout,
    )

    # 3. UDP targeted scan for specific services
    udp_results = await scan_udp_ports(host, UDP_SCAN_PORTS)

    # Generate findings for open UDP services
    for udp_port in udp_results:
        if udp_port.port == 53:
            finding = Finding(
                scan_id=scan_id,
                domain="network",
                title="Open DNS resolver detected (UDP 53)",
                description=(
                    "An open DNS resolver can be abused for DNS amplification attacks. "
                    "Attackers can use this service to amplify DDoS attacks by sending "
                    "small queries that generate large responses directed at victims."
                ),
                severity="high",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
                cvss_breakdown=CVSSBreakdown(
                    attack_vector="Network",
                    attack_complexity="Low",
                    privileges_required="None",
                    user_interaction="None",
                    scope="Changed",
                    confidentiality="None",
                    integrity="None",
                    availability="High",
                ),
                owasp_category="A05:2021 – Security Misconfiguration",
                owasp_id="A05",
                evidence=Evidence(
                    raw_request="DNS query to UDP 53",
                    raw_response="DNS response received",
                    banner=udp_port.banner,
                ),
                remediation=(
                    "Configure DNS to only respond to queries from authorized clients. "
                    "Implement rate limiting and response rate limiting (RRL). "
                    "Consider disabling recursion for external queries."
                ),
                false_positive_risk="low",
                references=[
                    "https://www.us-cert.gov/ncas/alerts/TA13-088A",
                ],
            )
            findings.append(finding)

        elif udp_port.port == 161:
            finding = Finding(
                scan_id=scan_id,
                domain="network",
                title="SNMP service with default community string (UDP 161)",
                description=(
                    "SNMP is accessible with the default 'public' community string. "
                    "This exposes system information, network configuration, and potentially "
                    "allows modification of settings if 'private' community is also default."
                ),
                severity="critical",
                cvss_score=9.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cvss_breakdown=CVSSBreakdown(
                    attack_vector="Network",
                    attack_complexity="Low",
                    privileges_required="None",
                    user_interaction="None",
                    scope="Unchanged",
                    confidentiality="High",
                    integrity="High",
                    availability="None",
                ),
                owasp_category="A05:2021 – Security Misconfiguration",
                owasp_id="A05",
                evidence=Evidence(
                    raw_request="SNMP GetRequest with community 'public'",
                    raw_response="SNMP response received",
                    banner=udp_port.banner,
                ),
                remediation=(
                    "Change SNMP community strings to strong, unique values. "
                    "Migrate to SNMPv3 with authentication and encryption. "
                    "Restrict SNMP access to management networks only via firewall."
                ),
                false_positive_risk="low",
                references=[
                    "https://cwe.mitre.org/data/definitions/200.html",
                ],
            )
            findings.append(finding)

        elif udp_port.port == 123:
            finding = Finding(
                scan_id=scan_id,
                domain="network",
                title="Open NTP server detected (UDP 123)",
                description=(
                    "An open NTP server can be abused for NTP amplification attacks. "
                    "The monlist command in particular can generate responses 200x larger "
                    "than the request, making it effective for DDoS amplification."
                ),
                severity="medium",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                cvss_breakdown=CVSSBreakdown(
                    attack_vector="Network",
                    attack_complexity="Low",
                    privileges_required="None",
                    user_interaction="None",
                    scope="Unchanged",
                    confidentiality="None",
                    integrity="None",
                    availability="Low",
                ),
                owasp_category="A05:2021 – Security Misconfiguration",
                owasp_id="A05",
                evidence=Evidence(
                    raw_request="NTP request to UDP 123",
                    raw_response="NTP response received",
                    banner=udp_port.banner,
                ),
                remediation=(
                    "Disable monlist and other dangerous NTP commands. "
                    "Restrict NTP queries to known clients. "
                    "Use 'restrict default noquery' in NTP configuration."
                ),
                false_positive_risk="low",
                references=[
                    "https://www.us-cert.gov/ncas/alerts/TA14-013A",
                ],
            )
            findings.append(finding)

        elif udp_port.port == 500:
            finding = Finding(
                scan_id=scan_id,
                domain="network",
                title="IKE/IPSec VPN endpoint detected (UDP 500)",
                description=(
                    "An IKE/IPSec VPN endpoint is exposed. While VPN services are often "
                    "intentional, exposed VPN endpoints can be targets for IKE aggressive "
                    "mode attacks, pre-shared key extraction, and DoS attacks."
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
                owasp_category="A05:2021 – Security Misconfiguration",
                owasp_id="A05",
                evidence=Evidence(
                    raw_request="IKE SA_INIT to UDP 500",
                    raw_response="IKE response received",
                    banner=udp_port.banner,
                ),
                remediation=(
                    "If VPN is intentional, ensure IKE aggressive mode is disabled. "
                    "Use strong pre-shared keys or certificate-based authentication. "
                    "If VPN is not needed, close UDP 500 and 4500."
                ),
                false_positive_risk="medium",
                references=[
                    "https://www.sans.org/reading-room/whitepapers/vpns/",
                ],
            )
            findings.append(finding)

    # 4. Banner grabbing on open TCP ports
    banners = await grab_banners(host, open_ports, timeout=banner_timeout)

    # Update PortResult objects with banners
    for port_result in open_ports:
        if port_result.port in banners:
            port_result.banner = banners[port_result.port]

    # 5. Classify dangerous ports and generate findings
    findings.extend(classify_ports(open_ports, banners, scan_id))

    # 6. Cross-check with manifest for undeclared ports
    if manifest:
        findings.extend(check_undeclared_ports(open_ports, manifest, scan_id))

    return findings


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def get_open_ports_summary(open_ports: List[PortResult]) -> str:
    """Generate a summary string of open ports."""
    if not open_ports:
        return "No open ports detected"
    ports_str = ", ".join(str(p.port) for p in sorted(open_ports, key=lambda x: x.port))
    return f"{len(open_ports)} open ports: {ports_str}"


def get_icmp_summary(icmp_result: ICMPResult) -> str:
    """Generate a summary string of ICMP probe results."""
    if not icmp_result.alive:
        return "Host appears down or ICMP filtered"
    parts = ["Host is up"]
    if icmp_result.ttl:
        parts.append(f"TTL={icmp_result.ttl}")
    if icmp_result.os_hint:
        parts.append(f"OS hint: {icmp_result.os_hint}")
    if icmp_result.latency_ms:
        parts.append(f"latency={icmp_result.latency_ms}ms")
    return ", ".join(parts)
