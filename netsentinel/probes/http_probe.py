"""
HTTP security probe for NetSentinel.

This module analyzes HTTP security configurations:
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- Cookie security attributes (Secure, HttpOnly, SameSite)
- CORS configuration analysis
- HTTP methods enumeration
- Redirect chain analysis
- Mixed content detection
"""
import logging
import re
from typing import List, Optional

import httpx

logger = logging.getLogger(__name__)

from netsentinel.config import (
    DATABASE_ERROR_PATTERNS,
    DEFAULT_ROUTES,
    SECURITY_HEADERS,
    SENSITIVE_PATHS,
    USER_AGENT,
)
from netsentinel.models import Evidence, Finding


# Sensitive paths with severity and description
SENSITIVE_PATH_CONFIG = [
    ('/.env', 'critical', 'Environment file exposed'),
    ('/.git/config', 'critical', 'Git config exposed'),
    ('/wp-config.php', 'critical', 'WordPress config exposed'),
    ('/config.php', 'high', 'Config file exposed'),
    ('/server-status', 'medium', 'Server status exposed'),
    ('/.htaccess', 'medium', 'htaccess exposed'),
    ('/phpinfo.php', 'high', 'PHP info exposed'),
    ('/adminer.php', 'critical', 'Database admin exposed'),
    ('/.svn/entries', 'critical', 'SVN entries exposed'),
    ('/web.config', 'high', 'Web config exposed'),
    ('/.DS_Store', 'low', 'DS_Store file exposed'),
    ('/backup.sql', 'critical', 'SQL backup exposed'),
    ('/database.sql', 'critical', 'Database dump exposed'),
    ('/.bash_history', 'critical', 'Bash history exposed'),
    ('/.ssh/id_rsa', 'critical', 'SSH private key exposed'),
    ('/composer.json', 'low', 'Composer manifest exposed'),
    ('/package.json', 'low', 'NPM manifest exposed'),
    ('/secrets.yml', 'critical', 'Secrets file exposed'),
    ('/credentials.json', 'critical', 'Credentials file exposed'),
    ('/.aws/credentials', 'critical', 'AWS credentials exposed'),
]

# XSS test parameters
XSS_TEST_PARAMS = ['q', 'search', 'query', 'id', 'name', 'input', 'text', 'value']

# SQLi test parameters
SQLI_TEST_PARAMS = ['id', 'user', 'page', 'cat', 'item', 'product', 'order']

# SQLi payloads for detection
SQLI_PAYLOADS = ["'", '"', "' OR '1'='1", "1' OR '1'='1' --"]

# Dangerous HTTP methods
DANGEROUS_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT']


def check_security_headers(
    client: httpx.Client, base_url: str, routes: List[str], scan_id: str
) -> List[Finding]:
    """Check for missing or weak security headers."""
    findings = []

    for route in routes:
        try:
            response = client.get(f'{base_url}{route}')
            response_headers_lower = {h.lower(): v for h, v in response.headers.items()}

            # Check each required header
            for header, (issue, severity) in SECURITY_HEADERS.items():
                if header.lower() not in response_headers_lower:
                    findings.append(Finding(
                        scan_id=scan_id,
                        domain='http',
                        title=f'Missing {header} header on {route}',
                        description=f'The {header} security header is not present in the response.',
                        severity=severity,
                        owasp_id='A05',
                        owasp_category='Security Misconfiguration',
                        evidence=Evidence(
                            raw_request=f'GET {route}',
                            raw_response=str(dict(response.headers))
                        ),
                        remediation=f'Add {header} header to HTTP responses'
                    ))

            # Check CSP value if present
            csp = response_headers_lower.get('content-security-policy', '')
            if csp:
                if 'default-src *' in csp or "default-src '*'" in csp:
                    findings.append(Finding(
                        scan_id=scan_id,
                        domain='http',
                        title=f'Weak CSP on {route}: default-src *',
                        description='Content-Security-Policy allows all sources, defeating its purpose.',
                        severity='medium',
                        owasp_id='A05',
                        owasp_category='Security Misconfiguration',
                        evidence=Evidence(
                            raw_request=f'GET {route}',
                            raw_response=f'CSP: {csp}'
                        ),
                        remediation='Restrict CSP default-src to specific trusted domains'
                    ))

                if "'unsafe-inline'" in csp and "'unsafe-eval'" in csp:
                    findings.append(Finding(
                        scan_id=scan_id,
                        domain='http',
                        title=f'Weak CSP on {route}: unsafe-inline and unsafe-eval',
                        description='CSP allows both inline scripts and eval, reducing XSS protection.',
                        severity='medium',
                        owasp_id='A05',
                        owasp_category='Security Misconfiguration',
                        evidence=Evidence(
                            raw_request=f'GET {route}',
                            raw_response=f'CSP: {csp}'
                        ),
                        remediation='Remove unsafe-inline and unsafe-eval from CSP'
                    ))

        except httpx.RequestError:
            pass

    return findings


def check_cors(
    client: httpx.Client, base_url: str, routes: List[str], scan_id: str
) -> List[Finding]:
    """Check for CORS misconfigurations."""
    findings = []

    # Limit to first 5 routes to avoid excessive requests
    for route in routes[:5]:
        url = f'{base_url}{route}'

        # Test 1: Arbitrary origin reflection
        try:
            response = client.get(url, headers={'Origin': 'https://evil.com'})
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')

            if acao == 'https://evil.com':
                severity = 'critical' if acac.lower() == 'true' else 'high'
                findings.append(Finding(
                    scan_id=scan_id,
                    domain='http',
                    title=f'CORS misconfiguration on {route}',
                    description='Arbitrary origin is reflected in Access-Control-Allow-Origin header.',
                    severity=severity,
                    owasp_id='A01',
                    owasp_category='Broken Access Control',
                    evidence=Evidence(
                        raw_request=f'GET {route}\nOrigin: https://evil.com',
                        raw_response=f'Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}'
                    ),
                    remediation='Configure CORS to allow only trusted origins'
                ))
            elif acao == '*':
                severity = 'high' if acac.lower() == 'true' else 'medium'
                findings.append(Finding(
                    scan_id=scan_id,
                    domain='http',
                    title=f'CORS wildcard origin on {route}',
                    description='Access-Control-Allow-Origin is set to wildcard (*), allowing any origin.',
                    severity=severity,
                    owasp_id='A01',
                    owasp_category='Broken Access Control',
                    evidence=Evidence(
                        raw_request=f'GET {route}\nOrigin: https://evil.com',
                        raw_response=f'Access-Control-Allow-Origin: {acao}'
                    ),
                    remediation='Replace wildcard with specific trusted origins'
                ))
        except httpx.RequestError:
            pass

        # Test 2: Null origin acceptance
        try:
            response = client.get(url, headers={'Origin': 'null'})
            acao = response.headers.get('Access-Control-Allow-Origin', '')

            if acao == 'null':
                findings.append(Finding(
                    scan_id=scan_id,
                    domain='http',
                    title=f'CORS accepts null origin on {route}',
                    description='Server accepts null origin which can be exploited via sandboxed iframes.',
                    severity='high',
                    owasp_id='A01',
                    owasp_category='Broken Access Control',
                    evidence=Evidence(
                        raw_request=f'GET {route}\nOrigin: null',
                        raw_response=f'Access-Control-Allow-Origin: {acao}'
                    ),
                    remediation='Do not allow null origin in CORS configuration'
                ))
        except httpx.RequestError:
            pass

        # Test 3: Prefix/suffix bypass attempt
        try:
            # Try subdomain bypass (e.g., evil.trusted.com)
            response = client.get(url, headers={'Origin': 'https://evil.trusted.com'})
            acao = response.headers.get('Access-Control-Allow-Origin', '')

            if acao == 'https://evil.trusted.com':
                findings.append(Finding(
                    scan_id=scan_id,
                    domain='http',
                    title=f'CORS origin validation bypass on {route}',
                    description='CORS origin validation may be using weak regex allowing subdomain bypass.',
                    severity='high',
                    owasp_id='A01',
                    owasp_category='Broken Access Control',
                    evidence=Evidence(
                        raw_request=f'GET {route}\nOrigin: https://evil.trusted.com',
                        raw_response=f'Access-Control-Allow-Origin: {acao}'
                    ),
                    remediation='Use strict origin matching, not regex-based validation'
                ))
        except httpx.RequestError:
            pass

    return findings


def check_sensitive_paths(
    client: httpx.Client, base_url: str, scan_id: str
) -> List[Finding]:
    """Check for exposed sensitive files/paths."""
    findings = []

    for path, severity, title in SENSITIVE_PATH_CONFIG:
        try:
            response = client.get(f'{base_url}{path}')

            # Check for successful response with content
            if response.status_code == 200:
                # Additional validation: check if response has meaningful content
                content_length = len(response.content)
                if content_length > 0:
                    findings.append(Finding(
                        scan_id=scan_id,
                        domain='http',
                        title=title,
                        description=f'Sensitive file {path} is accessible and returned content.',
                        severity=severity,
                        owasp_id='A01',
                        owasp_category='Broken Access Control',
                        evidence=Evidence(
                            raw_request=f'GET {path}',
                            raw_response=f'Status: {response.status_code}, Content-Length: {content_length}'
                        ),
                        remediation=f'Block access to {path} or remove the file from the server'
                    ))
        except httpx.RequestError:
            pass

    return findings


def check_info_leakage(
    client: httpx.Client, base_url: str, scan_id: str
) -> List[Finding]:
    """Check for information disclosure in headers."""
    findings = []

    try:
        response = client.get(base_url)

        # Server header with version
        server = response.headers.get('Server', '')
        if server and any(c.isdigit() for c in server):
            findings.append(Finding(
                scan_id=scan_id,
                domain='http',
                title=f'Server version disclosed: {server}',
                description='Server header reveals version information that could aid attackers.',
                severity='low',
                owasp_id='A05',
                owasp_category='Security Misconfiguration',
                evidence=Evidence(
                    raw_request='GET /',
                    raw_response=f'Server: {server}'
                ),
                remediation='Remove or obfuscate the Server header'
            ))

        # X-Powered-By header
        powered_by = response.headers.get('X-Powered-By', '')
        if powered_by:
            findings.append(Finding(
                scan_id=scan_id,
                domain='http',
                title=f'Technology disclosed: {powered_by}',
                description='X-Powered-By header reveals technology stack information.',
                severity='low',
                owasp_id='A05',
                owasp_category='Security Misconfiguration',
                evidence=Evidence(
                    raw_request='GET /',
                    raw_response=f'X-Powered-By: {powered_by}'
                ),
                remediation='Remove the X-Powered-By header'
            ))

        # X-AspNet-Version header
        aspnet_version = response.headers.get('X-AspNet-Version', '')
        if aspnet_version:
            findings.append(Finding(
                scan_id=scan_id,
                domain='http',
                title=f'ASP.NET version disclosed: {aspnet_version}',
                description='X-AspNet-Version header reveals framework version.',
                severity='low',
                owasp_id='A05',
                owasp_category='Security Misconfiguration',
                evidence=Evidence(
                    raw_request='GET /',
                    raw_response=f'X-AspNet-Version: {aspnet_version}'
                ),
                remediation='Remove the X-AspNet-Version header'
            ))

        # X-AspNetMvc-Version header
        mvc_version = response.headers.get('X-AspNetMvc-Version', '')
        if mvc_version:
            findings.append(Finding(
                scan_id=scan_id,
                domain='http',
                title=f'ASP.NET MVC version disclosed: {mvc_version}',
                description='X-AspNetMvc-Version header reveals framework version.',
                severity='low',
                owasp_id='A05',
                owasp_category='Security Misconfiguration',
                evidence=Evidence(
                    raw_request='GET /',
                    raw_response=f'X-AspNetMvc-Version: {mvc_version}'
                ),
                remediation='Remove the X-AspNetMvc-Version header'
            ))

    except httpx.RequestError:
        pass

    return findings


def check_http_methods(
    client: httpx.Client, base_url: str, routes: List[str], scan_id: str
) -> List[Finding]:
    """Check for dangerous HTTP methods enabled."""
    findings = []

    for route in routes[:3]:  # Limit to first 3 routes
        url = f'{base_url}{route}'

        # Check OPTIONS to discover allowed methods
        try:
            response = client.options(url)
            allow_header = response.headers.get('Allow', '')

            if allow_header:
                enabled_dangerous = [
                    method for method in DANGEROUS_METHODS
                    if method in allow_header.upper()
                ]

                for method in enabled_dangerous:
                    findings.append(Finding(
                        scan_id=scan_id,
                        domain='http',
                        title=f'Dangerous HTTP method {method} enabled on {route}',
                        description=f'The {method} HTTP method is enabled which could allow unauthorized actions.',
                        severity='medium' if method != 'TRACE' else 'low',
                        owasp_id='A05',
                        owasp_category='Security Misconfiguration',
                        evidence=Evidence(
                            raw_request=f'OPTIONS {route}',
                            raw_response=f'Allow: {allow_header}'
                        ),
                        remediation=f'Disable the {method} HTTP method if not required'
                    ))

        except httpx.RequestError:
            pass

        # Direct TRACE test (for XST vulnerability)
        try:
            response = client.request('TRACE', url)
            if response.status_code == 200:
                findings.append(Finding(
                    scan_id=scan_id,
                    domain='http',
                    title=f'TRACE method enabled on {route}',
                    description='TRACE method is enabled which can lead to Cross-Site Tracing (XST) attacks.',
                    severity='low',
                    owasp_id='A05',
                    owasp_category='Security Misconfiguration',
                    evidence=Evidence(
                        raw_request=f'TRACE {route}',
                        raw_response=f'Status: {response.status_code}'
                    ),
                    remediation='Disable the TRACE HTTP method'
                ))
        except httpx.RequestError:
            pass

    return findings


def check_xss_reflection(
    client: httpx.Client, base_url: str, routes: List[str], scan_id: str
) -> List[Finding]:
    """Check for reflected XSS - GET only, no state changes."""
    findings = []
    payload = '<script>netsentinel</script>'

    for route in routes[:3]:  # Limit to first 3 routes
        found_xss = False

        for param in XSS_TEST_PARAMS:
            if found_xss:
                break

            try:
                url = f'{base_url}{route}?{param}={payload}'
                response = client.get(url)

                if payload in response.text:
                    findings.append(Finding(
                        scan_id=scan_id,
                        domain='http',
                        title=f'Potential XSS on {route}',
                        description=f'Payload reflected unescaped in parameter "{param}".',
                        severity='high',
                        owasp_id='A03',
                        owasp_category='Injection',
                        evidence=Evidence(
                            raw_request=f'GET {route}?{param}={payload}',
                            raw_response='Payload found unescaped in response body'
                        ),
                        remediation='Encode output and implement Content-Security-Policy',
                        false_positive_risk='medium'
                    ))
                    found_xss = True  # One finding per route

            except httpx.RequestError:
                pass

    return findings


def check_sqli_errors(
    client: httpx.Client, base_url: str, routes: List[str], scan_id: str
) -> List[Finding]:
    """Check for SQL injection indicators - GET only."""
    findings = []

    # Compile patterns for efficiency
    compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in DATABASE_ERROR_PATTERNS]

    for route in routes[:3]:  # Limit to first 3 routes
        found_sqli = False

        for param in SQLI_TEST_PARAMS:
            if found_sqli:
                break

            for payload in SQLI_PAYLOADS:
                if found_sqli:
                    break

                try:
                    url = f'{base_url}{route}?{param}={payload}'
                    response = client.get(url)

                    for pattern in compiled_patterns:
                        if pattern.search(response.text):
                            findings.append(Finding(
                                scan_id=scan_id,
                                domain='http',
                                title=f'Potential SQL injection on {route}',
                                description=f'Database error message detected in response for parameter "{param}".',
                                severity='high',
                                owasp_id='A03',
                                owasp_category='Injection',
                                evidence=Evidence(
                                    raw_request=f'GET {route}?{param}={payload}',
                                    raw_response=f'Database error pattern detected: {pattern.pattern}'
                                ),
                                remediation='Use parameterized queries and prepared statements',
                                false_positive_risk='low'
                            ))
                            found_sqli = True
                            break

                except httpx.RequestError:
                    pass

    return findings


def check_cookie_security(
    client: httpx.Client, base_url: str, scan_id: str
) -> List[Finding]:
    """Check for insecure cookie configurations."""
    findings = []

    try:
        response = client.get(base_url)

        for cookie in response.cookies.jar:
            cookie_name = cookie.name
            issues = []

            # Check Secure flag (especially important for HTTPS)
            if not cookie.secure and base_url.startswith('https'):
                issues.append(('missing Secure flag', 'medium'))

            # Check HttpOnly flag
            # httpx Cookie objects don't have direct httponly attribute,
            # we need to check the raw Set-Cookie header
            set_cookie_headers = response.headers.get_list('set-cookie')
            for header in set_cookie_headers:
                if cookie_name in header:
                    if 'httponly' not in header.lower():
                        issues.append(('missing HttpOnly flag', 'medium'))
                    if 'samesite' not in header.lower():
                        issues.append(('missing SameSite attribute', 'low'))
                    break

            for issue, severity in issues:
                findings.append(Finding(
                    scan_id=scan_id,
                    domain='http',
                    title=f'Cookie "{cookie_name}" {issue}',
                    description=f'The cookie "{cookie_name}" is {issue}.',
                    severity=severity,
                    owasp_id='A05',
                    owasp_category='Security Misconfiguration',
                    evidence=Evidence(
                        raw_request='GET /',
                        raw_response=f'Set-Cookie: {cookie_name}=...'
                    ),
                    remediation=f'Add {issue.replace("missing ", "")} to the cookie'
                ))

    except httpx.RequestError:
        pass

    return findings


# Common HTTPS ports (should use https:// scheme)
HTTPS_PORTS = {443, 8443, 4443, 9443}


def _determine_scheme(port: int) -> str:
    """Determine HTTP scheme based on port number."""
    return 'https' if port in HTTPS_PORTS else 'http'


def _try_connect(client: httpx.Client, base_url: str) -> bool:
    """Test if the base URL is reachable."""
    try:
        response = client.get(f'{base_url}/', timeout=5.0)
        return response.status_code < 500
    except httpx.RequestError:
        return False


def probe_http(
    host: str,
    port: int,
    scan_id: str,
    routes: Optional[List[str]] = None
) -> List[Finding]:
    """
    Run all HTTP probes against the target.

    Args:
        host: IP address or domain
        port: Port to probe (usually 80 or 443)
        scan_id: UUID for this scan
        routes: Optional list of routes from manifest

    Returns:
        List of Finding objects
    """
    findings = []
    
    # Determine scheme based on port
    scheme = _determine_scheme(port)
    base_url = f'{scheme}://{host}:{port}'

    # Use routes from manifest or defaults
    routes_to_check = routes or DEFAULT_ROUTES

    try:
        with httpx.Client(
            timeout=10.0,
            verify=False,
            follow_redirects=True,
            headers={'User-Agent': USER_AGENT}
        ) as client:
            # Try primary scheme first, fallback to alternate if connection fails
            if not _try_connect(client, base_url):
                alt_scheme = 'http' if scheme == 'https' else 'https'
                alt_url = f'{alt_scheme}://{host}:{port}'
                logger.debug(f"Primary scheme {scheme} failed for {host}:{port}, trying {alt_scheme}")
                if _try_connect(client, alt_url):
                    base_url = alt_url
                    logger.info(f"Using alternate scheme: {base_url}")
                else:
                    logger.warning(f"HTTP probe: Cannot connect to {host}:{port} on either scheme")
                    return findings
            
            logger.info(f"HTTP probe starting for {base_url}")
            
            # 1. Security headers check
            findings.extend(check_security_headers(client, base_url, routes_to_check, scan_id))

            # 2. CORS misconfiguration
            findings.extend(check_cors(client, base_url, routes_to_check, scan_id))

            # 3. Sensitive paths
            findings.extend(check_sensitive_paths(client, base_url, scan_id))

            # 4. Information leakage
            findings.extend(check_info_leakage(client, base_url, scan_id))

            # 5. HTTP methods
            findings.extend(check_http_methods(client, base_url, routes_to_check, scan_id))

            # 6. Cookie security
            findings.extend(check_cookie_security(client, base_url, scan_id))

            # 7. XSS surface detection (GET only)
            findings.extend(check_xss_reflection(client, base_url, routes_to_check, scan_id))

            # 8. SQLi surface detection (GET only)
            findings.extend(check_sqli_errors(client, base_url, routes_to_check, scan_id))
            
            logger.info(f"HTTP probe completed for {base_url}: {len(findings)} findings")

    except httpx.RequestError as e:
        logger.warning(f"HTTP probe failed for {host}:{port}: {e}")

    return findings
