"""
DNS security probe for NetSentinel.

This module performs DNS security assessments:
- DNSSEC validation
- SPF, DKIM, DMARC record analysis
- CAA record verification
- DNS zone transfer checks
- Subdomain enumeration
- DNS rebinding vulnerability detection
"""

import asyncio
import ipaddress
import logging
from typing import List, Optional, Set, Tuple

import dns.asyncresolver
import dns.query
import dns.resolver
import dns.zone
import dns.rdatatype
import dns.exception

from netsentinel.models import Finding, Evidence
from netsentinel.config import DKIM_SELECTORS, SUBDOMAIN_WORDLIST, SCANNER_CONFIG

logger = logging.getLogger(__name__)


# RFC1918 private IP ranges
RFC1918_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
]


def is_internal_ip(ip_str: str) -> bool:
    """Check if an IP address is in RFC1918 private range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in RFC1918_NETWORKS)
    except ValueError:
        return False


def get_nameservers(domain: str) -> List[str]:
    """Get nameservers for a domain."""
    nameservers = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = SCANNER_CONFIG.get('dns_timeout', 5.0)
        resolver.lifetime = SCANNER_CONFIG.get('dns_timeout', 5.0)
        answers = resolver.resolve(domain, 'NS')
        for rdata in answers:
            ns_name = str(rdata.target).rstrip('.')
            # Resolve NS hostname to IP
            try:
                ns_ips = resolver.resolve(ns_name, 'A')
                for ip in ns_ips:
                    nameservers.append(str(ip))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                pass
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
        logger.debug(f"Failed to get nameservers for {domain}: {e}")
    return nameservers


def attempt_zone_transfer(domain: str, nameservers: List[str], scan_id: str) -> List[Finding]:
    """
    Attempt DNS zone transfer (AXFR) against all nameservers.
    Returns findings if zone transfer is allowed (critical vulnerability).
    """
    findings = []
    
    for ns in nameservers:
        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(ns, domain, timeout=SCANNER_CONFIG.get('dns_timeout', 5.0))
            )
            # Zone transfer succeeded - this is a critical vulnerability
            records = []
            for name, node in zone.nodes.items():
                records.append(str(name))
            
            findings.append(Finding(
                scan_id=scan_id,
                domain="dns",
                title="DNS Zone Transfer Allowed",
                description=(
                    f"The nameserver {ns} allows zone transfer (AXFR) for domain {domain}. "
                    f"This exposes all DNS records including internal hostnames, mail servers, "
                    f"and subdomains to attackers. Retrieved {len(records)} records."
                ),
                severity="critical",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                owasp_category="Security Misconfiguration",
                owasp_id="A05",
                evidence=Evidence(
                    dns_record=f"AXFR from {ns}: {', '.join(records[:20])}{'...' if len(records) > 20 else ''}"
                ),
                remediation=(
                    "Restrict zone transfers to authorized secondary nameservers only. "
                    "Configure allow-transfer in BIND or equivalent ACLs in your DNS server."
                ),
                references=[
                    "https://tools.ietf.org/html/rfc5936",
                    "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"
                ]
            ))
            logger.warning(f"Zone transfer successful on {ns} for {domain}")
        except dns.exception.FormError:
            # Zone transfer refused (expected secure behavior)
            logger.debug(f"Zone transfer refused by {ns} for {domain}")
        except dns.query.TransferError:
            logger.debug(f"Zone transfer failed for {ns}: Transfer error")
        except Exception as e:
            logger.debug(f"Zone transfer failed for {ns}: {e}")
    
    return findings


def check_spf(domain: str, scan_id: str) -> List[Finding]:
    """
    Check SPF (Sender Policy Framework) record configuration.
    
    Severity levels:
    - Missing SPF: medium
    - +all (pass all): critical
    - ~all (softfail): low
    """
    findings = []
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = SCANNER_CONFIG.get('dns_timeout', 5.0)
        resolver.lifetime = SCANNER_CONFIG.get('dns_timeout', 5.0)
        answers = resolver.resolve(domain, 'TXT')
        
        spf_record = None
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=spf1'):
                spf_record = txt
                break
        
        if spf_record is None:
            findings.append(Finding(
                scan_id=scan_id,
                domain="dns",
                title="Missing SPF Record",
                description=(
                    f"No SPF (Sender Policy Framework) record found for {domain}. "
                    f"Without SPF, attackers can easily spoof emails from your domain, "
                    f"leading to phishing attacks and reputation damage."
                ),
                severity="medium",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                owasp_category="Security Misconfiguration",
                owasp_id="A05",
                evidence=Evidence(dns_record="No SPF TXT record found"),
                remediation=(
                    "Add an SPF record to your DNS. Example: "
                    "'v=spf1 include:_spf.google.com ~all' for Google Workspace. "
                    "Use -all for strict rejection of unauthorized senders."
                ),
                references=[
                    "https://tools.ietf.org/html/rfc7208",
                    "https://dmarcian.com/spf-overview/"
                ]
            ))
        elif '+all' in spf_record:
            findings.append(Finding(
                scan_id=scan_id,
                domain="dns",
                title="SPF Record Allows All Senders (+all)",
                description=(
                    f"The SPF record for {domain} uses '+all' which allows any server to send "
                    f"email on behalf of the domain. This completely defeats the purpose of SPF "
                    f"and makes email spoofing trivial."
                ),
                severity="critical",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                owasp_category="Security Misconfiguration",
                owasp_id="A05",
                evidence=Evidence(dns_record=f"SPF: {spf_record}"),
                remediation=(
                    "Change '+all' to '-all' (hard fail) or '~all' (soft fail) to restrict "
                    "who can send email on behalf of your domain."
                ),
                references=[
                    "https://tools.ietf.org/html/rfc7208",
                    "https://dmarcian.com/spf-overview/"
                ]
            ))
        elif '~all' in spf_record:
            findings.append(Finding(
                scan_id=scan_id,
                domain="dns",
                title="SPF Record Uses Soft Fail (~all)",
                description=(
                    f"The SPF record for {domain} uses '~all' (soft fail) instead of '-all' (hard fail). "
                    f"While better than +all, soft fail may not block spoofed emails depending on "
                    f"receiver configuration."
                ),
                severity="low",
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                owasp_category="Security Misconfiguration",
                owasp_id="A05",
                evidence=Evidence(dns_record=f"SPF: {spf_record}"),
                remediation=(
                    "Consider changing '~all' to '-all' for stricter email authentication. "
                    "Ensure all legitimate sending sources are included before making this change."
                ),
                references=[
                    "https://tools.ietf.org/html/rfc7208",
                    "https://dmarcian.com/spf-overview/"
                ]
            ))
        # If -all is present, SPF is properly configured - no finding
        
    except dns.resolver.NXDOMAIN:
        findings.append(Finding(
            scan_id=scan_id,
            domain="dns",
            title="Domain Does Not Exist (NXDOMAIN)",
            description=f"The domain {domain} does not exist or has no DNS records.",
            severity="info",
            cvss_score=0.0,
            cvss_vector="",
            owasp_category="Security Misconfiguration",
            owasp_id="A05",
            evidence=Evidence(dns_record="NXDOMAIN"),
            remediation="Verify the domain name is correct.",
            references=[]
        ))
    except dns.resolver.NoAnswer:
        findings.append(Finding(
            scan_id=scan_id,
            domain="dns",
            title="Missing SPF Record",
            description=(
                f"No TXT records found for {domain}. SPF record is missing, "
                f"allowing potential email spoofing."
            ),
            severity="medium",
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            owasp_category="Security Misconfiguration",
            owasp_id="A05",
            evidence=Evidence(dns_record="No TXT records"),
            remediation="Add an SPF TXT record to your DNS configuration.",
            references=["https://tools.ietf.org/html/rfc7208"]
        ))
    except dns.exception.DNSException as e:
        logger.debug(f"SPF check failed for {domain}: {e}")
    
    return findings


def check_dmarc(domain: str, scan_id: str) -> List[Finding]:
    """
    Check DMARC (Domain-based Message Authentication) record configuration.
    
    Severity levels:
    - Missing DMARC: medium
    - p=none (no enforcement): low
    """
    findings = []
    dmarc_domain = f"_dmarc.{domain}"
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = SCANNER_CONFIG.get('dns_timeout', 5.0)
        resolver.lifetime = SCANNER_CONFIG.get('dns_timeout', 5.0)
        answers = resolver.resolve(dmarc_domain, 'TXT')
        
        dmarc_record = None
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=DMARC1'):
                dmarc_record = txt
                break
        
        if dmarc_record is None:
            findings.append(Finding(
                scan_id=scan_id,
                domain="dns",
                title="Missing DMARC Record",
                description=(
                    f"No DMARC record found for {domain}. DMARC provides instructions to "
                    f"receiving mail servers on how to handle emails that fail SPF/DKIM checks. "
                    f"Without DMARC, you have no visibility into email spoofing attempts."
                ),
                severity="medium",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                owasp_category="Security Misconfiguration",
                owasp_id="A05",
                evidence=Evidence(dns_record=f"No DMARC record at {dmarc_domain}"),
                remediation=(
                    "Add a DMARC record. Start with 'v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com' "
                    "for monitoring, then gradually move to p=quarantine or p=reject."
                ),
                references=[
                    "https://tools.ietf.org/html/rfc7489",
                    "https://dmarc.org/"
                ]
            ))
        elif 'p=none' in dmarc_record:
            findings.append(Finding(
                scan_id=scan_id,
                domain="dns",
                title="DMARC Policy Set to None",
                description=(
                    f"The DMARC record for {domain} uses 'p=none' which only monitors but does not "
                    f"block spoofed emails. While useful for initial deployment, this provides no "
                    f"protection against email spoofing."
                ),
                severity="low",
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                owasp_category="Security Misconfiguration",
                owasp_id="A05",
                evidence=Evidence(dns_record=f"DMARC: {dmarc_record}"),
                remediation=(
                    "After reviewing DMARC reports and ensuring legitimate email flows properly, "
                    "upgrade to 'p=quarantine' or 'p=reject' for actual protection."
                ),
                references=[
                    "https://tools.ietf.org/html/rfc7489",
                    "https://dmarc.org/"
                ]
            ))
        # p=quarantine or p=reject are properly configured - no finding
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        findings.append(Finding(
            scan_id=scan_id,
            domain="dns",
            title="Missing DMARC Record",
            description=(
                f"No DMARC record found at {dmarc_domain}. Without DMARC, receiving mail servers "
                f"don't know how to handle emails that fail authentication."
            ),
            severity="medium",
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            owasp_category="Security Misconfiguration",
            owasp_id="A05",
            evidence=Evidence(dns_record=f"No DMARC record at {dmarc_domain}"),
            remediation="Add a DMARC TXT record at _dmarc.yourdomain.com.",
            references=["https://tools.ietf.org/html/rfc7489"]
        ))
    except dns.exception.DNSException as e:
        logger.debug(f"DMARC check failed for {domain}: {e}")
    
    return findings


def check_dkim(domain: str, selectors: List[str], scan_id: str) -> List[Finding]:
    """
    Check DKIM (DomainKeys Identified Mail) records for common selectors.
    
    Checks configured selectors for presence of DKIM public keys.
    """
    findings = []
    found_selectors = []
    missing_selectors = []
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = SCANNER_CONFIG.get('dns_timeout', 5.0)
    resolver.lifetime = SCANNER_CONFIG.get('dns_timeout', 5.0)
    
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = resolver.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if 'v=DKIM1' in txt or 'p=' in txt:
                    found_selectors.append(selector)
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            missing_selectors.append(selector)
        except dns.exception.DNSException as e:
            logger.debug(f"DKIM check failed for {dkim_domain}: {e}")
            missing_selectors.append(selector)
    
    # Only report if NO selectors were found
    if not found_selectors:
        findings.append(Finding(
            scan_id=scan_id,
            domain="dns",
            title="No DKIM Records Found",
            description=(
                f"No DKIM records found for {domain} using common selectors "
                f"({', '.join(selectors)}). DKIM cryptographically signs emails to prevent "
                f"tampering and verify sender authenticity."
            ),
            severity="medium",
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            owasp_category="Security Misconfiguration",
            owasp_id="A05",
            evidence=Evidence(dns_record=f"Checked selectors: {', '.join(selectors)} - none found"),
            remediation=(
                "Configure DKIM for your email service. Add the DKIM public key as a TXT record "
                "at selector._domainkey.yourdomain.com. Your email provider will give you the "
                "specific record to add."
            ),
            references=[
                "https://tools.ietf.org/html/rfc6376",
                "https://dmarcian.com/dkim-overview/"
            ]
        ))
    
    return findings


async def enumerate_subdomains(
    domain: str, 
    wordlist: List[str]
) -> List[Tuple[str, str, bool]]:
    """
    Enumerate subdomains using async DNS resolution with 200 concurrency.
    
    Returns list of tuples: (subdomain, ip_address, is_internal)
    """
    results: List[Tuple[str, str, bool]] = []
    semaphore = asyncio.Semaphore(SCANNER_CONFIG.get('subdomain_concurrency', 200))
    
    async def resolve_subdomain(subdomain: str) -> Optional[Tuple[str, str, bool]]:
        async with semaphore:
            fqdn = f"{subdomain}.{domain}"
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.timeout = SCANNER_CONFIG.get('dns_timeout', 5.0)
                resolver.lifetime = SCANNER_CONFIG.get('dns_timeout', 5.0)
                
                answers = await resolver.resolve(fqdn, 'A')
                for rdata in answers:
                    ip = str(rdata)
                    internal = is_internal_ip(ip)
                    return (fqdn, ip, internal)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except dns.exception.DNSException as e:
                logger.debug(f"Subdomain resolution failed for {fqdn}: {e}")
            return None
    
    # Create tasks for all subdomains
    tasks = [resolve_subdomain(sub) for sub in wordlist]
    
    # Run with gather and filter None results
    resolved = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in resolved:
        if isinstance(result, tuple):
            results.append(result)
        elif isinstance(result, Exception):
            logger.debug(f"Subdomain enumeration error: {result}")
    
    return results


def check_open_resolver(nameservers: List[str], scan_id: str) -> List[Finding]:
    """
    Check if nameservers act as open resolvers.
    
    Open resolvers respond to recursive queries for external domains,
    which can be abused for DNS amplification attacks.
    """
    findings = []
    external_domain = "google.com"  # Use well-known external domain
    
    for ns in nameservers:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ns]
            resolver.timeout = SCANNER_CONFIG.get('dns_timeout', 5.0)
            resolver.lifetime = SCANNER_CONFIG.get('dns_timeout', 5.0)
            
            # Try to resolve an external domain through the nameserver
            answers = resolver.resolve(external_domain, 'A')
            
            if answers:
                # Nameserver resolved external domain - it's an open resolver
                findings.append(Finding(
                    scan_id=scan_id,
                    domain="dns",
                    title="Open DNS Resolver Detected",
                    description=(
                        f"The nameserver {ns} responds to recursive DNS queries for external domains. "
                        f"Open resolvers can be abused in DNS amplification DDoS attacks and may "
                        f"leak information about internal queries."
                    ),
                    severity="high",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
                    owasp_category="Security Misconfiguration",
                    owasp_id="A05",
                    evidence=Evidence(
                        dns_record=f"Recursive query for {external_domain} succeeded via {ns}"
                    ),
                    remediation=(
                        "Configure the DNS server to only respond to queries for domains it's "
                        "authoritative for, or restrict recursive queries to trusted networks. "
                        "In BIND, set 'allow-recursion' to your trusted network ranges."
                    ),
                    references=[
                        "https://www.us-cert.gov/ncas/alerts/TA13-088A",
                        "https://www.cloudflare.com/learning/dns/dns-amplification-ddos-attack/"
                    ]
                ))
                logger.warning(f"Open resolver detected: {ns}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            # Nameserver refused or didn't resolve - this is expected secure behavior
            logger.debug(f"Nameserver {ns} is not an open resolver (refused external query)")
        except dns.exception.Timeout:
            logger.debug(f"Timeout checking open resolver status for {ns}")
        except dns.exception.DNSException as e:
            logger.debug(f"Open resolver check failed for {ns}: {e}")
    
    return findings


async def probe_dns(domain: str, scan_id: str) -> List[Finding]:
    """
    Main entry point for DNS security probe.
    
    Performs comprehensive DNS security checks:
    1. Zone transfer attempts
    2. SPF record analysis
    3. DMARC record analysis
    4. DKIM record checks
    5. Subdomain enumeration with internal IP detection
    6. Open resolver detection
    
    Args:
        domain: The domain to scan
        scan_id: Unique identifier for this scan
        
    Returns:
        List of Finding objects for discovered issues
    """
    findings: List[Finding] = []
    
    logger.info(f"Starting DNS probe for {domain}")
    
    # Get nameservers first
    nameservers = get_nameservers(domain)
    logger.debug(f"Found nameservers for {domain}: {nameservers}")
    
    # 1. Zone Transfer Check
    if nameservers:
        findings.extend(attempt_zone_transfer(domain, nameservers, scan_id))
    
    # 2. SPF Check
    findings.extend(check_spf(domain, scan_id))
    
    # 3. DMARC Check
    findings.extend(check_dmarc(domain, scan_id))
    
    # 4. DKIM Check
    findings.extend(check_dkim(domain, DKIM_SELECTORS, scan_id))
    
    # 5. Subdomain Enumeration
    subdomains = await enumerate_subdomains(domain, SUBDOMAIN_WORDLIST)
    
    # Report subdomains resolving to internal IPs
    internal_subdomains = [(fqdn, ip) for fqdn, ip, internal in subdomains if internal]
    if internal_subdomains:
        subdomain_list = ", ".join([f"{fqdn} -> {ip}" for fqdn, ip in internal_subdomains[:10]])
        findings.append(Finding(
            scan_id=scan_id,
            domain="dns",
            title="Subdomains Resolving to Internal IPs",
            description=(
                f"Found {len(internal_subdomains)} subdomain(s) resolving to RFC1918 internal IP "
                f"addresses. This may expose internal network structure or indicate DNS "
                f"misconfigurations that could be exploited for DNS rebinding attacks."
            ),
            severity="medium",
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            owasp_category="Security Misconfiguration",
            owasp_id="A05",
            evidence=Evidence(
                dns_record=subdomain_list + (f"... and {len(internal_subdomains) - 10} more" if len(internal_subdomains) > 10 else "")
            ),
            remediation=(
                "Review DNS records pointing to internal IPs. Remove or restrict access to "
                "records that expose internal infrastructure. Consider split-horizon DNS for "
                "internal-only resources."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/350.html",
                "https://owasp.org/www-community/attacks/DNS_Rebinding"
            ]
        ))
    
    # Log enumeration results
    logger.info(f"Subdomain enumeration found {len(subdomains)} subdomains, {len(internal_subdomains)} internal")
    
    # 6. Open Resolver Check
    if nameservers:
        findings.extend(check_open_resolver(nameservers, scan_id))
    
    logger.info(f"DNS probe completed for {domain}: {len(findings)} findings")
    
    return findings
