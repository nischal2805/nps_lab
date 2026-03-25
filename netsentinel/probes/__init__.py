"""
Network probes package for NetSentinel.

This package contains modules for actively probing network services
to assess their security configuration. Each probe module focuses
on a specific protocol or service type.
"""
from netsentinel.probes.http_probe import (
    probe_http,
    check_security_headers,
    check_cors,
    check_sensitive_paths,
    check_info_leakage,
    check_http_methods,
    check_xss_reflection,
    check_sqli_errors,
    check_cookie_security,
)
from netsentinel.probes.network import (
    probe_network,
    probe_icmp,
    scan_port,
    scan_tcp_ports,
    scan_udp_ports,
    grab_banner,
    grab_banners,
    classify_ports,
    check_undeclared_ports,
    PortResult,
    ICMPResult,
)

__all__ = [
    # HTTP probe
    "probe_http",
    "check_security_headers",
    "check_cors",
    "check_sensitive_paths",
    "check_info_leakage",
    "check_http_methods",
    "check_xss_reflection",
    "check_sqli_errors",
    "check_cookie_security",
    # Network probe (Module 3A)
    "probe_network",
    "probe_icmp",
    "scan_port",
    "scan_tcp_ports",
    "scan_udp_ports",
    "grab_banner",
    "grab_banners",
    "classify_ports",
    "check_undeclared_ports",
    "PortResult",
    "ICMPResult",
]
