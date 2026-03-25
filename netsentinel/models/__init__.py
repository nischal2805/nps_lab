"""NetSentinel data models."""

from .finding import Finding, CVSSBreakdown, Evidence
from .manifest import (
    AttackSurfaceManifest,
    PortEntry,
    RouteEntry,
    SecretEntry,
    OutboundHost,
    TLSConfig,
    DNSConfig,
)
from .scan_config import ScanConfig
from .scan_result import (
    ScanResult,
    Scores,
    DomainScore,
    OWASPCoverage,
    ScoreSummary,
)

__all__ = [
    # Finding models
    "Finding",
    "CVSSBreakdown",
    "Evidence",
    # Manifest models
    "AttackSurfaceManifest",
    "PortEntry",
    "RouteEntry",
    "SecretEntry",
    "OutboundHost",
    "TLSConfig",
    "DNSConfig",
    # Config models
    "ScanConfig",
    # Result models
    "ScanResult",
    "Scores",
    "DomainScore",
    "OWASPCoverage",
    "ScoreSummary",
]
