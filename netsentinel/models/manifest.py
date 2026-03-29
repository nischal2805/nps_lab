"""Attack Surface Manifest - output of static analysis."""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any


@dataclass
class PortEntry:
    """A port extracted from static analysis."""
    port: int
    protocol: str  # tcp, udp
    source_file: str
    line: int
    service_hint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: Dict[str, Any] = {
            "port": self.port,
            "protocol": self.protocol,
            "source_file": self.source_file,
            "line": self.line,
        }
        if self.service_hint is not None:
            result["service_hint"] = self.service_hint
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PortEntry':
        """Create PortEntry from dictionary."""
        return cls(
            port=int(data.get("port", 0)),
            protocol=data.get("protocol", "tcp"),
            source_file=data.get("source_file", ""),
            line=int(data.get("line", 0)),
            service_hint=data.get("service_hint"),
        )


@dataclass
class RouteEntry:
    """An HTTP route extracted from static analysis."""
    method: str  # GET, POST, PUT, DELETE, etc.
    path: str
    source_file: str
    line: int
    auth_hint: Optional[str] = None  # none, token, session, etc.
    framework: Optional[str] = None  # express, flask, fastapi, spring

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: Dict[str, Any] = {
            "method": self.method,
            "path": self.path,
            "source_file": self.source_file,
            "line": self.line,
        }
        if self.auth_hint is not None:
            result["auth_hint"] = self.auth_hint
        if self.framework is not None:
            result["framework"] = self.framework
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RouteEntry':
        """Create RouteEntry from dictionary."""
        return cls(
            method=data.get("method", "GET"),
            path=data.get("path", "/"),
            source_file=data.get("source_file", ""),
            line=int(data.get("line", 0)),
            auth_hint=data.get("auth_hint"),
            framework=data.get("framework"),
        )


@dataclass
class SecretEntry:
    """A secret or credential found in static analysis."""
    type: str  # aws_key, stripe_key, github_token, etc.
    file: str
    line: int
    preview: str  # Redacted preview like "sk_live_****"
    severity: str = "critical"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "type": self.type,
            "file": self.file,
            "line": self.line,
            "preview": self.preview,
            "severity": self.severity,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecretEntry':
        """Create SecretEntry from dictionary."""
        return cls(
            type=data.get("type", ""),
            file=data.get("file", ""),
            line=int(data.get("line", 0)),
            preview=data.get("preview", ""),
            severity=data.get("severity", "critical"),
        )


@dataclass
class OutboundHost:
    """An outbound host reference found in static analysis."""
    host: str
    source_file: str
    line: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "host": self.host,
            "source_file": self.source_file,
            "line": self.line,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OutboundHost':
        """Create OutboundHost from dictionary."""
        return cls(
            host=data.get("host", ""),
            source_file=data.get("source_file", ""),
            line=int(data.get("line", 0)),
        )


@dataclass
class TLSConfig:
    """TLS configuration hints from static analysis."""
    version_hint: Optional[str] = None
    cert_verification_disabled: bool = False
    cert_pinning: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: Dict[str, Any] = {
            "cert_verification_disabled": self.cert_verification_disabled,
            "cert_pinning": self.cert_pinning,
        }
        if self.version_hint is not None:
            result["version_hint"] = self.version_hint
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TLSConfig':
        """Create TLSConfig from dictionary."""
        return cls(
            version_hint=data.get("version_hint"),
            cert_verification_disabled=bool(data.get("cert_verification_disabled", False)),
            cert_pinning=bool(data.get("cert_pinning", False)),
        )


@dataclass
class DNSConfig:
    """DNS configuration hints from static analysis."""
    custom_resolver: bool = False
    hardcoded_entries: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "custom_resolver": self.custom_resolver,
            "hardcoded_entries": self.hardcoded_entries,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DNSConfig':
        """Create DNSConfig from dictionary."""
        return cls(
            custom_resolver=bool(data.get("custom_resolver", False)),
            hardcoded_entries=data.get("hardcoded_entries", []),
        )


@dataclass
class DependencyEntry:
    """A dependency extracted from package manifests (SBOM)."""
    name: str
    version: str
    ecosystem: str  # npm, PyPI, Go, Maven, etc.
    source_file: str
    vulnerable: bool = False
    vulnerability_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "source_file": self.source_file,
            "vulnerable": self.vulnerable,
            "vulnerability_count": self.vulnerability_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DependencyEntry':
        """Create DependencyEntry from dictionary."""
        return cls(
            name=data.get("name", ""),
            version=data.get("version", ""),
            ecosystem=data.get("ecosystem", ""),
            source_file=data.get("source_file", ""),
            vulnerable=bool(data.get("vulnerable", False)),
            vulnerability_count=int(data.get("vulnerability_count", 0)),
        )


@dataclass
class AttackSurfaceManifest:
    """Complete attack surface manifest from static analysis."""
    scan_id: str
    target: str  # repo URL or local path
    extracted_at: str
    language_detected: List[str] = field(default_factory=list)
    ports: List[PortEntry] = field(default_factory=list)
    routes: List[RouteEntry] = field(default_factory=list)
    outbound_hosts: List[OutboundHost] = field(default_factory=list)
    secrets_found: List[SecretEntry] = field(default_factory=list)
    dependencies: List[DependencyEntry] = field(default_factory=list)
    tls_config: Optional[TLSConfig] = None
    dns_config: Optional[DNSConfig] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: Dict[str, Any] = {
            "scan_id": self.scan_id,
            "target": self.target,
            "extracted_at": self.extracted_at,
            "language_detected": self.language_detected,
            "ports": [p.to_dict() for p in self.ports],
            "routes": [r.to_dict() for r in self.routes],
            "outbound_hosts": [h.to_dict() for h in self.outbound_hosts],
            "secrets_found": [s.to_dict() for s in self.secrets_found],
            "dependencies": [d.to_dict() for d in self.dependencies],
        }
        if self.tls_config is not None:
            result["tls_config"] = self.tls_config.to_dict()
        if self.dns_config is not None:
            result["dns_config"] = self.dns_config.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AttackSurfaceManifest':
        """Create manifest from dictionary."""
        ports = [PortEntry.from_dict(p) for p in data.get("ports", [])]
        routes = [RouteEntry.from_dict(r) for r in data.get("routes", [])]
        outbound_hosts = [OutboundHost.from_dict(h) for h in data.get("outbound_hosts", [])]
        secrets_found = [SecretEntry.from_dict(s) for s in data.get("secrets_found", [])]
        dependencies = [DependencyEntry.from_dict(d) for d in data.get("dependencies", [])]

        tls_config = None
        if data.get("tls_config"):
            tls_config = TLSConfig.from_dict(data["tls_config"])

        dns_config = None
        if data.get("dns_config"):
            dns_config = DNSConfig.from_dict(data["dns_config"])

        return cls(
            scan_id=data.get("scan_id", ""),
            target=data.get("target", ""),
            extracted_at=data.get("extracted_at", ""),
            language_detected=data.get("language_detected", []),
            ports=ports,
            routes=routes,
            outbound_hosts=outbound_hosts,
            secrets_found=secrets_found,
            dependencies=dependencies,
            tls_config=tls_config,
            dns_config=dns_config,
        )
