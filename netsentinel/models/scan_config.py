"""Scan configuration - parsed from CLI flags."""
from dataclasses import dataclass, field
from typing import Optional, List
from uuid import uuid4


@dataclass
class ScanConfig:
    """Configuration for a scan, parsed from CLI arguments."""
    target: Optional[str] = None  # Local path or GitHub URL
    host: Optional[str] = None  # IP or domain
    port: Optional[int] = None  # Specific port to focus on
    live_only: bool = False  # Skip static analysis
    static_only: bool = False  # Skip live probing
    scan_id: Optional[str] = field(default_factory=lambda: str(uuid4()))

    def validate(self) -> List[str]:
        """Validate config and return list of errors."""
        errors: List[str] = []
        if not self.target and not self.host:
            errors.append("Either --target or --host must be provided")
        if self.live_only and self.static_only:
            errors.append("Cannot use both --live-only and --static-only")
        if self.live_only and not self.host:
            errors.append("--live-only requires --host")
        if self.static_only and not self.target:
            errors.append("--static-only requires --target")
        if self.port is not None:
            if self.port < 1 or self.port > 65535:
                errors.append("--port must be between 1 and 65535")
        return errors

    @property
    def is_github_url(self) -> bool:
        """Check if target is a GitHub URL."""
        if not self.target:
            return False
        return self.target.startswith('https://github.com/')

    @property
    def requires_static_analysis(self) -> bool:
        """Check if static analysis should be performed."""
        return not self.live_only and self.target is not None

    @property
    def requires_live_probing(self) -> bool:
        """Check if live probing should be performed."""
        return not self.static_only and self.host is not None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "live_only": self.live_only,
            "static_only": self.static_only,
            "scan_id": self.scan_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'ScanConfig':
        """Create ScanConfig from dictionary."""
        return cls(
            target=data.get("target"),
            host=data.get("host"),
            port=data.get("port"),
            live_only=bool(data.get("live_only", False)),
            static_only=bool(data.get("static_only", False)),
            scan_id=data.get("scan_id"),
        )
