"""Complete scan result with findings and scores."""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path
import json
import os


@dataclass
class DomainScore:
    """Score for a single domain."""
    domain: str
    score: int
    finding_count: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "domain": self.domain,
            "score": self.score,
            "finding_count": self.finding_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DomainScore':
        """Create DomainScore from dictionary."""
        return cls(
            domain=data.get("domain", ""),
            score=int(data.get("score", 0)),
            finding_count=int(data.get("finding_count", 0)),
        )


@dataclass
class OWASPCoverage:
    """OWASP category coverage status."""
    owasp_id: str
    category: str  # Category name
    status: str  # pass, fail, untested
    finding_count: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "owasp_id": self.owasp_id,
            "status": self.status,
            "finding_count": self.finding_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OWASPCoverage':
        """Create OWASPCoverage from dictionary."""
        return cls(
            owasp_id=data.get("owasp_id", ""),
            status=data.get("status", "untested"),
            finding_count=int(data.get("finding_count", 0)),
        )


@dataclass
class ScoreSummary:
    """Summary statistics for findings."""
    total_findings: int
    by_severity: Dict[str, int]
    highest_cvss: float
    highest_cvss_finding: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_findings": self.total_findings,
            "by_severity": self.by_severity,
            "highest_cvss": self.highest_cvss,
            "highest_cvss_finding": self.highest_cvss_finding,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScoreSummary':
        """Create ScoreSummary from dictionary."""
        return cls(
            total_findings=int(data.get("total_findings", 0)),
            by_severity=data.get("by_severity", {}),
            highest_cvss=float(data.get("highest_cvss", 0.0)),
            highest_cvss_finding=data.get("highest_cvss_finding", ""),
        )


@dataclass
class Scores:
    """Domain scores and overall grade."""
    network: int
    tls: int
    http: int
    dns: int
    static: int = 100  # Static analysis score (default 100 if not run)
    weighted_overall: float = 0.0
    grade: str = "A"  # A, B, C, D, F

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "network": self.network,
            "tls": self.tls,
            "http": self.http,
            "dns": self.dns,
            "weighted_overall": self.weighted_overall,
            "grade": self.grade,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Scores':
        """Create Scores from dictionary."""
        return cls(
            network=int(data.get("network", 100)),
            tls=int(data.get("tls", 100)),
            http=int(data.get("http", 100)),
            dns=int(data.get("dns", 100)),
            weighted_overall=float(data.get("weighted_overall", 100.0)),
            grade=data.get("grade", "A"),
        )


@dataclass
class ScanResult:
    """Complete scan result with all data."""
    scan_id: str
    target: Optional[str]
    host: Optional[str]
    started_at: str
    completed_at: str
    duration_seconds: float
    manifest: Optional[Dict[str, Any]] = None  # AttackSurfaceManifest as dict
    findings: List[Dict[str, Any]] = field(default_factory=list)  # Finding objects as dicts
    scores: Optional[Scores] = None
    owasp_coverage: List[OWASPCoverage] = field(default_factory=list)
    summary: Optional[ScoreSummary] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: Dict[str, Any] = {
            "scan_id": self.scan_id,
            "target": self.target,
            "host": self.host,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "findings": self.findings,
        }
        if self.manifest is not None:
            result["manifest"] = self.manifest
        if self.scores is not None:
            result["scores"] = self.scores.to_dict()
        if self.owasp_coverage:
            result["owasp_coverage"] = [c.to_dict() for c in self.owasp_coverage]
        if self.summary is not None:
            result["summary"] = self.summary.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanResult':
        """Create result from dictionary."""
        scores = None
        if data.get("scores"):
            scores = Scores.from_dict(data["scores"])

        owasp_coverage = [
            OWASPCoverage.from_dict(c) for c in data.get("owasp_coverage", [])
        ]

        summary = None
        if data.get("summary"):
            summary = ScoreSummary.from_dict(data["summary"])

        return cls(
            scan_id=data.get("scan_id", ""),
            target=data.get("target"),
            host=data.get("host"),
            started_at=data.get("started_at", ""),
            completed_at=data.get("completed_at", ""),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            manifest=data.get("manifest"),
            findings=data.get("findings", []),
            scores=scores,
            owasp_coverage=owasp_coverage,
            summary=summary,
        )

    def save(self, storage_dir: str) -> str:
        """Save to ~/.netsentinel/scans/<scan_id>.json and update index.
        
        Args:
            storage_dir: Base storage directory (e.g., ~/.netsentinel)
            
        Returns:
            Path to the saved scan file.
        """
        storage_path = Path(storage_dir)
        scans_dir = storage_path / "scans"
        scans_dir.mkdir(parents=True, exist_ok=True)

        scan_file = scans_dir / f"{self.scan_id}.json"
        with open(scan_file, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2)

        index_file = storage_path / "index.json"
        index_data: List[Dict[str, Any]] = []
        if index_file.exists():
            try:
                with open(index_file, 'r', encoding='utf-8') as f:
                    index_data = json.load(f)
            except (json.JSONDecodeError, IOError):
                index_data = []

        # Remove existing entry for this scan_id if present
        index_data = [entry for entry in index_data if entry.get("scan_id") != self.scan_id]

        # Add new entry
        index_entry = {
            "scan_id": self.scan_id,
            "target": self.target,
            "host": self.host,
            "date": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "grade": self.scores.grade if self.scores else None,
            "total_findings": self.summary.total_findings if self.summary else len(self.findings),
        }
        index_data.append(index_entry)

        with open(index_file, 'w', encoding='utf-8') as f:
            json.dump(index_data, f, indent=2)

        return str(scan_file)

    @classmethod
    def load(cls, scan_id: str, storage_dir: str) -> 'ScanResult':
        """Load from storage.
        
        Args:
            scan_id: The scan ID to load.
            storage_dir: Base storage directory (e.g., ~/.netsentinel)
            
        Returns:
            ScanResult loaded from disk.
            
        Raises:
            FileNotFoundError: If the scan file does not exist.
            json.JSONDecodeError: If the scan file is not valid JSON.
        """
        storage_path = Path(storage_dir)
        scan_file = storage_path / "scans" / f"{scan_id}.json"

        if not scan_file.exists():
            raise FileNotFoundError(f"Scan file not found: {scan_file}")

        with open(scan_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        return cls.from_dict(data)

    @classmethod
    def list_all(cls, storage_dir: str) -> List[Dict[str, Any]]:
        """List all scans from the index.
        
        Args:
            storage_dir: Base storage directory (e.g., ~/.netsentinel)
            
        Returns:
            List of scan metadata entries from index.json.
        """
        index_file = Path(storage_dir) / "index.json"
        if not index_file.exists():
            return []

        try:
            with open(index_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []

    @classmethod
    def delete(cls, scan_id: str, storage_dir: str) -> bool:
        """Delete a scan from storage.
        
        Args:
            scan_id: The scan ID to delete.
            storage_dir: Base storage directory (e.g., ~/.netsentinel)
            
        Returns:
            True if deletion was successful, False otherwise.
        """
        storage_path = Path(storage_dir)
        scan_file = storage_path / "scans" / f"{scan_id}.json"

        # Delete scan file
        if scan_file.exists():
            os.remove(scan_file)

        # Update index
        index_file = storage_path / "index.json"
        if index_file.exists():
            try:
                with open(index_file, 'r', encoding='utf-8') as f:
                    index_data = json.load(f)
                index_data = [entry for entry in index_data if entry.get("scan_id") != scan_id]
                with open(index_file, 'w', encoding='utf-8') as f:
                    json.dump(index_data, f, indent=2)
            except (json.JSONDecodeError, IOError):
                pass

        return True

    @classmethod
    def get_last(cls, storage_dir: str) -> Optional['ScanResult']:
        """Get the most recent scan.
        
        Args:
            storage_dir: Base storage directory (e.g., ~/.netsentinel)
            
        Returns:
            Most recent ScanResult or None if no scans exist.
        """
        scans = cls.list_all(storage_dir)
        if not scans:
            return None

        # Sort by date descending
        scans.sort(key=lambda x: x.get("date", ""), reverse=True)
        latest = scans[0]
        return cls.load(latest["scan_id"], storage_dir)
