"""Finding model - represents a single security finding."""
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
from uuid import uuid4
from datetime import datetime


@dataclass
class CVSSBreakdown:
    """CVSS 3.1 metric breakdown."""
    attack_vector: str  # Network, Adjacent, Local, Physical
    attack_complexity: str  # Low, High
    privileges_required: str  # None, Low, High
    user_interaction: str  # None, Required
    scope: str  # Unchanged, Changed
    confidentiality: str  # None, Low, High
    integrity: str  # None, Low, High
    availability: str  # None, Low, High

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for JSON serialization."""
        return {
            "attack_vector": self.attack_vector,
            "attack_complexity": self.attack_complexity,
            "privileges_required": self.privileges_required,
            "user_interaction": self.user_interaction,
            "scope": self.scope,
            "confidentiality": self.confidentiality,
            "integrity": self.integrity,
            "availability": self.availability,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'CVSSBreakdown':
        """Create CVSSBreakdown from dictionary."""
        return cls(
            attack_vector=data.get("attack_vector", "Network"),
            attack_complexity=data.get("attack_complexity", "Low"),
            privileges_required=data.get("privileges_required", "None"),
            user_interaction=data.get("user_interaction", "None"),
            scope=data.get("scope", "Unchanged"),
            confidentiality=data.get("confidentiality", "None"),
            integrity=data.get("integrity", "None"),
            availability=data.get("availability", "None"),
        )


@dataclass
class Evidence:
    """Evidence for a finding."""
    raw_request: Optional[str] = None
    raw_response: Optional[str] = None
    banner: Optional[str] = None
    certificate_info: Optional[Dict[str, Any]] = None
    dns_record: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: Dict[str, Any] = {}
        if self.raw_request is not None:
            result["raw_request"] = self.raw_request
        if self.raw_response is not None:
            result["raw_response"] = self.raw_response
        if self.banner is not None:
            result["banner"] = self.banner
        if self.certificate_info is not None:
            result["certificate_info"] = self.certificate_info
        if self.dns_record is not None:
            result["dns_record"] = self.dns_record
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Evidence':
        """Create Evidence from dictionary."""
        return cls(
            raw_request=data.get("raw_request"),
            raw_response=data.get("raw_response"),
            banner=data.get("banner"),
            certificate_info=data.get("certificate_info"),
            dns_record=data.get("dns_record"),
        )


@dataclass
class Finding:
    """A single security finding."""
    id: str = field(default_factory=lambda: str(uuid4()))
    scan_id: str = ""
    domain: str = ""  # network, tls, http, dns, static
    title: str = ""
    description: str = ""
    severity: str = ""  # critical, high, medium, low, info
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cvss_breakdown: Optional[CVSSBreakdown] = None
    owasp_category: str = ""
    owasp_id: str = ""  # A01-A10
    evidence: Optional[Evidence] = None
    remediation: str = ""
    false_positive_risk: str = "low"
    references: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: Dict[str, Any] = {
            "id": self.id,
            "scan_id": self.scan_id,
            "domain": self.domain,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "owasp_category": self.owasp_category,
            "owasp_id": self.owasp_id,
            "remediation": self.remediation,
            "false_positive_risk": self.false_positive_risk,
            "references": self.references,
            "timestamp": self.timestamp,
        }
        if self.cvss_breakdown is not None:
            result["cvss_breakdown"] = self.cvss_breakdown.to_dict()
        if self.evidence is not None:
            result["evidence"] = self.evidence.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create Finding from dictionary."""
        cvss_breakdown = None
        if data.get("cvss_breakdown"):
            cvss_breakdown = CVSSBreakdown.from_dict(data["cvss_breakdown"])

        evidence = None
        if data.get("evidence"):
            evidence = Evidence.from_dict(data["evidence"])

        return cls(
            id=data.get("id", str(uuid4())),
            scan_id=data.get("scan_id", ""),
            domain=data.get("domain", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            severity=data.get("severity", ""),
            cvss_score=float(data.get("cvss_score", 0.0)),
            cvss_vector=data.get("cvss_vector", ""),
            cvss_breakdown=cvss_breakdown,
            owasp_category=data.get("owasp_category", ""),
            owasp_id=data.get("owasp_id", ""),
            evidence=evidence,
            remediation=data.get("remediation", ""),
            false_positive_risk=data.get("false_positive_risk", "low"),
            references=data.get("references", []),
            timestamp=data.get("timestamp", datetime.utcnow().isoformat()),
        )
