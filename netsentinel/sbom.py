"""
SBOM (Software Bill of Materials) and CVE enrichment module for NetSentinel.

Parses dependency files (package.json, requirements.txt, pyproject.toml),
queries the OSV API for known vulnerabilities, and generates security findings.
"""
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

import httpx
import toml

from netsentinel.models import Finding


OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# Timeout for OSV API requests (seconds)
OSV_TIMEOUT = 30.0


@dataclass
class Dependency:
    """A single dependency with optional vulnerability information."""
    name: str
    version: str
    ecosystem: str  # npm, PyPI, Go, Maven, etc.
    source_file: str
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "source_file": self.source_file,
            "vulnerabilities": self.vulnerabilities,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Dependency':
        """Create Dependency from dictionary."""
        return cls(
            name=data.get("name", ""),
            version=data.get("version", ""),
            ecosystem=data.get("ecosystem", ""),
            source_file=data.get("source_file", ""),
            vulnerabilities=data.get("vulnerabilities", []),
        )


def parse_package_json(path: Path) -> List[Dependency]:
    """
    Parse dependencies from package.json.

    Args:
        path: Path to package.json file

    Returns:
        List of Dependency objects
    """
    dependencies: List[Dependency] = []
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return dependencies

    source_file = str(path)

    # Parse both dependencies and devDependencies
    for dep_key in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
        deps = data.get(dep_key, {})
        if not isinstance(deps, dict):
            continue
            
        for name, version_spec in deps.items():
            if not isinstance(version_spec, str):
                continue
            version = _normalize_npm_version(version_spec)
            if version:
                dependencies.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    source_file=source_file,
                ))

    return dependencies


def _normalize_npm_version(version_spec: str) -> str:
    """
    Normalize npm version specifier to a clean version string.
    
    Handles: ^1.2.3, ~1.2.3, >=1.0.0, 1.2.3, etc.
    Returns empty string for unparseable specs (e.g., git URLs, file: refs)
    """
    # Remove common prefixes
    version = version_spec.strip()
    
    # Skip URLs, file refs, and other non-semver specs
    if any(prefix in version.lower() for prefix in ['http', 'git', 'file:', 'link:', '*', 'latest']):
        return ""
    
    # Remove ^, ~, >=, <=, >, <, = prefixes
    version = re.sub(r'^[\^~>=<]+', '', version)
    
    # Handle ranges like "1.0.0 - 2.0.0" - take first version
    if ' - ' in version:
        version = version.split(' - ')[0].strip()
    
    # Handle || ranges - take first version
    if ' || ' in version:
        version = version.split(' || ')[0].strip()
        version = re.sub(r'^[\^~>=<]+', '', version)
    
    # Validate it looks like a version
    if re.match(r'^\d+(\.\d+)*', version):
        return version.strip()
    
    return ""


def parse_requirements_txt(path: Path) -> List[Dependency]:
    """
    Parse dependencies from requirements.txt.

    Args:
        path: Path to requirements.txt file

    Returns:
        List of Dependency objects
    """
    dependencies: List[Dependency] = []
    source_file = str(path)
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except OSError:
        return dependencies

    for line in lines:
        line = line.strip()
        
        # Skip comments and empty lines
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        
        # Skip editable installs and URLs
        if line.startswith('git+') or line.startswith('http') or line.startswith('-e'):
            continue
        
        # Parse package==version, package>=version, package~=version, etc.
        match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*([<>=!~]+)\s*([0-9][0-9a-zA-Z\.\-_]*)', line)
        if match:
            name = match.group(1).lower()
            version = match.group(3)
            dependencies.append(Dependency(
                name=name,
                version=version,
                ecosystem="PyPI",
                source_file=source_file,
            ))
            continue
        
        # Handle package without version (just name)
        name_match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*$', line)
        if name_match:
            # No version specified - skip for CVE checking
            continue

    return dependencies


def parse_pyproject_toml(path: Path) -> List[Dependency]:
    """
    Parse dependencies from pyproject.toml.

    Args:
        path: Path to pyproject.toml file

    Returns:
        List of Dependency objects
    """
    dependencies: List[Dependency] = []
    source_file = str(path)
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = toml.load(f)
    except (toml.TomlDecodeError, OSError):
        return dependencies

    # Check [project.dependencies]
    project_deps = data.get('project', {}).get('dependencies', [])
    if isinstance(project_deps, list):
        for dep_str in project_deps:
            dep = _parse_pep508_dependency(dep_str)
            if dep:
                dep.source_file = source_file
                dependencies.append(dep)

    # Check [project.optional-dependencies]
    optional_deps = data.get('project', {}).get('optional-dependencies', {})
    if isinstance(optional_deps, dict):
        for group_deps in optional_deps.values():
            if isinstance(group_deps, list):
                for dep_str in group_deps:
                    dep = _parse_pep508_dependency(dep_str)
                    if dep:
                        dep.source_file = source_file
                        dependencies.append(dep)

    # Check [tool.poetry.dependencies] (Poetry format)
    poetry_deps = data.get('tool', {}).get('poetry', {}).get('dependencies', {})
    if isinstance(poetry_deps, dict):
        for name, version_spec in poetry_deps.items():
            if name.lower() == 'python':
                continue
            version = _extract_poetry_version(version_spec)
            if version:
                dependencies.append(Dependency(
                    name=name.lower(),
                    version=version,
                    ecosystem="PyPI",
                    source_file=source_file,
                ))

    # Check [tool.poetry.dev-dependencies]
    poetry_dev_deps = data.get('tool', {}).get('poetry', {}).get('dev-dependencies', {})
    if isinstance(poetry_dev_deps, dict):
        for name, version_spec in poetry_dev_deps.items():
            version = _extract_poetry_version(version_spec)
            if version:
                dependencies.append(Dependency(
                    name=name.lower(),
                    version=version,
                    ecosystem="PyPI",
                    source_file=source_file,
                ))

    return dependencies


def _parse_pep508_dependency(dep_str: str) -> Optional[Dependency]:
    """
    Parse a PEP 508 dependency string.
    
    Examples:
        "requests>=2.28.0"
        "flask[async]>=2.0.0,<3.0"
        "django==4.2.1"
    """
    if not isinstance(dep_str, str):
        return None
        
    # Remove extras like [async]
    dep_str = re.sub(r'\[.*?\]', '', dep_str)
    
    # Match name and version spec
    match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*([<>=!~]+)\s*([0-9][0-9a-zA-Z\.\-_]*)', dep_str)
    if match:
        return Dependency(
            name=match.group(1).lower(),
            version=match.group(3),
            ecosystem="PyPI",
            source_file="",
        )
    return None


def _extract_poetry_version(version_spec: Any) -> str:
    """Extract version from Poetry dependency specification."""
    if isinstance(version_spec, str):
        # Direct version string like "^1.2.3"
        version = re.sub(r'^[\^~>=<]+', '', version_spec)
        if re.match(r'^\d+(\.\d+)*', version):
            return version
    elif isinstance(version_spec, dict):
        # Complex spec like {version = "^1.2.3", python = "^3.8"}
        v = version_spec.get('version', '')
        if isinstance(v, str):
            version = re.sub(r'^[\^~>=<]+', '', v)
            if re.match(r'^\d+(\.\d+)*', version):
                return version
    return ""


def query_osv(packages: List[Dependency]) -> List[Dependency]:
    """
    Query OSV API for vulnerabilities in the given packages.
    
    Uses batch API for efficiency.

    Args:
        packages: List of dependencies to check

    Returns:
        Same list with vulnerabilities field populated
    """
    if not packages:
        return packages

    # Build batch query
    queries = []
    for pkg in packages:
        queries.append({
            "package": {
                "name": pkg.name,
                "ecosystem": pkg.ecosystem,
            },
            "version": pkg.version,
        })

    try:
        with httpx.Client(timeout=OSV_TIMEOUT) as client:
            response = client.post(OSV_BATCH_URL, json={"queries": queries})
            response.raise_for_status()
            results = response.json()
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        # Log error but don't fail the scan
        print(f"[SBOM] Warning: OSV API query failed: {e}")
        return packages

    # Map results back to packages
    for i, result in enumerate(results.get("results", [])):
        if i < len(packages):
            vulns = result.get("vulns", [])
            packages[i].vulnerabilities = vulns

    return packages


def _severity_from_cvss(cvss_score: float) -> str:
    """Convert CVSS score to severity string."""
    if cvss_score >= 9.0:
        return "critical"
    elif cvss_score >= 7.0:
        return "high"
    elif cvss_score >= 4.0:
        return "medium"
    elif cvss_score >= 0.1:
        return "low"
    return "info"


def _extract_cvss_from_vuln(vuln: Dict[str, Any]) -> Tuple[float, str]:
    """
    Extract CVSS score and vector from OSV vulnerability data.
    
    Returns:
        Tuple of (score, vector_string)
    """
    severity_list = vuln.get("severity", [])
    
    for severity in severity_list:
        if severity.get("type") == "CVSS_V3":
            score_value = severity.get("score", "")
            
            # Handle numeric score directly
            if isinstance(score_value, (int, float)):
                return float(score_value), ""
            
            # Handle vector string
            if isinstance(score_value, str) and score_value:
                vector = score_value
                # Parse score from vector string if present
                # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
                score_match = re.search(r'CVSS:3\.[01]/.*?/?([\d.]+)', vector)
                if score_match:
                    try:
                        return float(score_match.group(1)), vector
                    except ValueError:
                        pass
                # Just return the vector without parsed score
                return 5.0, vector  # Default medium severity

    # Fallback: Check database_specific for score
    db_specific = vuln.get("database_specific", {})
    if "cvss" in db_specific:
        cvss = db_specific["cvss"]
        if isinstance(cvss, dict):
            score = cvss.get("score", 0.0)
            vector = cvss.get("vectorString", "")
            return float(score), vector

    # Check affected ranges for severity hints
    for affected in vuln.get("affected", []):
        ecosystem_specific = affected.get("ecosystem_specific", {})
        if "severity" in ecosystem_specific:
            sev = str(ecosystem_specific["severity"]).lower()
            if sev == "critical":
                return 9.5, ""
            elif sev == "high":
                return 7.5, ""
            elif sev == "moderate" or sev == "medium":
                return 5.5, ""
            elif sev == "low":
                return 2.5, ""

    # Default: unknown severity, assume medium
    return 5.0, ""


def _extract_fixed_version(vuln: Dict[str, Any], ecosystem: str) -> Optional[str]:
    """Extract the fixed version from vulnerability data."""
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("ecosystem", "").lower() == ecosystem.lower():
            for ranges in affected.get("ranges", []):
                for event in ranges.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return None


def generate_sbom_findings(
    directory: Path,
    scan_id: str,
    file_tree: Optional[List[Tuple[Path, str]]] = None
) -> Tuple[List[Finding], List[Dependency]]:
    """
    Generate SBOM findings for a directory.
    
    Scans for package.json, requirements.txt, and pyproject.toml files,
    extracts dependencies, queries OSV for vulnerabilities, and returns
    findings for any vulnerable packages.

    Args:
        directory: Root directory to scan
        scan_id: Scan UUID
        file_tree: Optional pre-computed file tree (path, content tuples)

    Returns:
        Tuple of (findings list, all dependencies list)
    """
    findings: List[Finding] = []
    all_dependencies: List[Dependency] = []

    # Find and parse dependency files
    package_files: List[Path] = []
    
    if file_tree:
        # Use pre-computed file tree
        for path, _ in file_tree:
            if path.name == "package.json":
                package_files.append(path)
            elif path.name in ("requirements.txt", "requirements-dev.txt"):
                package_files.append(path)
            elif path.name == "pyproject.toml":
                package_files.append(path)
    else:
        # Walk directory ourselves
        for pattern in ["**/package.json", "**/requirements*.txt", "**/pyproject.toml"]:
            package_files.extend(directory.glob(pattern))

    # Parse all dependency files
    for pkg_file in package_files:
        # Skip node_modules and similar
        if any(part in pkg_file.parts for part in ['node_modules', '.git', 'venv', '.venv', 'env']):
            continue

        if pkg_file.name == "package.json":
            deps = parse_package_json(pkg_file)
        elif pkg_file.name.startswith("requirements") and pkg_file.suffix == ".txt":
            deps = parse_requirements_txt(pkg_file)
        elif pkg_file.name == "pyproject.toml":
            deps = parse_pyproject_toml(pkg_file)
        else:
            continue

        all_dependencies.extend(deps)

    if not all_dependencies:
        return findings, all_dependencies

    # Query OSV for vulnerabilities
    all_dependencies = query_osv(all_dependencies)

    # Generate findings for vulnerable packages
    for dep in all_dependencies:
        if not dep.vulnerabilities:
            continue

        for vuln in dep.vulnerabilities:
            vuln_id = vuln.get("id", "UNKNOWN")
            summary = vuln.get("summary", vuln.get("details", "No description available"))
            
            # Truncate long summaries
            if len(summary) > 500:
                summary = summary[:497] + "..."

            cvss_score, cvss_vector = _extract_cvss_from_vuln(vuln)
            severity = _severity_from_cvss(cvss_score)
            fixed_version = _extract_fixed_version(vuln, dep.ecosystem)

            # Build remediation text
            if fixed_version:
                remediation = f"Upgrade {dep.name} to version {fixed_version} or later."
            else:
                remediation = f"Check for updates to {dep.name} or consider alternative packages."

            # Build references
            references = vuln.get("references", [])
            ref_urls = [ref.get("url") for ref in references if ref.get("url")][:5]

            # Add OSV link
            osv_url = f"https://osv.dev/vulnerability/{vuln_id}"
            if osv_url not in ref_urls:
                ref_urls.insert(0, osv_url)

            finding = Finding(
                scan_id=scan_id,
                domain="static",
                title=f"{vuln_id}: Vulnerable dependency {dep.name}@{dep.version}",
                description=(
                    f"The dependency {dep.name} version {dep.version} ({dep.ecosystem}) "
                    f"is affected by {vuln_id}.\n\n{summary}"
                ),
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                owasp_category="Vulnerable and Outdated Components",
                owasp_id="A06",
                remediation=remediation,
                false_positive_risk="low",
                references=ref_urls,
                timestamp=datetime.utcnow().isoformat(),
            )
            findings.append(finding)

    return findings, all_dependencies
