"""Unit tests for the SBOM (Software Bill of Materials) module."""
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from netsentinel.sbom import (
    parse_package_json,
    parse_requirements_txt,
    parse_pyproject_toml,
    query_osv,
    generate_sbom_findings,
    Dependency,
    _normalize_npm_version,
    _extract_cvss_from_vuln,
    _extract_fixed_version,
    _severity_from_cvss,
)


class TestParsePackageJson:
    """Tests for parse_package_json function."""

    def test_parses_dependencies(self, tmp_path: Path) -> None:
        """Should parse regular dependencies."""
        pkg_json = tmp_path / "package.json"
        pkg_json.write_text(json.dumps({
            "name": "test-app",
            "dependencies": {
                "express": "^4.18.2",
                "lodash": "4.17.21"
            }
        }))
        
        deps = parse_package_json(pkg_json)
        
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "express" in names
        assert "lodash" in names
        assert all(d.ecosystem == "npm" for d in deps)

    def test_parses_dev_dependencies(self, tmp_path: Path) -> None:
        """Should parse devDependencies."""
        pkg_json = tmp_path / "package.json"
        pkg_json.write_text(json.dumps({
            "name": "test-app",
            "devDependencies": {
                "jest": "^29.0.0",
                "typescript": "~5.0.0"
            }
        }))
        
        deps = parse_package_json(pkg_json)
        
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "jest" in names
        assert "typescript" in names

    def test_skips_git_dependencies(self, tmp_path: Path) -> None:
        """Should skip git: and http: dependencies."""
        pkg_json = tmp_path / "package.json"
        pkg_json.write_text(json.dumps({
            "name": "test-app",
            "dependencies": {
                "express": "^4.18.2",
                "my-private-pkg": "git+https://github.com/org/repo.git",
                "another": "file:../local-pkg"
            }
        }))
        
        deps = parse_package_json(pkg_json)
        
        assert len(deps) == 1
        assert deps[0].name == "express"

    def test_handles_invalid_json(self, tmp_path: Path) -> None:
        """Should return empty list for invalid JSON."""
        pkg_json = tmp_path / "package.json"
        pkg_json.write_text("{ invalid json }")
        
        deps = parse_package_json(pkg_json)
        
        assert deps == []

    def test_handles_missing_file(self, tmp_path: Path) -> None:
        """Should return empty list for missing file."""
        pkg_json = tmp_path / "nonexistent.json"
        
        deps = parse_package_json(pkg_json)
        
        assert deps == []


class TestNormalizeNpmVersion:
    """Tests for _normalize_npm_version helper."""

    def test_removes_caret(self) -> None:
        """Should remove ^ prefix."""
        assert _normalize_npm_version("^1.2.3") == "1.2.3"

    def test_removes_tilde(self) -> None:
        """Should remove ~ prefix."""
        assert _normalize_npm_version("~1.2.3") == "1.2.3"

    def test_removes_gte(self) -> None:
        """Should remove >= prefix."""
        assert _normalize_npm_version(">=1.0.0") == "1.0.0"

    def test_handles_plain_version(self) -> None:
        """Should pass through plain versions."""
        assert _normalize_npm_version("1.2.3") == "1.2.3"

    def test_skips_star(self) -> None:
        """Should return empty for * versions."""
        assert _normalize_npm_version("*") == ""

    def test_skips_latest(self) -> None:
        """Should return empty for 'latest'."""
        assert _normalize_npm_version("latest") == ""

    def test_handles_range(self) -> None:
        """Should take first version from range."""
        assert _normalize_npm_version("1.0.0 - 2.0.0") == "1.0.0"


class TestParseRequirementsTxt:
    """Tests for parse_requirements_txt function."""

    def test_parses_pinned_versions(self, tmp_path: Path) -> None:
        """Should parse package==version format."""
        req_txt = tmp_path / "requirements.txt"
        req_txt.write_text("flask==2.3.0\nrequests==2.28.0\n")
        
        deps = parse_requirements_txt(req_txt)
        
        assert len(deps) == 2
        assert deps[0].name == "flask"
        assert deps[0].version == "2.3.0"
        assert deps[0].ecosystem == "PyPI"

    def test_parses_gte_versions(self, tmp_path: Path) -> None:
        """Should parse package>=version format."""
        req_txt = tmp_path / "requirements.txt"
        req_txt.write_text("django>=4.0\n")
        
        deps = parse_requirements_txt(req_txt)
        
        assert len(deps) == 1
        assert deps[0].name == "django"
        assert deps[0].version == "4.0"

    def test_skips_comments(self, tmp_path: Path) -> None:
        """Should skip comment lines."""
        req_txt = tmp_path / "requirements.txt"
        req_txt.write_text("# This is a comment\nflask==2.3.0\n")
        
        deps = parse_requirements_txt(req_txt)
        
        assert len(deps) == 1
        assert deps[0].name == "flask"

    def test_skips_empty_lines(self, tmp_path: Path) -> None:
        """Should skip empty lines."""
        req_txt = tmp_path / "requirements.txt"
        req_txt.write_text("\n\nflask==2.3.0\n\n")
        
        deps = parse_requirements_txt(req_txt)
        
        assert len(deps) == 1

    def test_skips_editable_installs(self, tmp_path: Path) -> None:
        """Should skip -e editable installs."""
        req_txt = tmp_path / "requirements.txt"
        req_txt.write_text("-e git+https://github.com/org/repo.git\nflask==2.3.0\n")
        
        deps = parse_requirements_txt(req_txt)
        
        assert len(deps) == 1
        assert deps[0].name == "flask"

    def test_skips_packages_without_version(self, tmp_path: Path) -> None:
        """Should skip packages without version specifier."""
        req_txt = tmp_path / "requirements.txt"
        req_txt.write_text("flask\nrequests==2.28.0\n")
        
        deps = parse_requirements_txt(req_txt)
        
        assert len(deps) == 1
        assert deps[0].name == "requests"


class TestParsePyprojectToml:
    """Tests for parse_pyproject_toml function."""

    def test_parses_project_dependencies(self, tmp_path: Path) -> None:
        """Should parse [project.dependencies]."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("""
[project]
name = "myapp"
dependencies = [
    "flask>=2.3.0",
    "requests==2.28.0"
]
""")
        
        deps = parse_pyproject_toml(pyproject)
        
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "flask" in names
        assert "requests" in names

    def test_parses_poetry_dependencies(self, tmp_path: Path) -> None:
        """Should parse [tool.poetry.dependencies]."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("""
[tool.poetry]
name = "myapp"

[tool.poetry.dependencies]
python = "^3.9"
flask = "^2.3.0"
requests = {version = "^2.28.0", python = "^3.8"}
""")
        
        deps = parse_pyproject_toml(pyproject)
        
        assert len(deps) == 2  # python is skipped
        names = {d.name for d in deps}
        assert "flask" in names
        assert "requests" in names

    def test_handles_invalid_toml(self, tmp_path: Path) -> None:
        """Should return empty list for invalid TOML."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("invalid toml {{{{")
        
        deps = parse_pyproject_toml(pyproject)
        
        assert deps == []


class TestSeverityFromCvss:
    """Tests for _severity_from_cvss helper."""

    def test_critical(self) -> None:
        """Scores >= 9.0 should be critical."""
        assert _severity_from_cvss(9.0) == "critical"
        assert _severity_from_cvss(10.0) == "critical"

    def test_high(self) -> None:
        """Scores 7.0-8.9 should be high."""
        assert _severity_from_cvss(7.0) == "high"
        assert _severity_from_cvss(8.9) == "high"

    def test_medium(self) -> None:
        """Scores 4.0-6.9 should be medium."""
        assert _severity_from_cvss(4.0) == "medium"
        assert _severity_from_cvss(6.9) == "medium"

    def test_low(self) -> None:
        """Scores 0.1-3.9 should be low."""
        assert _severity_from_cvss(0.1) == "low"
        assert _severity_from_cvss(3.9) == "low"

    def test_info(self) -> None:
        """Score 0 should be info."""
        assert _severity_from_cvss(0.0) == "info"


class TestExtractCvssFromVuln:
    """Tests for _extract_cvss_from_vuln helper."""

    def test_extracts_cvss_v3_vector(self) -> None:
        """Should extract CVSS v3 vector string."""
        vuln = {
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ]
        }
        score, vector = _extract_cvss_from_vuln(vuln)
        assert vector.startswith("CVSS:3.1")

    def test_extracts_numeric_score(self) -> None:
        """Should handle numeric score directly."""
        vuln = {
            "severity": [
                {"type": "CVSS_V3", "score": 7.5}
            ]
        }
        score, vector = _extract_cvss_from_vuln(vuln)
        assert score == 7.5

    def test_fallback_to_ecosystem_severity(self) -> None:
        """Should fallback to ecosystem_specific severity."""
        vuln = {
            "affected": [{
                "ecosystem_specific": {"severity": "HIGH"}
            }]
        }
        score, vector = _extract_cvss_from_vuln(vuln)
        assert score == 7.5
        assert vector == ""


class TestExtractFixedVersion:
    """Tests for _extract_fixed_version helper."""

    def test_extracts_fixed_version(self) -> None:
        """Should extract fixed version from affected ranges."""
        vuln = {
            "affected": [{
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "4.17.21"}
                    ]
                }]
            }]
        }
        fixed = _extract_fixed_version(vuln, "npm")
        assert fixed == "4.17.21"

    def test_returns_none_if_no_fix(self) -> None:
        """Should return None if no fixed version exists."""
        vuln = {
            "affected": [{
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{
                    "events": [{"introduced": "0"}]
                }]
            }]
        }
        fixed = _extract_fixed_version(vuln, "npm")
        assert fixed is None


class TestQueryOsv:
    """Tests for query_osv function."""

    def test_handles_empty_packages(self) -> None:
        """Should return empty list for empty input."""
        result = query_osv([])
        assert result == []

    @patch('netsentinel.sbom.httpx.Client')
    def test_queries_batch_api(self, mock_client_class: MagicMock) -> None:
        """Should use batch API for multiple packages."""
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_class.return_value.__exit__ = MagicMock(return_value=False)
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [
                {"vulns": [{"id": "CVE-2021-12345"}]},
                {"vulns": []}
            ]
        }
        mock_client.post.return_value = mock_response
        
        deps = [
            Dependency(name="lodash", version="4.17.15", ecosystem="npm", source_file="package.json"),
            Dependency(name="express", version="4.18.2", ecosystem="npm", source_file="package.json"),
        ]
        
        result = query_osv(deps)
        
        assert len(result) == 2
        assert len(result[0].vulnerabilities) == 1
        assert result[0].vulnerabilities[0]["id"] == "CVE-2021-12345"
        assert len(result[1].vulnerabilities) == 0

    @patch('netsentinel.sbom.httpx.Client')
    def test_handles_api_error(self, mock_client_class: MagicMock) -> None:
        """Should handle API errors gracefully."""
        import httpx
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_client_class.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = httpx.HTTPError("Network error")
        
        deps = [Dependency(name="lodash", version="4.17.15", ecosystem="npm", source_file="package.json")]
        
        result = query_osv(deps)
        
        # Should return original deps without crashing
        assert len(result) == 1
        assert result[0].vulnerabilities == []


class TestGenerateSbomFindings:
    """Tests for generate_sbom_findings function."""

    def test_finds_package_json(self, tmp_path: Path) -> None:
        """Should find and parse package.json files."""
        pkg_json = tmp_path / "package.json"
        pkg_json.write_text(json.dumps({
            "name": "test",
            "dependencies": {"lodash": "4.17.21"}
        }))
        
        with patch('netsentinel.sbom.query_osv') as mock_query:
            mock_query.return_value = [
                Dependency(
                    name="lodash",
                    version="4.17.21",
                    ecosystem="npm",
                    source_file=str(pkg_json),
                    vulnerabilities=[]
                )
            ]
            
            findings, deps = generate_sbom_findings(tmp_path, "scan-123")
        
        assert len(deps) == 1
        assert deps[0].name == "lodash"

    def test_generates_findings_for_vulns(self, tmp_path: Path) -> None:
        """Should generate findings for vulnerable dependencies."""
        pkg_json = tmp_path / "package.json"
        pkg_json.write_text(json.dumps({
            "name": "test",
            "dependencies": {"lodash": "4.17.15"}
        }))
        
        with patch('netsentinel.sbom.query_osv') as mock_query:
            mock_query.return_value = [
                Dependency(
                    name="lodash",
                    version="4.17.15",
                    ecosystem="npm",
                    source_file=str(pkg_json),
                    vulnerabilities=[{
                        "id": "CVE-2021-23337",
                        "summary": "Prototype pollution in lodash",
                        "severity": [{"type": "CVSS_V3", "score": 7.5}],
                        "affected": [{
                            "package": {"name": "lodash", "ecosystem": "npm"},
                            "ranges": [{
                                "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]
                            }]
                        }],
                        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}]
                    }]
                )
            ]
            
            findings, deps = generate_sbom_findings(tmp_path, "scan-123")
        
        assert len(findings) == 1
        finding = findings[0]
        assert "CVE-2021-23337" in finding.title
        assert finding.domain == "static"
        assert finding.owasp_id == "A06"
        assert "4.17.21" in finding.remediation  # Fixed version

    def test_skips_node_modules(self, tmp_path: Path) -> None:
        """Should skip package.json in node_modules."""
        node_modules = tmp_path / "node_modules" / "lodash"
        node_modules.mkdir(parents=True)
        pkg_json = node_modules / "package.json"
        pkg_json.write_text(json.dumps({
            "name": "lodash",
            "dependencies": {}
        }))
        
        # Root package.json
        root_pkg = tmp_path / "package.json"
        root_pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {"express": "4.18.2"}
        }))
        
        with patch('netsentinel.sbom.query_osv') as mock_query:
            mock_query.return_value = [
                Dependency(
                    name="express",
                    version="4.18.2",
                    ecosystem="npm",
                    source_file=str(root_pkg),
                    vulnerabilities=[]
                )
            ]
            
            findings, deps = generate_sbom_findings(tmp_path, "scan-123")
        
        # Should only have express from root, not lodash from node_modules
        assert len(deps) == 1
        assert deps[0].name == "express"


class TestDependencyModel:
    """Tests for Dependency dataclass."""

    def test_to_dict(self) -> None:
        """Should convert to dictionary correctly."""
        dep = Dependency(
            name="flask",
            version="2.3.0",
            ecosystem="PyPI",
            source_file="requirements.txt",
            vulnerabilities=[{"id": "CVE-2023-1234"}]
        )
        
        d = dep.to_dict()
        
        assert d["name"] == "flask"
        assert d["version"] == "2.3.0"
        assert d["ecosystem"] == "PyPI"
        assert len(d["vulnerabilities"]) == 1

    def test_from_dict(self) -> None:
        """Should create from dictionary correctly."""
        data = {
            "name": "flask",
            "version": "2.3.0",
            "ecosystem": "PyPI",
            "source_file": "requirements.txt",
            "vulnerabilities": [{"id": "CVE-2023-1234"}]
        }
        
        dep = Dependency.from_dict(data)
        
        assert dep.name == "flask"
        assert dep.version == "2.3.0"
        assert len(dep.vulnerabilities) == 1
