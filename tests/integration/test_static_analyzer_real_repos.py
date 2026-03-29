"""Integration tests for static analyzer with real code samples."""
import uuid
from pathlib import Path

import pytest

from netsentinel.static_analyzer import analyze
from netsentinel.models import AttackSurfaceManifest


@pytest.mark.integration
class TestStaticAnalyzerPythonRepos:
    """Test static analyzer on Python repos."""

    def test_extracts_hardcoded_secrets(self, tmp_path: Path) -> None:
        """Test extraction of hardcoded secrets."""
        (tmp_path / "app.py").write_text("""
API_KEY = "sk-1234567890abcdef"
SECRET_KEY = "my-super-secret-key"
app.run(host='0.0.0.0', port=8080)
""")
        
        scan_id = str(uuid.uuid4())
        manifest = analyze(str(tmp_path), scan_id)
        
        assert isinstance(manifest, AttackSurfaceManifest)
        assert len(manifest.secrets_found) > 0

    def test_extracts_exposed_ports(self, tmp_path: Path) -> None:
        """Test port extraction."""
        (tmp_path / "app.py").write_text("app.run(port=8080)")
        
        scan_id = str(uuid.uuid4())
        manifest = analyze(str(tmp_path), scan_id)
        
        port_numbers = [p.port for p in manifest.ports]
        assert 8080 in port_numbers

    def test_detects_python_language(self, tmp_path: Path) -> None:
        """Test Python language detection."""
        (tmp_path / "app.py").write_text("import os")
        
        scan_id = str(uuid.uuid4())
        manifest = analyze(str(tmp_path), scan_id)
        
        assert "python" in manifest.language_detected


@pytest.mark.integration
class TestStaticAnalyzerDockerRepos:
    """Test analyzer on Docker configs."""

    def test_extracts_ports_from_dockerfile(self, tmp_path: Path) -> None:
        """Test Dockerfile port extraction."""
        (tmp_path / "Dockerfile").write_text("""
FROM python:3.10
EXPOSE 8080
EXPOSE 443
""")
        
        scan_id = str(uuid.uuid4())
        manifest = analyze(str(tmp_path), scan_id)
        
        port_numbers = [p.port for p in manifest.ports]
        assert 8080 in port_numbers
        assert 443 in port_numbers

    def test_handles_empty_repository(self, tmp_path: Path) -> None:
        """Test empty repo handling."""
        scan_id = str(uuid.uuid4())
        manifest = analyze(str(tmp_path), scan_id)
        
        assert isinstance(manifest, AttackSurfaceManifest)
        assert len(manifest.ports) == 0
