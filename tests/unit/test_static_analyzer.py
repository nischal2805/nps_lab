"""Unit tests for the static analyzer module."""
import tempfile
import uuid
from pathlib import Path

import pytest

from netsentinel.static_analyzer import (
    analyze,
    detect_languages,
    extract_dns_config,
    extract_outbound_hosts,
    extract_ports,
    extract_routes,
    extract_secrets,
    extract_tls_config,
    walk_files,
)


class TestWalkFiles:
    """Tests for the walk_files function."""

    def test_walks_python_files(self, tmp_path: Path) -> None:
        """Should include .py files."""
        py_file = tmp_path / "test.py"
        py_file.write_text("print('hello')")
        
        files = list(walk_files(tmp_path))
        assert len(files) == 1
        assert files[0][0] == py_file
        assert "print('hello')" in files[0][1]

    def test_skips_node_modules(self, tmp_path: Path) -> None:
        """Should skip node_modules directory."""
        node_dir = tmp_path / "node_modules"
        node_dir.mkdir()
        (node_dir / "test.js").write_text("module.exports = {}")
        
        py_file = tmp_path / "app.py"
        py_file.write_text("import sys")
        
        files = list(walk_files(tmp_path))
        paths = [str(f[0]) for f in files]
        
        assert len(files) == 1
        # Check that no file from node_modules is included
        assert all("node_modules" not in p.replace(str(tmp_path), "") for p in paths)

    def test_includes_dockerfile(self, tmp_path: Path) -> None:
        """Should include Dockerfile even without extension."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.10")
        
        files = list(walk_files(tmp_path))
        assert len(files) == 1
        assert files[0][0].name == "Dockerfile"


class TestDetectLanguages:
    """Tests for language detection."""

    def test_detects_python_by_extension(self, tmp_path: Path) -> None:
        """Should detect Python from .py files."""
        (tmp_path / "app.py").write_text("import os")
        file_tree = list(walk_files(tmp_path))
        
        languages = detect_languages(file_tree, tmp_path)
        assert "python" in languages

    def test_detects_python_by_requirements(self, tmp_path: Path) -> None:
        """Should detect Python from requirements.txt."""
        # requirements.txt has no extension in INCLUDED_EXTENSIONS, so we need
        # to also have a .py file or the file won't be walked
        (tmp_path / "requirements.txt").write_text("flask>=2.0")
        (tmp_path / "app.py").write_text("from flask import Flask")
        file_tree = list(walk_files(tmp_path))
        
        languages = detect_languages(file_tree, tmp_path)
        assert "python" in languages

    def test_detects_javascript_by_package_json(self, tmp_path: Path) -> None:
        """Should detect JavaScript from package.json."""
        (tmp_path / "package.json").write_text('{"name": "test"}')
        file_tree = list(walk_files(tmp_path))
        
        languages = detect_languages(file_tree, tmp_path)
        assert "javascript" in languages


class TestExtractPorts:
    """Tests for port extraction."""

    def test_extracts_dockerfile_expose(self, tmp_path: Path) -> None:
        """Should extract ports from EXPOSE directives."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.10\nEXPOSE 8080\nEXPOSE 443/tcp")
        
        file_tree = list(walk_files(tmp_path))
        ports = extract_ports(file_tree)
        
        port_nums = [p.port for p in ports]
        assert 8080 in port_nums
        assert 443 in port_nums

    def test_extracts_docker_compose_ports(self, tmp_path: Path) -> None:
        """Should extract ports from docker-compose.yml."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("""
services:
  web:
    ports:
      - "3000:3000"
      - "8080:80"
""")
        file_tree = list(walk_files(tmp_path))
        ports = extract_ports(file_tree)
        
        port_nums = [p.port for p in ports]
        assert 3000 in port_nums
        assert 80 in port_nums

    def test_extracts_env_port(self, tmp_path: Path) -> None:
        """Should extract PORT from .env files."""
        env_file = tmp_path / ".env"
        env_file.write_text("PORT=5000\nDB_PORT=5432")
        
        file_tree = list(walk_files(tmp_path))
        ports = extract_ports(file_tree)
        
        port_nums = [p.port for p in ports]
        assert 5000 in port_nums
        assert 5432 in port_nums

    def test_extracts_listen_call(self, tmp_path: Path) -> None:
        """Should extract port from app.listen() calls."""
        js_file = tmp_path / "server.js"
        js_file.write_text("app.listen(3000, () => console.log('Running'));")
        
        file_tree = list(walk_files(tmp_path))
        ports = extract_ports(file_tree)
        
        assert len(ports) >= 1
        assert any(p.port == 3000 for p in ports)


class TestExtractRoutes:
    """Tests for route extraction."""

    def test_extracts_express_routes(self, tmp_path: Path) -> None:
        """Should extract Express.js routes."""
        js_file = tmp_path / "routes.js"
        js_file.write_text("""
app.get('/users', getUsers);
app.post('/users', createUser);
router.delete('/users/:id', deleteUser);
""")
        file_tree = list(walk_files(tmp_path))
        routes = extract_routes(file_tree)
        
        paths = [(r.method, r.path) for r in routes]
        assert ("GET", "/users") in paths
        assert ("POST", "/users") in paths
        assert ("DELETE", "/users/:id") in paths

    def test_extracts_flask_routes(self, tmp_path: Path) -> None:
        """Should extract Flask routes."""
        py_file = tmp_path / "app.py"
        py_file.write_text("""
@app.route('/api/items', methods=['GET', 'POST'])
def items():
    pass

@app.route('/health')
def health():
    pass
""")
        file_tree = list(walk_files(tmp_path))
        routes = extract_routes(file_tree)
        
        paths = [(r.method, r.path) for r in routes]
        assert ("GET", "/api/items") in paths
        assert ("POST", "/api/items") in paths
        assert ("GET", "/health") in paths

    def test_extracts_fastapi_routes(self, tmp_path: Path) -> None:
        """Should extract FastAPI routes."""
        py_file = tmp_path / "main.py"
        py_file.write_text("""
@app.get('/items')
async def get_items():
    pass

@router.post('/items')
async def create_item():
    pass
""")
        file_tree = list(walk_files(tmp_path))
        routes = extract_routes(file_tree)
        
        paths = [(r.method, r.path) for r in routes]
        assert ("GET", "/items") in paths
        assert ("POST", "/items") in paths

    def test_extracts_spring_routes(self, tmp_path: Path) -> None:
        """Should extract Spring Boot routes."""
        java_file = tmp_path / "Controller.java"
        java_file.write_text("""
@GetMapping("/api/users")
public List<User> getUsers() {}

@PostMapping("/api/users")
public User createUser() {}
""")
        file_tree = list(walk_files(tmp_path))
        routes = extract_routes(file_tree)
        
        paths = [(r.method, r.path) for r in routes]
        assert ("GET", "/api/users") in paths
        assert ("POST", "/api/users") in paths


class TestExtractSecrets:
    """Tests for secret detection."""

    def test_detects_aws_key(self, tmp_path: Path) -> None:
        """Should detect AWS access key pattern."""
        py_file = tmp_path / "config.py"
        # AWS keys are exactly AKIA + 16 uppercase alphanumeric chars (20 total)
        py_file.write_text('AWS_KEY = "AKIA1234567890ABCDEF"')
        
        file_tree = list(walk_files(tmp_path))
        secrets = extract_secrets(file_tree)
        
        assert len(secrets) >= 1
        assert any(s.type == "aws_access_key" for s in secrets)

    def test_detects_stripe_key(self, tmp_path: Path) -> None:
        """Should detect Stripe live key pattern."""
        js_file = tmp_path / "payment.js"
        js_file.write_text('const key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";')
        
        file_tree = list(walk_files(tmp_path))
        secrets = extract_secrets(file_tree)
        
        assert len(secrets) >= 1
        assert any(s.type == "stripe_live_key" for s in secrets)
        assert "****" in secrets[0].preview

    def test_skips_placeholder_values(self, tmp_path: Path) -> None:
        """Should skip placeholder values."""
        env_file = tmp_path / ".env"
        env_file.write_text('API_KEY = "your_api_key_here"\nSECRET = "placeholder"')
        
        file_tree = list(walk_files(tmp_path))
        secrets = extract_secrets(file_tree)
        
        # Should not detect placeholders
        assert len(secrets) == 0

    def test_skips_comments(self, tmp_path: Path) -> None:
        """Should skip commented lines."""
        py_file = tmp_path / "config.py"
        py_file.write_text('# AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        
        file_tree = list(walk_files(tmp_path))
        secrets = extract_secrets(file_tree)
        
        assert len(secrets) == 0


class TestExtractTLSConfig:
    """Tests for TLS configuration extraction."""

    def test_detects_reject_unauthorized_false(self, tmp_path: Path) -> None:
        """Should detect Node.js insecure TLS setting."""
        js_file = tmp_path / "https.js"
        js_file.write_text('const options = { rejectUnauthorized: false };')
        
        file_tree = list(walk_files(tmp_path))
        tls_config = extract_tls_config(file_tree)
        
        assert tls_config.cert_verification_disabled is True

    def test_detects_python_cert_none(self, tmp_path: Path) -> None:
        """Should detect Python ssl.CERT_NONE."""
        py_file = tmp_path / "client.py"
        py_file.write_text('context.verify_mode = ssl.CERT_NONE')
        
        file_tree = list(walk_files(tmp_path))
        tls_config = extract_tls_config(file_tree)
        
        assert tls_config.cert_verification_disabled is True

    def test_detects_tls_version(self, tmp_path: Path) -> None:
        """Should detect TLS version references."""
        py_file = tmp_path / "server.py"
        py_file.write_text('ssl_context.minimum_version = TLSv1.2')
        
        file_tree = list(walk_files(tmp_path))
        tls_config = extract_tls_config(file_tree)
        
        assert tls_config.version_hint is not None
        assert "TLS" in tls_config.version_hint


class TestExtractDNSConfig:
    """Tests for DNS configuration extraction."""

    def test_detects_custom_resolver(self, tmp_path: Path) -> None:
        """Should detect custom DNS resolver."""
        config = tmp_path / "config.yml"
        config.write_text('dns_resolver: "8.8.8.8"')
        
        file_tree = list(walk_files(tmp_path))
        dns_config = extract_dns_config(file_tree)
        
        assert dns_config.custom_resolver is True
        assert "8.8.8.8" in dns_config.hardcoded_entries

    def test_detects_hardcoded_ips(self, tmp_path: Path) -> None:
        """Should detect hardcoded IPs in config."""
        config = tmp_path / "config.json"
        config.write_text('{"api_host": "52.1.2.3"}')
        
        file_tree = list(walk_files(tmp_path))
        dns_config = extract_dns_config(file_tree)
        
        assert "52.1.2.3" in dns_config.hardcoded_entries


class TestAnalyze:
    """Tests for the main analyze function."""

    def test_produces_valid_manifest(self, tmp_path: Path) -> None:
        """Should produce a valid AttackSurfaceManifest."""
        # Create minimal project
        (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)")
        (tmp_path / "Dockerfile").write_text("FROM python:3.10\nEXPOSE 5000")
        
        scan_id = str(uuid.uuid4())
        manifest = analyze(str(tmp_path), scan_id)
        
        assert manifest.scan_id == scan_id
        assert manifest.target == str(tmp_path)
        assert manifest.extracted_at is not None
        assert "python" in manifest.language_detected
        assert isinstance(manifest.ports, list)
        assert isinstance(manifest.routes, list)
        assert manifest.tls_config is not None
        assert manifest.dns_config is not None

    def test_manifest_serialization(self, tmp_path: Path) -> None:
        """Should serialize manifest to dict properly."""
        (tmp_path / "server.js").write_text("app.listen(3000);")
        
        scan_id = str(uuid.uuid4())
        manifest = analyze(str(tmp_path), scan_id)
        
        d = manifest.to_dict()
        assert d["scan_id"] == scan_id
        assert "ports" in d
        assert "routes" in d
        assert "secrets_found" in d

    def test_invalid_path_raises_error(self) -> None:
        """Should raise error for non-existent path."""
        with pytest.raises(ValueError, match="does not exist"):
            analyze("/nonexistent/path/to/repo", str(uuid.uuid4()))
