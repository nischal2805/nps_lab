"""
Static analysis module for NetSentinel.

Reads source code (local or GitHub) and extracts attack surface WITHOUT
executing any code. Produces an AttackSurfaceManifest with ports, routes,
secrets, TLS config, DNS config, and dependency information (SBOM).
"""
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Optional, Set, Tuple

import yaml

from netsentinel.config import SECRET_PATTERNS
from netsentinel.models import (
    AttackSurfaceManifest,
    DependencyEntry,
    DNSConfig,
    Finding,
    OutboundHost,
    PortEntry,
    RouteEntry,
    SecretEntry,
    TLSConfig,
)
from netsentinel.sbom import generate_sbom_findings, Dependency

# File extensions to include in analysis
INCLUDED_EXTENSIONS = {
    '.py', '.js', '.ts', '.tsx', '.jsx', '.java',
    '.yml', '.yaml', '.json', '.env', '.properties',
    '.toml', '.xml', '.go', '.rb', '.php',
}

# Directories to skip
EXCLUDED_DIRS = {
    'node_modules', '.git', '__pycache__', 'venv', 'env',
    '.venv', 'dist', 'build', '.next', '.nuxt', 'vendor',
    'target', '.idea', '.vscode', 'coverage', '.pytest_cache',
}

# Files to always include regardless of extension
INCLUDED_FILES = {
    'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    '.env', '.env.local', '.env.development', '.env.production',
    'Makefile', 'Procfile',
}


def analyze(target: str, scan_id: str) -> AttackSurfaceManifest:
    """
    Analyze a codebase and return its attack surface manifest.
    
    Args:
        target: Local path or GitHub HTTPS URL
        scan_id: UUID for this scan
        
    Returns:
        AttackSurfaceManifest with all extracted data
    """
    manifest, _ = analyze_with_findings(target, scan_id)
    return manifest


def analyze_with_findings(target: str, scan_id: str) -> Tuple[AttackSurfaceManifest, List[Finding]]:
    """
    Analyze a codebase and return both the manifest and any security findings.
    
    This is the main analysis function that also performs SBOM vulnerability
    checking and generates findings for vulnerable dependencies.
    
    Args:
        target: Local path or GitHub HTTPS URL
        scan_id: UUID for this scan
        
    Returns:
        Tuple of (AttackSurfaceManifest, List[Finding])
    """
    cloned_path: Optional[Path] = None
    root_path: Path
    
    # 1. If GitHub URL, clone to temp directory
    if _is_github_url(target):
        cloned_path = clone_github_repo(target)
        root_path = cloned_path
    else:
        root_path = Path(target).resolve()
        if not root_path.exists():
            raise ValueError(f"Target path does not exist: {target}")
    
    try:
        # 2. Walk file tree and collect (path, content) tuples
        file_tree = list(walk_files(root_path))
        
        # 3. Run all extractors
        languages = detect_languages(file_tree, root_path)
        ports = extract_ports(file_tree)
        routes = extract_routes(file_tree)
        secrets = extract_secrets(file_tree)
        outbound = extract_outbound_hosts(file_tree)
        tls_config = extract_tls_config(file_tree)
        dns_config = extract_dns_config(file_tree)
        
        # 4. Generate SBOM and vulnerability findings
        sbom_findings, sbom_dependencies = generate_sbom_findings(
            root_path, scan_id, file_tree
        )
        
        # Convert SBOM dependencies to manifest format
        dependencies = _convert_sbom_dependencies(sbom_dependencies)
        
        # 5. Assemble manifest
        manifest = AttackSurfaceManifest(
            scan_id=scan_id,
            target=target,
            extracted_at=datetime.now(timezone.utc).isoformat(),
            language_detected=languages,
            ports=ports,
            routes=routes,
            outbound_hosts=outbound,
            secrets_found=secrets,
            dependencies=dependencies,
            tls_config=tls_config,
            dns_config=dns_config,
        )
        
        return manifest, sbom_findings
        
    finally:
        # 6. Clean up temp dir if cloned
        if cloned_path:
            cleanup_temp(cloned_path)


def _convert_sbom_dependencies(deps: List[Dependency]) -> List[DependencyEntry]:
    """Convert SBOM Dependency objects to DependencyEntry for the manifest."""
    return [
        DependencyEntry(
            name=dep.name,
            version=dep.version,
            ecosystem=dep.ecosystem,
            source_file=dep.source_file,
            vulnerable=len(dep.vulnerabilities) > 0,
            vulnerability_count=len(dep.vulnerabilities),
        )
        for dep in deps
    ]


def _is_github_url(target: str) -> bool:
    """Check if target is a GitHub URL."""
    return target.startswith('https://github.com/') or target.startswith('git@github.com:')


def clone_github_repo(url: str) -> Path:
    """Clone a GitHub repo to temp directory, return path."""
    try:
        import git
    except ImportError:
        raise ImportError("gitpython is required for GitHub cloning. Install with: pip install gitpython")
    
    # Create temp directory
    temp_dir = tempfile.mkdtemp(prefix='netsentinel_')
    temp_path = Path(temp_dir)
    
    try:
        # Clone the repository (shallow clone for speed)
        git.Repo.clone_from(url, temp_path, depth=1)
        return temp_path
    except git.GitCommandError as e:
        # Clean up on failure
        shutil.rmtree(temp_path, ignore_errors=True)
        raise RuntimeError(f"Failed to clone repository: {e}")


def cleanup_temp(path: Path) -> None:
    """Remove temp directory."""
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def walk_files(root_path: Path) -> Iterator[Tuple[Path, str]]:
    """
    Yield (file_path, content) for all relevant files.
    
    Skips: node_modules, .git, __pycache__, venv, dist, build
    Includes: .py, .js, .ts, .tsx, .java, .yml, .yaml, .json, .env, Dockerfile
    """
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Modify dirnames in-place to skip excluded directories
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        
        for filename in filenames:
            file_path = Path(dirpath) / filename
            
            # Check if file should be included
            if filename in INCLUDED_FILES or file_path.suffix.lower() in INCLUDED_EXTENSIONS:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    yield file_path, content
                except (IOError, OSError):
                    continue


def detect_languages(file_tree: List[Tuple[Path, str]], root_path: Path) -> List[str]:
    """Detect languages in the codebase."""
    languages: Set[str] = set()
    
    extension_mapping = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.java': 'java',
        '.go': 'go',
        '.rb': 'ruby',
        '.php': 'php',
    }
    
    # Marker files for languages/frameworks
    marker_files = {
        'package.json': 'javascript',
        'requirements.txt': 'python',
        'Pipfile': 'python',
        'pyproject.toml': 'python',
        'setup.py': 'python',
        'pom.xml': 'java',
        'build.gradle': 'java',
        'go.mod': 'go',
        'Gemfile': 'ruby',
        'composer.json': 'php',
        'Cargo.toml': 'rust',
    }
    
    for file_path, _ in file_tree:
        # Check extension
        suffix = file_path.suffix.lower()
        if suffix in extension_mapping:
            languages.add(extension_mapping[suffix])
        
        # Check marker files
        if file_path.name in marker_files:
            languages.add(marker_files[file_path.name])
    
    return sorted(languages)


def extract_ports(file_tree: List[Tuple[Path, str]]) -> List[PortEntry]:
    """
    Extract ports from:
    - Dockerfiles (EXPOSE directives)
    - docker-compose.yml (ports: mappings)
    - .env files (PORT variables)
    - Config files (application.properties, config.yml, config.json)
    - Source code (socket.listen() calls)
    """
    ports: List[PortEntry] = []
    seen_ports: Set[Tuple[int, str, str, int]] = set()  # (port, proto, file, line)
    
    def add_port(port: int, protocol: str, source_file: str, line: int, 
                 service_hint: Optional[str] = None) -> None:
        key = (port, protocol, source_file, line)
        if key not in seen_ports and 1 <= port <= 65535:
            seen_ports.add(key)
            ports.append(PortEntry(
                port=port,
                protocol=protocol,
                source_file=source_file,
                line=line,
                service_hint=service_hint,
            ))
    
    for file_path, content in file_tree:
        rel_path = str(file_path)
        filename = file_path.name.lower()
        lines = content.splitlines()
        
        # Dockerfile EXPOSE directives
        if filename == 'dockerfile' or filename.startswith('dockerfile.'):
            for i, line in enumerate(lines, 1):
                match = re.match(r'^\s*EXPOSE\s+(.+)', line, re.IGNORECASE)
                if match:
                    for port_str in re.findall(r'(\d+)(?:/(\w+))?', match.group(1)):
                        port = int(port_str[0])
                        proto = port_str[1].lower() if port_str[1] else 'tcp'
                        add_port(port, proto, rel_path, i, _guess_service(port))
        
        # docker-compose.yml
        elif filename in ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'):
            _extract_compose_ports(content, rel_path, add_port)
        
        # .env files
        elif filename.startswith('.env'):
            _extract_env_ports(lines, rel_path, add_port)
        
        # application.properties (Java/Spring)
        elif filename == 'application.properties':
            _extract_properties_ports(lines, rel_path, add_port)
        
        # YAML config files
        elif file_path.suffix.lower() in ('.yml', '.yaml') and 'config' in filename:
            _extract_yaml_config_ports(content, rel_path, add_port)
        
        # JSON config files
        elif file_path.suffix.lower() == '.json' and 'config' in filename:
            _extract_json_config_ports(content, rel_path, add_port)
        
        # Source code - socket.listen() and app.listen() calls
        elif file_path.suffix.lower() in ('.py', '.js', '.ts', '.tsx', '.java'):
            _extract_source_ports(lines, rel_path, file_path.suffix, add_port)
    
    return ports


def _guess_service(port: int) -> Optional[str]:
    """Guess service from port number."""
    services = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 443: 'https', 3000: 'http', 3306: 'mysql',
        5432: 'postgresql', 5672: 'amqp', 6379: 'redis', 8080: 'http',
        8443: 'https', 9000: 'http', 27017: 'mongodb',
    }
    return services.get(port)


def _extract_compose_ports(content: str, rel_path: str, 
                           add_port: callable) -> None:
    """Extract ports from docker-compose YAML."""
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return
            
        services = data.get('services', {})
        if not isinstance(services, dict):
            return
            
        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue
            port_specs = service_config.get('ports', [])
            if not isinstance(port_specs, list):
                continue
            for port_spec in port_specs:
                ports_parsed = _parse_compose_port(str(port_spec))
                for port, proto in ports_parsed:
                    add_port(port, proto, rel_path, 0, _guess_service(port))
    except yaml.YAMLError:
        pass


def _parse_compose_port(port_spec: str) -> List[Tuple[int, str]]:
    """Parse docker-compose port specification."""
    results = []
    # Handle formats: "8080:80", "8080", "8080:80/tcp", "8080-8090:80-90"
    port_spec = port_spec.strip('"\'')
    
    # Extract protocol if specified
    proto = 'tcp'
    if '/' in port_spec:
        port_spec, proto = port_spec.rsplit('/', 1)
    
    # Handle host:container format
    if ':' in port_spec:
        parts = port_spec.split(':')
        container_port = parts[-1]
    else:
        container_port = port_spec
    
    # Handle port ranges
    if '-' in container_port:
        try:
            start, end = map(int, container_port.split('-'))
            for p in range(start, min(end + 1, start + 10)):  # Limit range
                results.append((p, proto))
        except ValueError:
            pass
    else:
        try:
            results.append((int(container_port), proto))
        except ValueError:
            pass
    
    return results


def _extract_env_ports(lines: List[str], rel_path: str, 
                       add_port: callable) -> None:
    """Extract PORT variables from .env files."""
    port_pattern = re.compile(r'^[A-Z_]*PORT[A-Z_]*\s*=\s*(\d+)', re.IGNORECASE)
    for i, line in enumerate(lines, 1):
        match = port_pattern.match(line.strip())
        if match:
            try:
                port = int(match.group(1))
                add_port(port, 'tcp', rel_path, i, _guess_service(port))
            except ValueError:
                pass


def _extract_properties_ports(lines: List[str], rel_path: str, 
                              add_port: callable) -> None:
    """Extract ports from Java properties files."""
    port_pattern = re.compile(r'^[a-z._]*port\s*=\s*(\d+)', re.IGNORECASE)
    for i, line in enumerate(lines, 1):
        match = port_pattern.match(line.strip())
        if match:
            try:
                port = int(match.group(1))
                add_port(port, 'tcp', rel_path, i, _guess_service(port))
            except ValueError:
                pass


def _extract_yaml_config_ports(content: str, rel_path: str, 
                               add_port: callable) -> None:
    """Extract ports from YAML config files."""
    try:
        data = yaml.safe_load(content)
        _extract_ports_from_dict(data, rel_path, add_port)
    except yaml.YAMLError:
        pass


def _extract_json_config_ports(content: str, rel_path: str, 
                               add_port: callable) -> None:
    """Extract ports from JSON config files."""
    import json
    try:
        data = json.loads(content)
        _extract_ports_from_dict(data, rel_path, add_port)
    except json.JSONDecodeError:
        pass


def _extract_ports_from_dict(data: any, rel_path: str, 
                             add_port: callable, depth: int = 0) -> None:
    """Recursively extract port values from nested dict."""
    if depth > 10:  # Prevent infinite recursion
        return
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(key, str) and 'port' in key.lower():
                if isinstance(value, int) and 1 <= value <= 65535:
                    add_port(value, 'tcp', rel_path, 0, _guess_service(value))
            _extract_ports_from_dict(value, rel_path, add_port, depth + 1)
    elif isinstance(data, list):
        for item in data:
            _extract_ports_from_dict(item, rel_path, add_port, depth + 1)


def _extract_source_ports(lines: List[str], rel_path: str, 
                          suffix: str, add_port: callable) -> None:
    """Extract ports from source code (listen calls)."""
    patterns = [
        # JavaScript/TypeScript: app.listen(3000), server.listen(8080)
        re.compile(r'\.listen\s*\(\s*(\d+)'),
        # Python: socket.listen(...) on port, Flask/FastAPI
        re.compile(r'port\s*=\s*(\d+)'),
        # General: bind to port
        re.compile(r'bind\s*\([^)]*["\']?[\d.]*["\']?\s*,\s*(\d+)'),
    ]
    
    for i, line in enumerate(lines, 1):
        for pattern in patterns:
            for match in pattern.finditer(line):
                try:
                    port = int(match.group(1))
                    if 1 <= port <= 65535:
                        add_port(port, 'tcp', rel_path, i, _guess_service(port))
                except ValueError:
                    pass


def extract_routes(file_tree: List[Tuple[Path, str]]) -> List[RouteEntry]:
    """
    Extract HTTP routes from various frameworks.
    
    TypeScript/JavaScript:
    - Express: app.get('/path'), router.post('/path')
    - Next.js: files under pages/api/ and app/api/
    
    Python:
    - Flask: @app.route('/path', methods=['GET'])
    - FastAPI: @app.get('/path'), @router.post('/path')
    - Django: URL patterns in urls.py
    
    Java:
    - Spring: @RequestMapping, @GetMapping, @PostMapping, etc.
    """
    routes: List[RouteEntry] = []
    seen: Set[Tuple[str, str, str, int]] = set()
    
    def add_route(method: str, path: str, source_file: str, line: int,
                  framework: Optional[str] = None, auth_hint: Optional[str] = None) -> None:
        key = (method, path, source_file, line)
        if key not in seen:
            seen.add(key)
            routes.append(RouteEntry(
                method=method.upper(),
                path=path,
                source_file=source_file,
                line=line,
                framework=framework,
                auth_hint=auth_hint,
            ))
    
    for file_path, content in file_tree:
        rel_path = str(file_path)
        lines = content.splitlines()
        suffix = file_path.suffix.lower()
        
        # Next.js API routes (file-based routing)
        if _is_nextjs_api_route(file_path):
            _extract_nextjs_routes(file_path, content, add_route)
        
        # JavaScript/TypeScript - Express
        elif suffix in ('.js', '.ts', '.tsx', '.jsx'):
            _extract_express_routes(lines, rel_path, add_route)
        
        # Python - Flask/FastAPI/Django
        elif suffix == '.py':
            filename = file_path.name.lower()
            if filename == 'urls.py':
                _extract_django_routes(lines, rel_path, add_route)
            else:
                _extract_flask_fastapi_routes(lines, rel_path, add_route)
        
        # Java - Spring
        elif suffix == '.java':
            _extract_spring_routes(lines, rel_path, add_route)
    
    return routes


def _is_nextjs_api_route(file_path: Path) -> bool:
    """Check if file is a Next.js API route."""
    path_str = str(file_path).replace('\\', '/')
    return ('/pages/api/' in path_str or '/app/api/' in path_str)


def _extract_nextjs_routes(file_path: Path, content: str, 
                           add_route: callable) -> None:
    """Extract routes from Next.js file-based routing."""
    path_str = str(file_path).replace('\\', '/')
    
    # Extract API path from file path
    if '/pages/api/' in path_str:
        api_path = path_str.split('/pages/api/')[-1]
    elif '/app/api/' in path_str:
        api_path = path_str.split('/app/api/')[-1]
    else:
        return
    
    # Convert file path to API route
    api_path = '/' + api_path
    api_path = re.sub(r'\.(js|ts|jsx|tsx)$', '', api_path)
    api_path = re.sub(r'/index$', '', api_path)
    api_path = re.sub(r'\[([^\]]+)\]', r':\1', api_path)  # [id] -> :id
    
    if not api_path:
        api_path = '/'
    
    # Check for exported HTTP methods
    methods = []
    if re.search(r'export\s+(async\s+)?function\s+GET', content):
        methods.append('GET')
    if re.search(r'export\s+(async\s+)?function\s+POST', content):
        methods.append('POST')
    if re.search(r'export\s+(async\s+)?function\s+PUT', content):
        methods.append('PUT')
    if re.search(r'export\s+(async\s+)?function\s+DELETE', content):
        methods.append('DELETE')
    if re.search(r'export\s+(async\s+)?function\s+PATCH', content):
        methods.append('PATCH')
    if re.search(r'export\s+default', content) and not methods:
        methods = ['GET', 'POST']  # Default handler supports all methods
    
    for method in methods:
        add_route(method, '/api' + api_path, str(file_path), 1, 'nextjs')


def _extract_express_routes(lines: List[str], rel_path: str, 
                            add_route: callable) -> None:
    """Extract routes from Express.js code."""
    # Patterns for app.get/post/put/delete and router.get/post/put/delete
    patterns = [
        re.compile(r'(?:app|router)\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']+)["\']'),
        re.compile(r'(?:app|router)\.use\s*\(\s*["\']([^"\']+)["\']'),
    ]
    
    for i, line in enumerate(lines, 1):
        for pattern in patterns:
            for match in pattern.finditer(line):
                if len(match.groups()) == 2:
                    method, path = match.groups()
                    add_route(method, path, rel_path, i, 'express')
                else:
                    path = match.group(1)
                    add_route('USE', path, rel_path, i, 'express')


def _extract_flask_fastapi_routes(lines: List[str], rel_path: str, 
                                  add_route: callable) -> None:
    """Extract routes from Flask and FastAPI code."""
    # Flask: @app.route('/path', methods=['GET', 'POST'])
    flask_pattern = re.compile(
        r'@(?:app|bp|blueprint)\.route\s*\(\s*["\']([^"\']+)["\']'
        r'(?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?'
    )
    
    # FastAPI: @app.get('/path'), @router.post('/path')
    fastapi_pattern = re.compile(
        r'@(?:app|router)\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']+)["\']'
    )
    
    for i, line in enumerate(lines, 1):
        # Check Flask patterns
        for match in flask_pattern.finditer(line):
            path = match.group(1)
            methods_str = match.group(2)
            if methods_str:
                methods = re.findall(r'["\'](\w+)["\']', methods_str)
            else:
                methods = ['GET']
            for method in methods:
                add_route(method, path, rel_path, i, 'flask')
        
        # Check FastAPI patterns
        for match in fastapi_pattern.finditer(line):
            method, path = match.groups()
            add_route(method, path, rel_path, i, 'fastapi')


def _extract_django_routes(lines: List[str], rel_path: str, 
                           add_route: callable) -> None:
    """Extract routes from Django urls.py."""
    # path('api/users/', views.user_list)
    # re_path(r'^api/users/(?P<id>\d+)/$', views.user_detail)
    patterns = [
        re.compile(r"path\s*\(\s*['\"]([^'\"]+)['\"]"),
        re.compile(r"re_path\s*\(\s*r?['\"]([^'\"]+)['\"]"),
        re.compile(r"url\s*\(\s*r?['\"]([^'\"]+)['\"]"),
    ]
    
    for i, line in enumerate(lines, 1):
        for pattern in patterns:
            for match in pattern.finditer(line):
                path = match.group(1)
                # Clean up regex patterns
                path = re.sub(r'\^|\$', '', path)
                path = re.sub(r'\(\?P<([^>]+)>[^)]+\)', r':\1', path)
                if not path.startswith('/'):
                    path = '/' + path
                add_route('GET', path, rel_path, i, 'django')


def _extract_spring_routes(lines: List[str], rel_path: str, 
                           add_route: callable) -> None:
    """Extract routes from Spring annotations."""
    mapping_pattern = re.compile(
        r'@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)'
        r'\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']'
    )
    
    method_mapping = {
        'RequestMapping': 'GET',  # Default, could be any
        'GetMapping': 'GET',
        'PostMapping': 'POST',
        'PutMapping': 'PUT',
        'DeleteMapping': 'DELETE',
        'PatchMapping': 'PATCH',
    }
    
    for i, line in enumerate(lines, 1):
        for match in mapping_pattern.finditer(line):
            annotation, path = match.groups()
            method = method_mapping.get(annotation, 'GET')
            add_route(method, path, rel_path, i, 'spring')


def extract_secrets(file_tree: List[Tuple[Path, str]]) -> List[SecretEntry]:
    """
    Scan files for secrets using patterns from config.SECRET_PATTERNS.
    
    - Generates redacted preview (e.g., "sk_live_****")
    - Checks .env files for non-placeholder values
    """
    secrets: List[SecretEntry] = []
    seen: Set[Tuple[str, str, int]] = set()  # (type, file, line)
    
    # Compile patterns
    compiled_patterns = {
        name: re.compile(pattern) 
        for name, pattern in SECRET_PATTERNS.items()
    }
    
    for file_path, content in file_tree:
        rel_path = str(file_path)
        lines = content.splitlines()
        
        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            
            for secret_type, pattern in compiled_patterns.items():
                for match in pattern.finditer(line):
                    key = (secret_type, rel_path, i)
                    if key in seen:
                        continue
                    
                    matched_value = match.group(0)
                    
                    # Skip placeholder values
                    if _is_placeholder(matched_value):
                        continue
                    
                    seen.add(key)
                    
                    # Generate redacted preview
                    preview = _redact_secret(matched_value, secret_type)
                    
                    # Determine severity
                    severity = _secret_severity(secret_type)
                    
                    secrets.append(SecretEntry(
                        type=secret_type,
                        file=rel_path,
                        line=i,
                        preview=preview,
                        severity=severity,
                    ))
    
    return secrets


def _is_placeholder(value: str) -> bool:
    """Check if a value is likely a placeholder."""
    placeholders = [
        'xxx', 'yyy', 'zzz', 'placeholder', 'example', 'your_',
        'change_me', 'changeme', 'replace', 'todo', 'fixme',
        '***', '---', '...', '<', '>', '${', '{{',
    ]
    lower_value = value.lower()
    return any(p in lower_value for p in placeholders)


def _redact_secret(value: str, secret_type: str) -> str:
    """Generate a redacted preview of the secret."""
    if len(value) <= 8:
        return '****'
    
    # Show prefix for identifiable tokens
    if secret_type in ('stripe_live_key', 'stripe_test_key'):
        return value[:8] + '****'
    elif secret_type in ('github_token', 'github_oauth'):
        return value[:4] + '****'
    elif secret_type == 'aws_access_key':
        return value[:4] + '****'
    elif secret_type == 'private_key':
        return '-----BEGIN PRIVATE KEY-----'
    else:
        # Generic: show first 4 and last 2 chars
        return value[:4] + '****' + value[-2:]


def _secret_severity(secret_type: str) -> str:
    """Determine severity based on secret type."""
    critical_types = {
        'aws_access_key', 'aws_secret_key', 'private_key',
        'stripe_live_key', 'github_token',
    }
    high_types = {
        'stripe_test_key', 'github_oauth', 'generic_api_key',
    }
    
    if secret_type in critical_types:
        return 'critical'
    elif secret_type in high_types:
        return 'high'
    else:
        return 'medium'


def extract_outbound_hosts(file_tree: List[Tuple[Path, str]]) -> List[OutboundHost]:
    """Extract outbound host references (URLs, hostnames)."""
    hosts: List[OutboundHost] = []
    seen: Set[Tuple[str, str, int]] = set()
    
    # Pattern for URLs and hostnames
    url_pattern = re.compile(
        r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)'
    )
    
    # Skip common/local hosts
    skip_hosts = {
        'localhost', '127.0.0.1', '0.0.0.0', 'example.com',
        'example.org', 'test.com', 'localhost.localdomain',
    }
    
    for file_path, content in file_tree:
        rel_path = str(file_path)
        lines = content.splitlines()
        
        for i, line in enumerate(lines, 1):
            for match in url_pattern.finditer(line):
                host = match.group(1).lower()
                
                if host in skip_hosts:
                    continue
                
                key = (host, rel_path, i)
                if key not in seen:
                    seen.add(key)
                    hosts.append(OutboundHost(
                        host=host,
                        source_file=rel_path,
                        line=i,
                    ))
    
    return hosts


def extract_tls_config(file_tree: List[Tuple[Path, str]]) -> TLSConfig:
    """
    Extract TLS configuration hints:
    - TLS version settings
    - rejectUnauthorized: false (Node.js)
    - ssl.CERT_NONE (Python)
    - Cert pinning references
    """
    version_hint: Optional[str] = None
    cert_verification_disabled = False
    cert_pinning = False
    
    # Patterns for TLS issues
    patterns = {
        # Node.js: rejectUnauthorized: false
        'node_insecure': re.compile(r'rejectUnauthorized\s*:\s*false'),
        # Python: ssl.CERT_NONE, verify=False
        'python_insecure': re.compile(r'(?:ssl\.CERT_NONE|verify\s*=\s*False|VERIFY_NONE)'),
        # TLS version settings
        'tls_version': re.compile(r'(?:TLSv?1\.?[0-3]|SSLv[23])'),
        # Cert pinning
        'pinning': re.compile(r'(?:certificate.?pinning|pin.?certificate|ssl.?pin)', re.IGNORECASE),
    }
    
    for file_path, content in file_tree:
        # Check for insecure TLS settings
        if patterns['node_insecure'].search(content):
            cert_verification_disabled = True
        
        if patterns['python_insecure'].search(content):
            cert_verification_disabled = True
        
        # Check for TLS version hints
        version_match = patterns['tls_version'].search(content)
        if version_match and not version_hint:
            version_hint = version_match.group(0)
        
        # Check for cert pinning
        if patterns['pinning'].search(content):
            cert_pinning = True
    
    return TLSConfig(
        version_hint=version_hint,
        cert_verification_disabled=cert_verification_disabled,
        cert_pinning=cert_pinning,
    )


def extract_dns_config(file_tree: List[Tuple[Path, str]]) -> DNSConfig:
    """
    Extract DNS configuration:
    - Custom resolver addresses
    - Hardcoded IP addresses that should be domains
    - Internal hostname references
    """
    custom_resolver = False
    hardcoded_entries: List[str] = []
    seen_ips: Set[str] = set()
    
    # Patterns
    resolver_pattern = re.compile(r'(?:resolver|nameserver|dns.?server)\s*[=:]\s*["\']?([\d.]+)')
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    
    # IPs to skip (local, documentation, etc.)
    skip_ips = {
        '127.0.0.1', '0.0.0.0', '255.255.255.255',
        '192.168.0.1', '10.0.0.1', '172.16.0.1',
    }
    
    for file_path, content in file_tree:
        # Skip non-config files for IP detection
        is_config = file_path.suffix.lower() in ('.yml', '.yaml', '.json', '.env', '.properties', '.xml')
        
        # Check for custom resolvers
        for match in resolver_pattern.finditer(content):
            custom_resolver = True
            ip = match.group(1)
            if ip not in skip_ips and ip not in seen_ips:
                seen_ips.add(ip)
                hardcoded_entries.append(ip)
        
        # Check for hardcoded IPs in config files
        if is_config:
            for match in ip_pattern.finditer(content):
                ip = match.group(1)
                # Validate IP format
                parts = ip.split('.')
                if all(0 <= int(p) <= 255 for p in parts):
                    if ip not in skip_ips and ip not in seen_ips:
                        # Skip documentation IPs (192.0.2.x, 198.51.100.x, 203.0.113.x)
                        if not (ip.startswith('192.0.2.') or 
                                ip.startswith('198.51.100.') or 
                                ip.startswith('203.0.113.')):
                            seen_ips.add(ip)
                            hardcoded_entries.append(ip)
    
    return DNSConfig(
        custom_resolver=custom_resolver,
        hardcoded_entries=hardcoded_entries[:20],  # Limit to 20 entries
    )


def scan_git_history_for_secrets(repo_path: Path, max_commits: int = 50) -> List[SecretEntry]:
    """
    Scan git history for leaked secrets.
    
    Args:
        repo_path: Path to the git repository
        max_commits: Maximum number of commits to scan (default: 50)
        
    Returns:
        List of SecretEntry found in git history
    """
    secrets: List[SecretEntry] = []
    
    try:
        import git
    except ImportError:
        return secrets
    
    try:
        repo = git.Repo(repo_path)
    except git.InvalidGitRepositoryError:
        return secrets
    
    # Compile patterns
    compiled_patterns = {
        name: re.compile(pattern) 
        for name, pattern in SECRET_PATTERNS.items()
    }
    
    seen: Set[Tuple[str, str, str]] = set()  # (type, preview, commit)
    
    try:
        commits = list(repo.iter_commits(max_count=max_commits))
    except Exception:
        return secrets
    
    for commit in commits:
        try:
            diff = commit.diff(commit.parents[0] if commit.parents else git.NULL_TREE)
            for diff_item in diff:
                if diff_item.a_blob:
                    try:
                        content = diff_item.a_blob.data_stream.read().decode('utf-8', errors='ignore')
                        for line_num, line in enumerate(content.splitlines(), 1):
                            for secret_type, pattern in compiled_patterns.items():
                                for match in pattern.finditer(line):
                                    matched_value = match.group(0)
                                    if _is_placeholder(matched_value):
                                        continue
                                    
                                    preview = _redact_secret(matched_value, secret_type)
                                    key = (secret_type, preview, str(commit.hexsha)[:7])
                                    
                                    if key not in seen:
                                        seen.add(key)
                                        secrets.append(SecretEntry(
                                            type=secret_type,
                                            file=f"git:{commit.hexsha[:7]}:{diff_item.a_path}",
                                            line=line_num,
                                            preview=preview,
                                            severity=_secret_severity(secret_type),
                                        ))
                    except Exception:
                        continue
        except Exception:
            continue
    
    return secrets
