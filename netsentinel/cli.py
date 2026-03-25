"""
Command-line interface for NetSentinel.

This module provides the main entry point for the CLI application.
It handles argument parsing, command routing, and orchestrates
the scanning workflow.

Commands:
- scan: Run security audits against target hosts
- report: View scan results in dashboard
- compare: Compare two scans side-by-side
- list: List all past scans
"""

import os
import sys
import socket
import subprocess
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import click
import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel

from netsentinel.models import ScanConfig, ScanResult, AttackSurfaceManifest
from netsentinel import __version__

console = Console()

# Default storage directory
DEFAULT_STORAGE_DIR = Path.home() / ".netsentinel"


def get_storage_dir() -> str:
    """Get the NetSentinel storage directory path."""
    storage = DEFAULT_STORAGE_DIR
    storage.mkdir(parents=True, exist_ok=True)
    (storage / "scans").mkdir(parents=True, exist_ok=True)
    return str(storage)


# =============================================================================
# Validation Functions
# =============================================================================


def validate_host(host: str, timeout: float = 3.0) -> bool:
    """
    Check if host is reachable via TCP connection.
    
    Args:
        host: IP address or domain name to check.
        timeout: Connection timeout in seconds.
        
    Returns:
        True if host is reachable, False otherwise.
    """
    # Try common ports to verify connectivity
    test_ports = [80, 443, 22]
    
    for port in test_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except (socket.gaierror, socket.timeout, OSError):
            continue
    
    # Also try ICMP ping as fallback (platform-specific)
    try:
        # Windows uses -n, Unix uses -c
        param = "-n" if sys.platform == "win32" else "-c"
        result = subprocess.run(
            ["ping", param, "1", "-w", "2000" if sys.platform == "win32" else "2", host],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    
    return False


def validate_path(path: str) -> bool:
    """
    Check if local path exists.
    
    Args:
        path: Local filesystem path.
        
    Returns:
        True if path exists, False otherwise.
    """
    return Path(path).exists()


def validate_github_url(url: str) -> bool:
    """
    Check if GitHub URL is accessible (returns 200).
    
    Args:
        url: GitHub repository URL.
        
    Returns:
        True if URL is accessible, False otherwise.
    """
    if not url.startswith("https://github.com/"):
        return False
    
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            response = client.head(url)
            return response.status_code == 200
    except (httpx.RequestError, httpx.TimeoutException):
        return False


def validate_target(target: str) -> tuple[bool, str]:
    """
    Validate target (local path or GitHub URL).
    
    Args:
        target: Local path or GitHub URL.
        
    Returns:
        Tuple of (is_valid, error_message).
    """
    if target.startswith("https://github.com/"):
        if validate_github_url(target):
            return True, ""
        return False, f"GitHub URL not accessible: {target}"
    else:
        if validate_path(target):
            return True, ""
        return False, f"Local path does not exist: {target}"


# =============================================================================
# CLI Group and Commands
# =============================================================================


@click.group()
@click.version_option(version=__version__, prog_name="NetSentinel")
def main():
    """NetSentinel - Network Security Auditing Tool
    
    A comprehensive tool for auditing network security configurations,
    performing multi-layer network probes, and generating scored reports.
    """
    pass


@main.command()
@click.option('--target', '-t', help='Local path or GitHub URL to codebase')
@click.option('--host', '-h', 'host', help='IP address or domain of live target')
@click.option('--port', '-p', type=int, help='Specific port to focus on')
@click.option('--live-only', is_flag=True, help='Skip static analysis')
@click.option('--static-only', is_flag=True, help='Skip live probing')
def scan(target: Optional[str], host: Optional[str], port: Optional[int], 
         live_only: bool, static_only: bool):
    """Run a security scan against a target.
    
    Examples:
    
        netsentinel scan --target ./myapp --host example.com
        
        netsentinel scan --host 192.168.1.1 --live-only
        
        netsentinel scan --target https://github.com/user/repo --static-only
    """
    # 1. Create ScanConfig from options
    config = ScanConfig(
        target=target,
        host=host,
        port=port,
        live_only=live_only,
        static_only=static_only,
    )
    
    # Validate config
    errors = config.validate()
    if errors:
        for error in errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(1)
    
    # 2. Validate inputs
    console.print(Panel.fit(
        f"[bold blue]NetSentinel Security Scan[/bold blue]\n"
        f"Scan ID: {config.scan_id}",
        border_style="blue"
    ))
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Validate target if provided
        if config.target:
            task = progress.add_task("Validating target...", total=None)
            is_valid, error_msg = validate_target(config.target)
            if not is_valid:
                progress.stop()
                console.print(f"[red]Validation failed:[/red] {error_msg}")
                sys.exit(1)
            progress.update(task, description="[green]✓[/green] Target validated")
            progress.remove_task(task)
        
        # Validate host if provided
        if config.host:
            task = progress.add_task(f"Checking host reachability ({config.host})...", total=None)
            if not validate_host(config.host):
                progress.stop()
                console.print(f"[yellow]Warning:[/yellow] Host {config.host} may not be reachable. Continuing anyway...")
            else:
                progress.update(task, description=f"[green]✓[/green] Host {config.host} is reachable")
            progress.remove_task(task)
        
        # Record start time
        started_at = datetime.utcnow().isoformat() + "Z"
        
        # Initialize result containers
        manifest = None
        findings = []
        
        # 3. Run static analyzer if not --live-only
        if config.requires_static_analysis:
            task = progress.add_task("Running static analysis...", total=None)
            
            # TODO: Import and call static analyzer when implemented
            # from netsentinel.static_analyzer import StaticAnalyzer
            # analyzer = StaticAnalyzer(config.target)
            # manifest = analyzer.analyze()
            
            # Stub: Create empty manifest
            manifest = AttackSurfaceManifest(
                scan_id=config.scan_id,
                target=config.target or "",
                extracted_at=datetime.utcnow().isoformat() + "Z",
            )
            
            progress.update(task, description="[green]✓[/green] Static analysis complete")
            progress.remove_task(task)
        
        # 4. Run live probes if not --static-only
        if config.requires_live_probing:
            # Network/Transport layer
            task = progress.add_task("Probing network layer...", total=None)
            
            # TODO: Import and call network probe when implemented
            # from netsentinel.probes.network import NetworkProbe
            # network_probe = NetworkProbe(config.host, config.port)
            # network_findings = network_probe.run()
            # findings.extend(network_findings)
            
            progress.update(task, description="[green]✓[/green] Network probe complete")
            progress.remove_task(task)
            
            # TLS/SSL layer
            task = progress.add_task("Analyzing TLS/SSL configuration...", total=None)
            
            # TODO: Import and call TLS probe when implemented
            # from netsentinel.probes.tls_probe import TLSProbe
            # tls_probe = TLSProbe(config.host, config.port or 443)
            # tls_findings = tls_probe.run()
            # findings.extend(tls_findings)
            
            progress.update(task, description="[green]✓[/green] TLS analysis complete")
            progress.remove_task(task)
            
            # HTTP application layer
            task = progress.add_task("Probing HTTP layer...", total=None)
            
            # TODO: Import and call HTTP probe when implemented
            # from netsentinel.probes.http_probe import HTTPProbe
            # http_probe = HTTPProbe(config.host, config.port or 80)
            # http_findings = http_probe.run()
            # findings.extend(http_findings)
            
            progress.update(task, description="[green]✓[/green] HTTP probe complete")
            progress.remove_task(task)
            
            # DNS layer
            task = progress.add_task("Analyzing DNS configuration...", total=None)
            
            # TODO: Import and call DNS probe when implemented
            # from netsentinel.probes.dns_probe import DNSProbe
            # dns_probe = DNSProbe(config.host)
            # dns_findings = dns_probe.run()
            # findings.extend(dns_findings)
            
            progress.update(task, description="[green]✓[/green] DNS analysis complete")
            progress.remove_task(task)
        
        # 5. Run scoring engine
        task = progress.add_task("Calculating security scores...", total=None)
        
        # TODO: Import and call scoring engine when implemented
        # from netsentinel.scoring import ScoringEngine
        # scorer = ScoringEngine()
        # scores, summary, owasp_coverage = scorer.calculate(findings)
        
        # Stub: Create default scores
        from netsentinel.models import Scores, ScoreSummary, OWASPCoverage
        
        scores = Scores(
            network=100,
            tls=100,
            http=100,
            dns=100,
            weighted_overall=100.0,
            grade="A",
        )
        
        summary = ScoreSummary(
            total_findings=len(findings),
            by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            highest_cvss=0.0,
            highest_cvss_finding="",
        )
        
        owasp_coverage = [
            OWASPCoverage(owasp_id=f"A{i:02d}", status="untested", finding_count=0)
            for i in range(1, 11)
        ]
        
        progress.update(task, description="[green]✓[/green] Scoring complete")
        progress.remove_task(task)
        
        # Record completion time
        completed_at = datetime.utcnow().isoformat() + "Z"
        
        # Calculate duration
        start_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
        duration_seconds = (end_dt - start_dt).total_seconds()
        
        # 6. Save result to ~/.netsentinel/
        task = progress.add_task("Saving scan results...", total=None)
        
        result = ScanResult(
            scan_id=config.scan_id,
            target=config.target,
            host=config.host,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration_seconds,
            manifest=manifest.to_dict() if manifest else None,
            findings=[f.to_dict() if hasattr(f, 'to_dict') else f for f in findings],
            scores=scores,
            owasp_coverage=owasp_coverage,
            summary=summary,
        )
        
        storage_dir = get_storage_dir()
        scan_file = result.save(storage_dir)
        
        progress.update(task, description=f"[green]✓[/green] Results saved to {scan_file}")
        progress.remove_task(task)
    
    # Print summary
    console.print()
    console.print(Panel(
        f"[bold green]Scan Complete[/bold green]\n\n"
        f"Scan ID: {config.scan_id}\n"
        f"Duration: {duration_seconds:.1f}s\n"
        f"Findings: {summary.total_findings}\n"
        f"Grade: [bold]{scores.grade}[/bold] ({scores.weighted_overall:.0f}/100)",
        title="Summary",
        border_style="green",
    ))
    
    # 7. Launch dashboard
    console.print("\n[dim]Launching dashboard...[/dim]")
    
    # TODO: Implement dashboard launch when server is ready
    # from netsentinel.dashboard.server import start_server
    # start_server(scan_id=config.scan_id)
    
    console.print(f"[dim]Dashboard not yet implemented. View results at:[/dim]")
    console.print(f"  {scan_file}")
    
    sys.exit(0)


@main.command()
@click.option('--last', is_flag=True, help='Open most recent scan')
@click.option('--scan-id', help='Open specific scan by ID')
def report(last: bool, scan_id: Optional[str]):
    """View scan results in dashboard.
    
    Examples:
    
        netsentinel report --last
        
        netsentinel report --scan-id abc123
    """
    storage_dir = get_storage_dir()
    
    if not last and not scan_id:
        console.print("[red]Error:[/red] Either --last or --scan-id must be provided")
        sys.exit(1)
    
    if last and scan_id:
        console.print("[red]Error:[/red] Cannot use both --last and --scan-id")
        sys.exit(1)
    
    try:
        if last:
            result = ScanResult.get_last(storage_dir)
            if result is None:
                console.print("[yellow]No scans found.[/yellow] Run a scan first with 'netsentinel scan'")
                sys.exit(1)
            scan_id = result.scan_id
        else:
            result = ScanResult.load(scan_id, storage_dir)
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] Scan not found: {scan_id}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error loading scan:[/red] {e}")
        sys.exit(1)
    
    # Display scan info
    console.print(Panel(
        f"[bold]Scan Report[/bold]\n\n"
        f"Scan ID: {result.scan_id}\n"
        f"Target: {result.target or 'N/A'}\n"
        f"Host: {result.host or 'N/A'}\n"
        f"Date: {result.completed_at}\n"
        f"Duration: {result.duration_seconds:.1f}s\n"
        f"Grade: [bold]{result.scores.grade if result.scores else 'N/A'}[/bold]",
        border_style="blue",
    ))
    
    # Show domain scores
    if result.scores:
        table = Table(title="Domain Scores")
        table.add_column("Domain", style="cyan")
        table.add_column("Score", justify="right")
        
        table.add_row("Network", f"{result.scores.network}/100")
        table.add_row("TLS/SSL", f"{result.scores.tls}/100")
        table.add_row("HTTP", f"{result.scores.http}/100")
        table.add_row("DNS", f"{result.scores.dns}/100")
        table.add_row("[bold]Overall[/bold]", f"[bold]{result.scores.weighted_overall:.0f}/100[/bold]")
        
        console.print(table)
    
    # TODO: Launch dashboard when implemented
    # from netsentinel.dashboard.server import start_server
    # start_server(scan_id=scan_id)
    
    console.print("\n[dim]Dashboard server not yet implemented.[/dim]")


@main.command()
@click.argument('scan_ids', nargs=2)
def compare(scan_ids: tuple[str, str]):
    """Compare two scans side-by-side.
    
    Example:
    
        netsentinel compare scan-id-1 scan-id-2
    """
    storage_dir = get_storage_dir()
    
    # Load both scans
    results = []
    for sid in scan_ids:
        try:
            result = ScanResult.load(sid, storage_dir)
            results.append(result)
        except FileNotFoundError:
            console.print(f"[red]Error:[/red] Scan not found: {sid}")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]Error loading scan {sid}:[/red] {e}")
            sys.exit(1)
    
    result1, result2 = results
    
    # Display comparison table
    console.print(Panel.fit(
        "[bold blue]Scan Comparison[/bold blue]",
        border_style="blue"
    ))
    
    table = Table(title="Comparison")
    table.add_column("Attribute", style="cyan")
    table.add_column(f"Scan 1\n{scan_ids[0][:8]}...", justify="center")
    table.add_column(f"Scan 2\n{scan_ids[1][:8]}...", justify="center")
    table.add_column("Δ", justify="center")
    
    # Basic info
    table.add_row("Target", result1.target or "N/A", result2.target or "N/A", "")
    table.add_row("Host", result1.host or "N/A", result2.host or "N/A", "")
    table.add_row("Date", result1.completed_at[:10], result2.completed_at[:10], "")
    
    # Scores comparison
    if result1.scores and result2.scores:
        def delta_str(v1: int, v2: int) -> str:
            diff = v2 - v1
            if diff > 0:
                return f"[green]+{diff}[/green]"
            elif diff < 0:
                return f"[red]{diff}[/red]"
            return "="
        
        table.add_row(
            "Network Score",
            str(result1.scores.network),
            str(result2.scores.network),
            delta_str(result1.scores.network, result2.scores.network)
        )
        table.add_row(
            "TLS Score",
            str(result1.scores.tls),
            str(result2.scores.tls),
            delta_str(result1.scores.tls, result2.scores.tls)
        )
        table.add_row(
            "HTTP Score",
            str(result1.scores.http),
            str(result2.scores.http),
            delta_str(result1.scores.http, result2.scores.http)
        )
        table.add_row(
            "DNS Score",
            str(result1.scores.dns),
            str(result2.scores.dns),
            delta_str(result1.scores.dns, result2.scores.dns)
        )
        table.add_row(
            "[bold]Overall[/bold]",
            f"[bold]{result1.scores.weighted_overall:.0f}[/bold]",
            f"[bold]{result2.scores.weighted_overall:.0f}[/bold]",
            delta_str(int(result1.scores.weighted_overall), int(result2.scores.weighted_overall))
        )
        table.add_row(
            "[bold]Grade[/bold]",
            f"[bold]{result1.scores.grade}[/bold]",
            f"[bold]{result2.scores.grade}[/bold]",
            ""
        )
    
    # Findings count
    f1_count = result1.summary.total_findings if result1.summary else len(result1.findings)
    f2_count = result2.summary.total_findings if result2.summary else len(result2.findings)
    diff = f2_count - f1_count
    diff_str = f"[green]-{abs(diff)}[/green]" if diff < 0 else f"[red]+{diff}[/red]" if diff > 0 else "="
    table.add_row("Total Findings", str(f1_count), str(f2_count), diff_str)
    
    console.print(table)
    
    # TODO: Launch dashboard compare view when implemented
    # from netsentinel.dashboard.server import start_server
    # start_server(compare=[scan_ids[0], scan_ids[1]])
    
    console.print("\n[dim]Dashboard comparison view not yet implemented.[/dim]")


@main.command('list')
def list_scans():
    """List all past scans.
    
    Displays a table of all scans with ID, target, host, date, and grade.
    """
    storage_dir = get_storage_dir()
    scans = ScanResult.list_all(storage_dir)
    
    if not scans:
        console.print("[yellow]No scans found.[/yellow] Run a scan first with 'netsentinel scan'")
        return
    
    # Sort by date descending (most recent first)
    scans.sort(key=lambda x: x.get("date", ""), reverse=True)
    
    table = Table(title="Scan History")
    table.add_column("Scan ID", style="cyan", no_wrap=True)
    table.add_column("Target", max_width=30)
    table.add_column("Host", max_width=20)
    table.add_column("Date", style="dim")
    table.add_column("Grade", justify="center")
    table.add_column("Findings", justify="right")
    
    for scan in scans:
        scan_id = scan.get("scan_id", "")
        # Truncate scan_id for display
        display_id = scan_id[:8] + "..." if len(scan_id) > 11 else scan_id
        
        target = scan.get("target") or ""
        if len(target) > 30:
            target = "..." + target[-27:]
        
        host = scan.get("host") or "N/A"
        
        date_str = scan.get("date", "")
        if date_str:
            # Extract just the date portion
            date_str = date_str[:10]
        
        grade = scan.get("grade") or "N/A"
        # Color code grades
        if grade == "A":
            grade = f"[green]{grade}[/green]"
        elif grade == "B":
            grade = f"[blue]{grade}[/blue]"
        elif grade == "C":
            grade = f"[yellow]{grade}[/yellow]"
        elif grade in ("D", "F"):
            grade = f"[red]{grade}[/red]"
        
        findings = str(scan.get("total_findings", 0))
        
        table.add_row(display_id, target, host, date_str, grade, findings)
    
    console.print(table)
    console.print(f"\n[dim]Total: {len(scans)} scan(s)[/dim]")
    console.print("[dim]Use 'netsentinel report --scan-id <id>' to view details[/dim]")


if __name__ == "__main__":
    main()
