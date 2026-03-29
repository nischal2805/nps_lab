"""Integration tests for CLI commands."""
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

import pytest
from click.testing import CliRunner

from netsentinel.cli import main as cli


@pytest.fixture
def cli_runner():
    """Create a Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def mock_storage_dir(tmp_path: Path):
    """Create a temporary storage directory."""
    storage = tmp_path / ".netsentinel"
    storage.mkdir(parents=True, exist_ok=True)
    (storage / "scans").mkdir(parents=True, exist_ok=True)
    
    index_data = [{
        "scan_id": "scan-001",
        "timestamp": "2024-01-15T10:30:00Z",
        "target": "192.0.2.1",
        "grade": "B",
        "score": 82.5,
    }]
    with open(storage / "index.json", "w") as f:
        json.dump(index_data, f)
    
    return storage


@pytest.mark.integration
class TestCLIScanCommand:
    """Test scan command."""

    def test_scan_with_local_path(self, cli_runner: CliRunner, tmp_path: Path) -> None:
        """Test scan with local path."""
        test_repo = tmp_path / "test_repo"
        test_repo.mkdir()
        (test_repo / "app.py").write_text("print('hello')")
        
        with patch('netsentinel.cli.get_storage_dir', return_value=str(tmp_path / ".netsentinel")):
            with patch('netsentinel.static_analyzer.analyze') as mock_analyze:
                with patch('netsentinel.probes.engine.run_live_probes', new_callable=AsyncMock):
                    with patch('netsentinel.scoring.generate_score_report') as mock_score:
                        from netsentinel.models import AttackSurfaceManifest
                        mock_analyze.return_value = AttackSurfaceManifest(
                            scan_id="test-scan",
                            target=str(test_repo),
                            extracted_at=datetime.now().isoformat(),
                            language_detected=["python"],
                            ports=[],
                            routes=[],
                            secrets_found=[],
                            outbound_hosts=[],
                        )
                        mock_score.return_value = MagicMock(
                            scores=MagicMock(overall=MagicMock(score=100.0, grade='A'))
                        )
                        
                        result = cli_runner.invoke(cli, [
                            'scan',
                            '--target', str(test_repo),
                            '--host', '192.0.2.1',
                            '--static-only',
                        ])
                        
                        assert result.exit_code == 0


@pytest.mark.integration
class TestCLIListCommand:
    """Test list command."""

    def test_list_all_scans(self, cli_runner: CliRunner, mock_storage_dir: Path) -> None:
        """Test listing all scans."""
        with patch('netsentinel.cli.get_storage_dir', return_value=str(mock_storage_dir)):
            result = cli_runner.invoke(cli, ['list'])
            assert result.exit_code == 0
