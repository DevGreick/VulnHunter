from typer.testing import CliRunner

from vulnhunter.cli import app

runner: CliRunner = CliRunner()


def test_help_returns_zero() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "vulnhunter" in result.output.lower() or "vulnerability" in result.output.lower()


def test_scan_help_returns_zero() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "scan" in result.output.lower()


def test_db_help_returns_zero() -> None:
    result = runner.invoke(app, ["db", "--help"])
    assert result.exit_code == 0
    assert "database" in result.output.lower()


def test_config_help_returns_zero() -> None:
    result = runner.invoke(app, ["config", "--help"])
    assert result.exit_code == 0
    assert "config" in result.output.lower() or "settings" in result.output.lower()


def test_scan_no_args_shows_error() -> None:
    result = runner.invoke(app, ["scan"])
    assert result.exit_code != 0


def test_scan_nonexistent_path_shows_error() -> None:
    result = runner.invoke(app, ["scan", "/nonexistent/path/that/does/not/exist"])
    assert result.exit_code != 0
