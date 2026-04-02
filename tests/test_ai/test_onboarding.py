import json
from pathlib import Path
from unittest.mock import patch

from vulnhunter.onboarding import (
    DEFAULT_CONFIG,
    load_config,
    needs_setup,
    save_config,
    show_banner,
)


def test_load_config_defaults(tmp_path: Path) -> None:
    with patch("vulnhunter.onboarding.CONFIG_FILE", tmp_path / "nonexistent.json"):
        cfg = load_config()
    assert cfg == DEFAULT_CONFIG


def test_save_and_load_config(tmp_path: Path) -> None:
    config_file = tmp_path / "config.json"
    with patch("vulnhunter.onboarding.CONFIG_DIR", tmp_path), patch(
        "vulnhunter.onboarding.CONFIG_FILE", config_file
    ):
        test_config = {"ai_triage_enabled": True, "model": "phi3"}
        save_config(test_config)
        assert config_file.exists()

        loaded = json.loads(config_file.read_text())
        assert loaded["ai_triage_enabled"] is True
        assert loaded["model"] == "phi3"


def test_needs_setup_true(tmp_path: Path) -> None:
    with patch("vulnhunter.onboarding.CONFIG_FILE", tmp_path / "nonexistent.json"):
        assert needs_setup() is True


def test_needs_setup_false(tmp_path: Path) -> None:
    config_file = tmp_path / "config.json"
    config_file.write_text("{}")
    with patch("vulnhunter.onboarding.CONFIG_FILE", config_file):
        assert needs_setup() is False


def test_show_banner_runs() -> None:
    show_banner()


def test_load_config_merge_defaults(tmp_path: Path) -> None:
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"model": "llama3"}))
    with patch("vulnhunter.onboarding.CONFIG_FILE", config_file):
        cfg = load_config()
    assert cfg["model"] == "llama3"
    assert cfg["ai_triage_enabled"] is False
    assert cfg["ollama_url"] == "http://localhost:11434"


def test_load_config_corrupted(tmp_path: Path) -> None:
    config_file = tmp_path / "config.json"
    config_file.write_text("not json{{{")
    with patch("vulnhunter.onboarding.CONFIG_FILE", config_file):
        cfg = load_config()
    assert cfg == DEFAULT_CONFIG
