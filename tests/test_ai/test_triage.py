from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from vulnhunter.ai.triage import DISCLAIMER, CodeAnalyzer, TriageEngine, TriageResponse


def test_triage_response_valid_risk_levels() -> None:
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "IRRELEVANT", "UNKNOWN"]:
        resp = TriageResponse(real_risk=level, analysis="test", recommendation="test")
        assert resp.real_risk == level


def test_triage_response_rejects_invalid_risk() -> None:
    with pytest.raises(ValidationError):
        TriageResponse(real_risk="INVALID", analysis="test", recommendation="test")


def test_triage_response_rejects_lowercase_risk() -> None:
    with pytest.raises(ValidationError):
        TriageResponse(real_risk="high", analysis="test", recommendation="test")


def test_code_analyzer_find_imports_nonexistent_dir() -> None:
    analyzer = CodeAnalyzer()
    results = analyzer.find_imports(Path("/nonexistent/dir/abc123"), "flask", "pypi")
    assert results == []


def test_disclaimer_constant_exists() -> None:
    assert isinstance(DISCLAIMER, str)
    assert len(DISCLAIMER) > 0


def test_code_analyzer_find_python_imports(tmp_path: Path) -> None:
    src = tmp_path / "app.py"
    src.write_text("import flask\nfrom flask import Flask\napp = Flask(__name__)\n")

    analyzer = CodeAnalyzer()
    results = analyzer.find_imports(tmp_path, "flask", "pypi")
    assert len(results) >= 1
    assert results[0]["file"] == "app.py"
    assert results[0]["line"] == 1


def test_code_analyzer_find_node_imports(tmp_path: Path) -> None:
    src = tmp_path / "index.js"
    src.write_text("const express = require('express');\nconst app = express();\n")

    analyzer = CodeAnalyzer()
    results = analyzer.find_imports(tmp_path, "express", "npm")
    assert len(results) >= 1
    assert "index.js" in results[0]["file"]


def test_code_analyzer_skips_hidden_dirs(tmp_path: Path) -> None:
    hidden = tmp_path / ".venv" / "lib"
    hidden.mkdir(parents=True)
    (hidden / "mod.py").write_text("import flask\n")

    analyzer = CodeAnalyzer()
    results = analyzer.find_imports(tmp_path, "flask", "pypi")
    assert len(results) == 0


def test_code_analyzer_no_extensions(tmp_path: Path) -> None:
    analyzer = CodeAnalyzer()
    results = analyzer.find_imports(tmp_path, "foo", "unknown_eco")
    assert results == []


def test_triage_engine_unavailable() -> None:
    engine = TriageEngine(ollama_url="http://localhost:99999")
    assert engine.is_available() is False


def test_triage_engine_build_prompt() -> None:
    engine = TriageEngine()
    vuln = {
        "id": "CVE-2023-0001",
        "package": "flask",
        "version": "2.0.1",
        "severity": "HIGH",
        "summary": "Test vuln",
    }
    refs = [{"file": "app.py", "line": 1, "snippet": "import flask"}]
    prompt = engine._build_prompt(vuln, refs)
    assert "CVE-2023-0001" in prompt
    assert "flask" in prompt
    assert "app.py" in prompt


def test_triage_engine_build_prompt_no_refs() -> None:
    engine = TriageEngine()
    vuln = {"id": "CVE-2023-0001", "package": "flask", "version": "2.0.1", "severity": "HIGH", "summary": "Test"}
    prompt = engine._build_prompt(vuln, [])
    assert "transitive dependency" in prompt


@patch("vulnhunter.ai.triage.requests.post")
def test_triage_engine_call_ollama_success(mock_post: MagicMock) -> None:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "response": '{"real_risk": "HIGH", "analysis": "Used in routing", "recommendation": "Upgrade"}'
    }
    mock_post.return_value = mock_resp

    engine = TriageEngine()
    result = engine._call_ollama("test prompt")
    assert result["real_risk"] == "HIGH"
    assert "routing" in result["analysis"]


@patch("vulnhunter.ai.triage.requests.post")
def test_triage_engine_call_ollama_invalid_json(mock_post: MagicMock) -> None:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"response": "not valid json here"}
    mock_post.return_value = mock_resp

    engine = TriageEngine()
    result = engine._call_ollama("test prompt")
    assert result["real_risk"] == "UNKNOWN"
    assert "not valid json" in result["analysis"]


@patch("vulnhunter.ai.triage.requests.post")
def test_triage_engine_call_ollama_timeout(mock_post: MagicMock) -> None:
    import requests

    mock_post.side_effect = requests.Timeout("timed out")

    engine = TriageEngine()
    result = engine._call_ollama("test prompt")
    assert result["real_risk"] == "UNKNOWN"
    assert "Manual review" in result["recommendation"]
