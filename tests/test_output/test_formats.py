import json
from pathlib import Path

from vulnhunter.models import Dependency, Ecosystem, ScanResult, Severity, Vulnerability
from vulnhunter.output.json_report import render_json
from vulnhunter.output.sarif import render_sarif


def _make_result() -> ScanResult:
    return ScanResult(
        total_dependencies=2,
        total_vulnerabilities=1,
        total_ignored=0,
        vulnerabilities=[
            Vulnerability(
                vuln_id="CVE-2023-0001",
                source="osv",
                name="flask",
                version="2.0.1",
                ecosystem=Ecosystem.PYPI,
                severity=Severity.HIGH,
                summary="Test vulnerability",
                fixed_version="2.3.2",
            )
        ],
        dependencies=[
            Dependency(name="flask", version="2.0.1", ecosystem=Ecosystem.PYPI),
            Dependency(name="requests", version="2.31.0", ecosystem=Ecosystem.PYPI),
        ],
    )


def test_json_report(tmp_path: Path) -> None:
    result = _make_result()
    output = tmp_path / "report.json"
    render_json(result, output, base_dir=tmp_path)
    assert output.exists()
    data = json.loads(output.read_text())
    assert data["total_vulnerabilities"] == 1
    assert len(data["vulnerabilities"]) == 1
    assert data["vulnerabilities"][0]["vuln_id"] == "CVE-2023-0001"


def test_sarif_output(tmp_path: Path) -> None:
    result = _make_result()
    output = tmp_path / "report.sarif"
    render_sarif(result, output, base_dir=tmp_path)
    assert output.exists()
    data = json.loads(output.read_text())
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "VulnHunter"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "CVE-2023-0001"


def test_sarif_severity_mapping(tmp_path: Path) -> None:
    result = _make_result()
    output = tmp_path / "report.sarif"
    render_sarif(result, output, base_dir=tmp_path)
    data = json.loads(output.read_text())
    assert data["runs"][0]["results"][0]["level"] == "error"


def test_json_empty_result(tmp_path: Path) -> None:
    result = ScanResult()
    output = tmp_path / "empty.json"
    render_json(result, output, base_dir=tmp_path)
    data = json.loads(output.read_text())
    assert data["total_vulnerabilities"] == 0
    assert data["vulnerabilities"] == []
