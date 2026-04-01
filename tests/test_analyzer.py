from pathlib import Path

from vulnhunter.analyzer import _is_version_in_range, _parse_version_safely, analyze
from vulnhunter.db.store import VulnDB
from vulnhunter.models import Dependency, Ecosystem


def test_parse_version_safely_valid() -> None:
    v = _parse_version_safely("2.0.1")
    assert v is not None
    assert str(v) == "2.0.1"


def test_parse_version_safely_invalid() -> None:
    v = _parse_version_safely("not-a-version")
    assert v is None


def test_parse_version_safely_empty() -> None:
    assert _parse_version_safely("") is None
    assert _parse_version_safely("  ") is None


def test_version_in_range_inclusive() -> None:
    v = _parse_version_safely("2.0.0")
    assert v is not None
    assert _is_version_in_range(v, "1.0.0", True, "3.0.0", False)
    assert _is_version_in_range(v, "1.0.0", True, "2.0.0", True)
    assert not _is_version_in_range(v, "1.0.0", True, "2.0.0", False)


def test_version_in_range_no_bounds() -> None:
    v = _parse_version_safely("5.0.0")
    assert v is not None
    assert _is_version_in_range(v, "", True, "", False)


def test_analyze_finds_vulns(populated_db: VulnDB) -> None:
    deps = [
        Dependency(name="flask", version="2.0.1", ecosystem=Ecosystem.PYPI),
        Dependency(name="requests", version="2.28.0", ecosystem=Ecosystem.PYPI),
    ]
    result = analyze(populated_db, deps)
    assert result.total_dependencies == 2
    assert result.total_vulnerabilities == 2
    vuln_ids = {v.vuln_id for v in result.vulnerabilities}
    assert "CVE-2023-0001" in vuln_ids
    assert "CVE-2023-0002" in vuln_ids


def test_analyze_no_match_fixed_version(populated_db: VulnDB) -> None:
    deps = [
        Dependency(name="flask", version="2.3.3", ecosystem=Ecosystem.PYPI),
    ]
    result = analyze(populated_db, deps)
    assert result.total_vulnerabilities == 0


def test_analyze_with_ignore_file(populated_db: VulnDB, tmp_path: Path) -> None:
    ignore_file = tmp_path / ".vulnignore"
    ignore_file.write_text("CVE-2023-0001\n")

    deps = [
        Dependency(name="flask", version="2.0.1", ecosystem=Ecosystem.PYPI),
        Dependency(name="requests", version="2.28.0", ecosystem=Ecosystem.PYPI),
    ]
    result = analyze(populated_db, deps, ignore_file)
    assert result.total_vulnerabilities == 1
    assert result.total_ignored == 1
    assert result.vulnerabilities[0].vuln_id == "CVE-2023-0002"


def test_analyze_with_package_specific_ignore(populated_db: VulnDB, tmp_path: Path) -> None:
    ignore_file = tmp_path / ".vulnignore"
    ignore_file.write_text("CVE-2023-0001 flask\n")

    deps = [
        Dependency(name="flask", version="2.0.1", ecosystem=Ecosystem.PYPI),
    ]
    result = analyze(populated_db, deps, ignore_file)
    assert result.total_vulnerabilities == 0
    assert result.total_ignored == 1


def test_analyze_empty_db(tmp_db: VulnDB) -> None:
    deps = [
        Dependency(name="flask", version="2.0.1", ecosystem=Ecosystem.PYPI),
    ]
    result = analyze(tmp_db, deps)
    assert result.total_vulnerabilities == 0


def test_analyze_sorts_by_severity(populated_db: VulnDB) -> None:
    deps = [
        Dependency(name="flask", version="2.0.1", ecosystem=Ecosystem.PYPI),
        Dependency(name="requests", version="2.28.0", ecosystem=Ecosystem.PYPI),
        Dependency(name="express", version="4.17.1", ecosystem=Ecosystem.NPM),
    ]
    result = analyze(populated_db, deps)
    severities = [v.severity.value for v in result.vulnerabilities]
    assert severities == ["CRITICAL", "HIGH", "MEDIUM"]
