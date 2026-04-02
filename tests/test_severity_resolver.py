from unittest.mock import MagicMock

import pytest

from vulnhunter.db.store import VulnDB
from vulnhunter.severity_resolver import (
    _resolve_from_cwe,
    _resolve_from_keywords,
    resolve_severity,
)


@pytest.fixture
def mock_db() -> MagicMock:
    db = MagicMock(spec=VulnDB)
    db.get_severity_by_id.return_value = None
    db.get_aliases.return_value = []
    return db


def test_known_severity_returns_unchanged(mock_db: MagicMock) -> None:
    severity, estimated, source = resolve_severity(
        mock_db, "CVE-2023-0001", "HIGH", "some summary", "OSV"
    )
    assert severity == "HIGH"
    assert estimated is False
    assert source == "OSV"
    mock_db.get_severity_by_id.assert_not_called()


def test_unknown_with_nvd_match_returns_nvd(mock_db: MagicMock) -> None:
    mock_db.get_severity_by_id.return_value = "CRITICAL"
    severity, estimated, source = resolve_severity(
        mock_db, "CVE-2023-0001", "UNKNOWN", "some summary", "OSV"
    )
    assert severity == "CRITICAL"
    assert estimated is False
    assert source == "OSV+NVD"


def test_unknown_with_nvd_alias_match(mock_db: MagicMock) -> None:
    mock_db.get_severity_by_id.side_effect = [None, "HIGH"]
    mock_db.get_aliases.return_value = ["GHSA-xxxx-yyyy"]
    severity, estimated, source = resolve_severity(
        mock_db, "CVE-2023-0001", "UNKNOWN", "some summary", "OSV"
    )
    assert severity == "HIGH"
    assert estimated is False
    assert source == "OSV+NVD"


def test_unknown_with_cwe_match(mock_db: MagicMock) -> None:
    severity, estimated, source = resolve_severity(
        mock_db, "CVE-2023-0001", "UNKNOWN", "Vulnerability related to CWE-89 injection", "OSV"
    )
    assert severity == "HIGH"
    assert estimated is True
    assert source == "OSV"


def test_unknown_with_keyword_match(mock_db: MagicMock) -> None:
    severity, estimated, source = resolve_severity(
        mock_db, "CVE-2023-0001", "UNKNOWN", "Remote code execution in parser", "OSV"
    )
    assert severity == "CRITICAL"
    assert estimated is True
    assert source == "OSV"


def test_unknown_with_keyword_sql_injection(mock_db: MagicMock) -> None:
    severity, estimated, source = resolve_severity(
        mock_db, "CVE-2023-0001", "UNKNOWN", "SQL injection via user input", "OSV"
    )
    assert severity == "HIGH"
    assert estimated is True


def test_unknown_with_keyword_dos(mock_db: MagicMock) -> None:
    severity, estimated, source = resolve_severity(
        mock_db, "CVE-2023-0001", "UNKNOWN", "Denial of service via large payload", "OSV"
    )
    assert severity == "MEDIUM"
    assert estimated is True


def test_unknown_no_match_returns_medium_fallback(mock_db: MagicMock) -> None:
    severity, estimated, source = resolve_severity(
        mock_db, "CVE-2023-0001", "UNKNOWN", "generic issue with no keywords", "OSV"
    )
    assert severity == "MEDIUM"
    assert estimated is True
    assert source == "OSV"


def test_empty_severity_treated_as_unknown(mock_db: MagicMock) -> None:
    severity, estimated, source = resolve_severity(
        mock_db, "CVE-2023-0001", "", "Remote code execution", "OSV"
    )
    assert severity == "CRITICAL"
    assert estimated is True


def test_resolve_from_cwe_known() -> None:
    assert _resolve_from_cwe("Issue related to CWE-94 code injection") == "CRITICAL"


def test_resolve_from_cwe_unknown() -> None:
    assert _resolve_from_cwe("No CWE referenced here") is None


def test_resolve_from_keywords_none() -> None:
    assert _resolve_from_keywords("just a normal bug fix") is None


def test_source_string_osv_nvd_crossref(mock_db: MagicMock) -> None:
    mock_db.get_severity_by_id.return_value = "HIGH"
    _, _, source = resolve_severity(
        mock_db, "CVE-2023-0001", "UNKNOWN", "test", "OSV"
    )
    assert "OSV+NVD" in source
