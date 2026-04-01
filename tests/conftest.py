from pathlib import Path

import pytest

from vulnhunter.db.store import VulnDB


@pytest.fixture
def tmp_db(tmp_path: Path) -> VulnDB:
    db = VulnDB(tmp_path / "test.db")
    _ = db.conn
    return db


@pytest.fixture
def populated_db(tmp_db: VulnDB) -> VulnDB:
    tmp_db.upsert_vulnerability(
        vuln_id="CVE-2023-0001",
        source="osv",
        severity="HIGH",
        summary="Test vulnerability in flask",
        published="2023-01-01",
        modified="2023-01-02",
    )
    tmp_db.insert_affected_package(
        vuln_id="CVE-2023-0001",
        ecosystem="PyPI",
        package_name="flask",
        version_start="1.0",
        version_start_inclusive=True,
        version_end="2.3.2",
        version_end_inclusive=False,
        fixed_version="2.3.2",
    )

    tmp_db.upsert_vulnerability(
        vuln_id="CVE-2023-0002",
        source="osv",
        severity="CRITICAL",
        summary="Critical vulnerability in requests",
        published="2023-02-01",
        modified="2023-02-02",
    )
    tmp_db.insert_affected_package(
        vuln_id="CVE-2023-0002",
        ecosystem="PyPI",
        package_name="requests",
        version_start="",
        version_start_inclusive=True,
        version_end="2.31.0",
        version_end_inclusive=False,
        fixed_version="2.31.0",
    )

    tmp_db.upsert_vulnerability(
        vuln_id="CVE-2023-0003",
        source="nvd",
        severity="MEDIUM",
        summary="Medium vuln in express",
        published="2023-03-01",
        modified="2023-03-02",
    )
    tmp_db.insert_affected_package(
        vuln_id="CVE-2023-0003",
        ecosystem="npm",
        package_name="express",
        version_start="4.0.0",
        version_start_inclusive=True,
        version_end="4.18.0",
        version_end_inclusive=False,
        fixed_version="4.18.0",
    )

    tmp_db.commit()
    return tmp_db


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"
