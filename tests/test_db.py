from pathlib import Path

from vulnhunter.db.store import VulnDB


def test_db_init(tmp_path: Path) -> None:
    db = VulnDB(tmp_path / "test.db")
    assert db.db_path.exists() is False
    _ = db.conn
    assert db.db_path.exists()
    db.close()


def test_upsert_and_query(tmp_db: VulnDB) -> None:
    tmp_db.upsert_vulnerability(
        vuln_id="CVE-2024-0001",
        source="osv",
        severity="HIGH",
        summary="Test vuln",
    )
    tmp_db.insert_affected_package(
        vuln_id="CVE-2024-0001",
        ecosystem="PyPI",
        package_name="Flask",
        version_start="1.0",
        version_end="2.0",
        version_end_inclusive=False,
    )
    tmp_db.commit()

    rows = tmp_db.query_vulnerabilities("PyPI", "flask")
    assert len(rows) == 1
    assert rows[0][0] == "CVE-2024-0001"
    assert rows[0][1] == "osv"


def test_upsert_idempotent(tmp_db: VulnDB) -> None:
    for _ in range(3):
        tmp_db.upsert_vulnerability(
            vuln_id="CVE-2024-0002",
            source="nvd",
            severity="MEDIUM",
            summary="Duplicate test",
        )
    tmp_db.commit()

    cursor = tmp_db.conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE id = 'CVE-2024-0002'")
    assert cursor.fetchone()[0] == 1


def test_cpe_aliases(tmp_db: VulnDB) -> None:
    tmp_db.upsert_cpe_alias("flask", "pocoo:flask")
    tmp_db.upsert_cpe_alias("flask", "palletsprojects:flask")
    tmp_db.upsert_cpe_alias("flask", "pocoo:flask")
    tmp_db.commit()

    aliases = tmp_db.query_cpe_aliases("flask")
    assert "pocoo:flask" in aliases
    assert "palletsprojects:flask" in aliases
    assert len(aliases) == 2


def test_clear_source(populated_db: VulnDB) -> None:
    populated_db.clear_source("osv")
    stats = populated_db.stats()
    assert stats["vulnerabilities"] == 1


def test_metadata(tmp_db: VulnDB) -> None:
    tmp_db.set_metadata("test_key", "test_value")
    assert tmp_db.get_metadata("test_key") == "test_value"
    assert tmp_db.get_metadata("nonexistent") is None


def test_stats(populated_db: VulnDB) -> None:
    stats = populated_db.stats()
    assert stats["vulnerabilities"] == 3
    assert stats["packages"] >= 3
