import logging
import sqlite3
import threading
from pathlib import Path

from vulnhunter.db.migrations import check_schema, init_db

logger = logging.getLogger("vulnhunter.db.store")

DEFAULT_DB_PATH = Path.home() / ".vulnhunter" / "vulnhunter.db"


class VulnDB:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            with self._lock:
                if self._conn is None:
                    self._conn = sqlite3.connect(str(self.db_path))
                    self._conn.execute("PRAGMA journal_mode=WAL")
                    self._conn.execute("PRAGMA foreign_keys=ON")
                    if not check_schema(self._conn):
                        init_db(self._conn)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def upsert_vulnerability(
        self,
        vuln_id: str,
        source: str,
        severity: str,
        summary: str,
        published: str = "",
        modified: str = "",
    ) -> None:
        self.conn.execute(
            """INSERT INTO vulnerabilities (id, source, severity, summary, published, modified)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   source=excluded.source,
                   severity=excluded.severity,
                   summary=excluded.summary,
                   published=excluded.published,
                   modified=excluded.modified""",
            (vuln_id, source, severity, summary, published, modified),
        )

    def insert_affected_package(
        self,
        vuln_id: str,
        ecosystem: str,
        package_name: str,
        version_start: str = "",
        version_start_inclusive: bool = True,
        version_end: str = "",
        version_end_inclusive: bool = False,
        fixed_version: str = "",
    ) -> None:
        self.conn.execute(
            """INSERT INTO affected_packages
               (vuln_id, ecosystem, package_name, version_start,
                version_start_inclusive, version_end, version_end_inclusive, fixed_version)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                vuln_id,
                ecosystem,
                package_name.lower(),
                version_start,
                int(version_start_inclusive),
                version_end,
                int(version_end_inclusive),
                fixed_version,
            ),
        )

    def upsert_cpe_alias(self, package_name: str, cpe_vendor_product: str) -> None:
        self.conn.execute(
            """INSERT INTO cpe_aliases (package_name, cpe_vendor_product)
               SELECT ?, ? WHERE NOT EXISTS (
                   SELECT 1 FROM cpe_aliases
                   WHERE package_name = ? AND cpe_vendor_product = ?
               )""",
            (package_name.lower(), cpe_vendor_product.lower(), package_name.lower(), cpe_vendor_product.lower()),
        )

    def query_vulnerabilities(
        self, ecosystem: str, package_name: str
    ) -> list[tuple[str, str, str, str, str, int, str, int, str]]:
        cursor = self.conn.execute(
            """SELECT v.id, v.source, v.severity, v.summary,
                      ap.version_start, ap.version_start_inclusive,
                      ap.version_end, ap.version_end_inclusive,
                      ap.fixed_version
               FROM vulnerabilities v
               JOIN affected_packages ap ON v.id = ap.vuln_id
               WHERE ap.ecosystem = ? AND ap.package_name = ?""",
            (ecosystem, package_name.lower()),
        )
        return cursor.fetchall()

    def query_cpe_aliases(self, package_name: str) -> list[str]:
        cursor = self.conn.execute(
            "SELECT cpe_vendor_product FROM cpe_aliases WHERE package_name = ?",
            (package_name.lower(),),
        )
        return [row[0] for row in cursor.fetchall()]

    def clear_source(self, source: str) -> None:
        self.conn.execute(
            "DELETE FROM affected_packages WHERE vuln_id IN (SELECT id FROM vulnerabilities WHERE source = ?)",
            (source,),
        )
        cursor = self.conn.execute("DELETE FROM vulnerabilities WHERE source = ?", (source,))
        deleted = cursor.rowcount
        self.conn.commit()
        logger.info("Cleared %d vulnerabilities from source '%s'", deleted, source)

    def set_metadata(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            (key, value),
        )
        self.conn.commit()

    def get_metadata(self, key: str) -> str | None:
        cursor = self.conn.execute("SELECT value FROM metadata WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row[0] if row else None

    def stats(self) -> dict[str, int]:
        cursor = self.conn.execute("SELECT COUNT(*) FROM vulnerabilities")
        total_vulns = cursor.fetchone()[0]
        cursor = self.conn.execute("SELECT COUNT(DISTINCT package_name) FROM affected_packages")
        total_packages = cursor.fetchone()[0]
        cursor = self.conn.execute("SELECT COUNT(*) FROM cpe_aliases")
        total_aliases = cursor.fetchone()[0]
        return {
            "vulnerabilities": total_vulns,
            "packages": total_packages,
            "cpe_aliases": total_aliases,
        }

    def insert_vuln_alias(self, vuln_id: str, alias: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO vuln_aliases (vuln_id, alias) VALUES (?, ?)",
            (vuln_id, alias),
        )

    def get_aliases(self, vuln_id: str) -> list[str]:
        cursor = self.conn.execute(
            "SELECT alias FROM vuln_aliases WHERE vuln_id = ?",
            (vuln_id,),
        )
        return [row[0] for row in cursor.fetchall()]

    def get_severity_by_id(self, vuln_id: str) -> str | None:
        cursor = self.conn.execute(
            "SELECT severity FROM vulnerabilities WHERE id = ? AND severity != 'UNKNOWN'",
            (vuln_id,),
        )
        row = cursor.fetchone()
        return row[0] if row else None

    def commit(self) -> None:
        self.conn.commit()
