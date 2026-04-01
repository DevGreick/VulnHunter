import logging
import sqlite3

logger = logging.getLogger("vulnhunter.db.migrations")

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    severity TEXT,
    summary TEXT,
    published TEXT,
    modified TEXT
);

CREATE TABLE IF NOT EXISTS affected_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    version_start TEXT,
    version_start_inclusive INTEGER DEFAULT 1,
    version_end TEXT,
    version_end_inclusive INTEGER DEFAULT 0,
    fixed_version TEXT
);

CREATE INDEX IF NOT EXISTS idx_affected_pkg
    ON affected_packages(ecosystem, package_name);

CREATE INDEX IF NOT EXISTS idx_affected_vuln
    ON affected_packages(vuln_id);

CREATE TABLE IF NOT EXISTS cpe_aliases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,
    cpe_vendor_product TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cpe_alias_pkg
    ON cpe_aliases(package_name);
"""


def init_db(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.executescript(SCHEMA_SQL)

    cursor.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        ("schema_version", str(SCHEMA_VERSION)),
    )
    conn.commit()
    logger.info("Database schema initialized (version %d)", SCHEMA_VERSION)


def check_schema(conn: sqlite3.Connection) -> bool:
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM metadata WHERE key = 'schema_version'")
        row = cursor.fetchone()
        if row is None:
            return False
        return int(row[0]) == SCHEMA_VERSION
    except sqlite3.OperationalError:
        return False
