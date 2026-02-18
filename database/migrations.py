"""
database/migrations.py - Pure stdlib sqlite3 migration manager.
Note: ALTER TABLE ... IF NOT EXISTS not supported in SQLite < 3.35
We handle this by checking columns manually.
"""
from __future__ import annotations
import sqlite3
from utils.logger import get_logger
log = get_logger("aegisscan.migrations")

MIGRATIONS = [
    (1, "initial_schema",            ""),
    (2, "add_os_guess_hosts",        ("hosts", "os_guess", "TEXT")),
    (3, "add_product_version_ports", ("ports", "product", "TEXT")),
    (4, "add_version_ports",         ("ports", "version", "TEXT")),
]

def _has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == column for r in rows)

def get_version(db_path: str) -> int:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, description TEXT, applied_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')))")
        conn.commit()
        r = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        return r[0] or 0
    finally:
        conn.close()

def migrate(db_path: str = "aegisscan.db") -> None:
    cur = get_version(db_path)
    pending = [(v, d, s) for v, d, s in MIGRATIONS if v > cur]
    if not pending:
        log.info(f"Schema v{cur} — up to date")
        return
    conn = sqlite3.connect(db_path)
    try:
        for v, desc, spec in sorted(pending):
            log.info(f"Applying migration v{v}: {desc}")
            if spec and isinstance(spec, tuple):
                table, col, col_type = spec
                if not _has_column(conn, table, col):
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
                    conn.commit()
            conn.execute(
                "INSERT OR REPLACE INTO schema_version(version,description) VALUES(?,?)", (v, desc)
            )
            conn.commit()
            log.info(f"Migration v{v} applied")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate()
