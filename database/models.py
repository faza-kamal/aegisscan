"""
database/models.py
Pure sqlite3 schema definition — zero external dependencies.

Schema:
  scans      — one row per scan session
  hosts      — one row per target host  
  ports      — one row per open port
  schema_version — migration tracking

WAL mode, proper indexes, FK enforcement.
"""

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
PRAGMA cache_size=-20000;
PRAGMA temp_store=MEMORY;

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    description TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type   TEXT    NOT NULL,
    target      TEXT    NOT NULL,
    ports_spec  TEXT,
    timing      TEXT    DEFAULT 'normal',
    started_at  TEXT    DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    finished_at TEXT,
    status      TEXT    DEFAULT 'running',
    hosts_found INTEGER DEFAULT 0,
    ports_open  INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_scans_target    ON scans(target);
CREATE INDEX IF NOT EXISTS ix_scans_started   ON scans(started_at);
CREATE INDEX IF NOT EXISTS ix_scans_status    ON scans(status);
CREATE INDEX IF NOT EXISTS ix_scans_tgt_start ON scans(target, started_at);

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip_address  TEXT    NOT NULL,
    hostname    TEXT,
    os_guess    TEXT,
    is_alive    INTEGER DEFAULT 1,
    scan_ms     REAL    DEFAULT 0,
    scanned_at  TEXT    DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE(scan_id, ip_address)
);
CREATE INDEX IF NOT EXISTS ix_hosts_scan_id    ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS ix_hosts_ip         ON hosts(ip_address);
CREATE INDEX IF NOT EXISTS ix_hosts_alive      ON hosts(scan_id, is_alive);

CREATE TABLE IF NOT EXISTS ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port_number INTEGER NOT NULL,
    state       TEXT    DEFAULT 'open',
    service     TEXT    DEFAULT 'unknown',
    product     TEXT,
    version     TEXT,
    banner      TEXT,
    response_ms REAL    DEFAULT 0,
    UNIQUE(host_id, port_number)
);
CREATE INDEX IF NOT EXISTS ix_ports_host_id    ON ports(host_id);
CREATE INDEX IF NOT EXISTS ix_ports_port_num   ON ports(port_number);
CREATE INDEX IF NOT EXISTS ix_ports_host_state ON ports(host_id, state);
"""
