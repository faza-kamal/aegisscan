"""
database/repository.py
Pure sqlite3 data access layer — zero external dependencies.

Layering: dashboard reads through this. core writes through this.
repository does NOT import core, dashboard, or reporting.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List, Optional

from database.models import SCHEMA_SQL


class Repository:
    """Thread-safe sqlite3 repository."""

    def __init__(self, db_path: str = "aegisscan.db"):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            for stmt in SCHEMA_SQL.strip().split(";"):
                s = stmt.strip()
                if s:
                    conn.execute(s)
            conn.commit()
        finally:
            conn.close()

    @contextmanager
    def _tx(self) -> Generator[sqlite3.Connection, None, None]:
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Scan CRUD ─────────────────────────────────────────────────────────────

    def create_scan(self, scan_type: str, target: str,
                    ports_spec: str = None, timing: str = "normal") -> int:
        with self._tx() as c:
            cur = c.execute(
                "INSERT INTO scans(scan_type,target,ports_spec,timing,status) VALUES(?,?,?,?,'running')",
                (scan_type, target, ports_spec, timing)
            )
            return cur.lastrowid

    def finish_scan(self, scan_id: int, hosts_found: int, ports_open: int) -> None:
        with self._tx() as c:
            c.execute(
                "UPDATE scans SET status='completed', finished_at=?, hosts_found=?, ports_open=? WHERE id=?",
                (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 hosts_found, ports_open, scan_id)
            )

    def get_scan(self, scan_id: int) -> Optional[dict]:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not row:
                return None
            return self._build_scan_dict(conn, dict(row))
        finally:
            conn.close()

    def list_scans(self, limit: int = 50) -> List[dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [self._scan_row_to_dict(dict(r)) for r in rows]
        finally:
            conn.close()

    def delete_scan(self, scan_id: int) -> bool:
        with self._tx() as c:
            n = c.execute("DELETE FROM scans WHERE id=?", (scan_id,)).rowcount
            return n > 0

    # ── Host + Port writes ────────────────────────────────────────────────────

    def save_host(self, scan_id: int, ip: str, hostname: Optional[str],
                  is_alive: bool, scan_ms: float, ports: List[dict],
                  os_guess: Optional[str] = None) -> int:
        with self._tx() as c:
            # Upsert host
            c.execute("""
                INSERT INTO hosts(scan_id,ip_address,hostname,os_guess,is_alive,scan_ms)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(scan_id,ip_address) DO UPDATE SET
                  hostname=excluded.hostname,
                  os_guess=excluded.os_guess,
                  is_alive=excluded.is_alive,
                  scan_ms=excluded.scan_ms
            """, (scan_id, ip, hostname, os_guess, int(is_alive), scan_ms))

            host_id = c.execute(
                "SELECT id FROM hosts WHERE scan_id=? AND ip_address=?",
                (scan_id, ip)
            ).fetchone()[0]

            # Replace ports
            c.execute("DELETE FROM ports WHERE host_id=?", (host_id,))
            for p in ports:
                c.execute("""
                    INSERT OR IGNORE INTO ports
                      (host_id,port_number,state,service,product,version,banner,response_ms)
                    VALUES(?,?,?,?,?,?,?,?)
                """, (host_id, p["port"], p.get("state","open"),
                      p.get("service","unknown"), p.get("product"),
                      p.get("version"), p.get("banner"), p.get("response_ms",0.0)))
            return host_id

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        conn = self._connect()
        try:
            def q(sql): return conn.execute(sql).fetchone()[0] or 0
            return {
                "total_scans":  q("SELECT COUNT(*) FROM scans"),
                "total_hosts":  q("SELECT COUNT(*) FROM hosts"),
                "alive_hosts":  q("SELECT COUNT(*) FROM hosts WHERE is_alive=1"),
                "total_ports":  q("SELECT COUNT(*) FROM ports"),
                "open_ports":   q("SELECT COUNT(*) FROM ports WHERE state='open'"),
                "unique_ips":   q("SELECT COUNT(DISTINCT ip_address) FROM hosts"),
            }
        finally:
            conn.close()

    def clear_all(self) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM ports")
            c.execute("DELETE FROM hosts")
            c.execute("DELETE FROM scans")

    # ── Serialization helpers ─────────────────────────────────────────────────

    def _build_scan_dict(self, conn: sqlite3.Connection, scan: dict) -> dict:
        hosts = []
        for h in conn.execute("SELECT * FROM hosts WHERE scan_id=?", (scan["id"],)).fetchall():
            h = dict(h)
            port_rows = conn.execute(
                "SELECT * FROM ports WHERE host_id=? ORDER BY port_number", (h["id"],)
            ).fetchall()
            h["ports"] = [dict(p) for p in port_rows]
            h["is_alive"] = bool(h["is_alive"])
            hosts.append(h)
        d = self._scan_row_to_dict(scan)
        d["hosts"] = hosts
        return d

    @staticmethod
    def _scan_row_to_dict(r: dict) -> dict:
        started  = r.get("started_at")
        finished = r.get("finished_at")
        dur = None
        if started and finished:
            try:
                fmt = "%Y-%m-%dT%H:%M:%SZ"
                dur = (datetime.strptime(finished, fmt) - datetime.strptime(started, fmt)).total_seconds()
            except Exception:
                pass
        return {**r, "duration_s": dur, "hosts": []}
