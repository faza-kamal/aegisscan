"""
tests/test_database.py
Unit tests for database models and repository using in-memory SQLite.
Run: pytest tests/test_database.py -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from database.repository import Repository


@pytest.fixture
def repo(tmp_path):
    """Fresh in-memory repository for each test."""
    return Repository(db_path=str(tmp_path / "test.db"))


class TestScanCRUD:

    def test_create_scan(self, repo):
        sid = repo.create_scan("tcp_connect", "192.168.1.1", "top100", "normal")
        assert isinstance(sid, int)
        assert sid > 0

    def test_get_scan_exists(self, repo):
        sid = repo.create_scan("tcp_connect", "10.0.0.1")
        data = repo.get_scan(sid)
        assert data is not None
        assert data["target"] == "10.0.0.1"
        assert data["status"] == "running"

    def test_get_scan_not_found(self, repo):
        assert repo.get_scan(99999) is None

    def test_finish_scan(self, repo):
        sid = repo.create_scan("subnet", "192.168.0.0/24")
        repo.finish_scan(sid, hosts_found=5, ports_open=12)
        data = repo.get_scan(sid)
        assert data["status"] == "completed"
        assert data["hosts_found"] == 5
        assert data["ports_open"] == 12
        assert data["finished_at"] is not None
        assert data["duration_s"] is not None
        assert data["duration_s"] >= 0

    def test_list_scans_empty(self, repo):
        assert repo.list_scans() == []

    def test_list_scans_multiple(self, repo):
        for i in range(5):
            repo.create_scan("tcp_connect", f"192.168.1.{i}")
        scans = repo.list_scans(limit=10)
        assert len(scans) == 5

    def test_list_scans_limit(self, repo):
        for i in range(10):
            repo.create_scan("tcp_connect", f"10.0.0.{i}")
        scans = repo.list_scans(limit=3)
        assert len(scans) == 3

    def test_delete_scan(self, repo):
        sid = repo.create_scan("tcp_connect", "1.2.3.4")
        ok = repo.delete_scan(sid)
        assert ok is True
        assert repo.get_scan(sid) is None

    def test_delete_nonexistent(self, repo):
        assert repo.delete_scan(99999) is False


class TestHostAndPorts:

    def test_save_host_with_ports(self, repo):
        sid = repo.create_scan("tcp_connect", "192.168.1.1")
        ports = [
            {"port": 80,  "state": "open", "service": "http", "banner": "nginx/1.24", "response_ms": 12.5},
            {"port": 443, "state": "open", "service": "https", "banner": None, "response_ms": 8.3},
        ]
        hid = repo.save_host(sid, "192.168.1.1", "myhost.local", True, 450.0, ports)
        assert isinstance(hid, int)
        assert hid > 0

    def test_host_ports_retrievable(self, repo):
        sid = repo.create_scan("tcp_connect", "10.0.0.5")
        ports = [
            {"port": 22, "state": "open", "service": "ssh", "banner": "OpenSSH 8.9", "response_ms": 5.0},
        ]
        repo.save_host(sid, "10.0.0.5", None, True, 200.0, ports)
        repo.finish_scan(sid, 1, 1)
        data = repo.get_scan(sid)
        assert len(data["hosts"]) == 1
        host = data["hosts"][0]
        assert host["ip"] == "10.0.0.5"
        assert len(host["ports"]) == 1
        assert host["ports"][0]["port"] == 22

    def test_save_dead_host(self, repo):
        sid = repo.create_scan("tcp_connect", "192.168.1.99")
        hid = repo.save_host(sid, "192.168.1.99", None, False, 1000.0, [])
        assert hid > 0

    def test_idempotent_host_save(self, repo):
        """Saving same host twice should not create duplicate."""
        sid = repo.create_scan("tcp_connect", "1.1.1.1")
        ports = [{"port": 80, "state": "open", "service": "http", "banner": None, "response_ms": 10}]
        repo.save_host(sid, "1.1.1.1", None, True, 100.0, ports)
        repo.save_host(sid, "1.1.1.1", None, True, 100.0, ports)
        data = repo.get_scan(sid)
        # Should still have only 1 host
        assert len(data["hosts"]) == 1


class TestStatistics:

    def test_stats_empty(self, repo):
        stats = repo.stats()
        assert stats["total_scans"] == 0
        assert stats["total_hosts"] == 0
        assert stats["open_ports"] == 0

    def test_stats_after_scan(self, repo):
        sid = repo.create_scan("tcp_connect", "192.168.1.1")
        repo.save_host(sid, "192.168.1.1", None, True, 100.0, [
            {"port": 80, "state": "open", "service": "http", "banner": None, "response_ms": 5},
            {"port": 443, "state": "open", "service": "https", "banner": None, "response_ms": 5},
        ])
        repo.finish_scan(sid, 1, 2)
        stats = repo.stats()
        assert stats["total_scans"] == 1
        assert stats["open_ports"] == 2
        assert stats["unique_ips"] == 1

    def test_clear_all(self, repo):
        sid = repo.create_scan("tcp_connect", "1.2.3.4")
        repo.save_host(sid, "1.2.3.4", None, True, 100.0, [
            {"port": 80, "state": "open", "service": "http", "banner": None, "response_ms": 1}
        ])
        repo.clear_all()
        stats = repo.stats()
        assert stats["total_scans"] == 0
        assert stats["total_hosts"] == 0


class TestSchemaIndexes:
    """Verify critical indexes exist (SQLite introspection)."""

    def test_scan_target_index_exists(self, repo):
        import sqlite3
        conn = sqlite3.connect(repo._engine.url.database)
        indexes = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='scans'"
        ).fetchall()
        idx_names = [r[0] for r in indexes]
        conn.close()
        # At least one index on scans table
        assert len(idx_names) >= 1

    def test_host_scan_id_index_exists(self, repo):
        import sqlite3
        conn = sqlite3.connect(repo._engine.url.database)
        indexes = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='hosts'"
        ).fetchall()
        conn.close()
        assert len(indexes) >= 1

    def test_port_host_id_index_exists(self, repo):
        import sqlite3
        conn = sqlite3.connect(repo._engine.url.database)
        indexes = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='ports'"
        ).fetchall()
        conn.close()
        assert len(indexes) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
