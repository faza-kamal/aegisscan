#!/usr/bin/env python3
"""
tests/run_all.py
Run all AegisScan tests using stdlib only — no pytest needed.

Usage:
    python3 tests/run_all.py
    python3 tests/run_all.py -v        # verbose
    python3 tests/run_all.py --fast    # skip network tests
"""

import sys
import os
import traceback
import tempfile
import ast
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

PASS = 0
FAIL = 0
SKIP = 0
_verbose = "-v" in sys.argv
_fast    = "--fast" in sys.argv

# ── Helpers ────────────────────────────────────────────────────────────────────

def test(name: str, fn, skip: bool = False):
    global PASS, FAIL, SKIP
    if skip:
        print(f"  ~ {name} [SKIPPED]"); SKIP += 1; return
    try:
        fn()
        if _verbose: print(f"  ✓ {name}")
        PASS += 1
    except Exception as e:
        print(f"  ✗ {name}")
        if _verbose: traceback.print_exc()
        else: print(f"    → {e}")
        FAIL += 1

def section(title: str):
    print(f"\n── {title} {'─'*(50 - len(title))}")

def ae(a, b): assert a == b, f"{a!r} != {b!r}"
def at(v):    assert v, f"Expected True, got {v!r}"
def ar(exc_type, fn):
    try:
        fn()
        raise AssertionError(f"Expected {exc_type.__name__} not raised")
    except exc_type:
        pass

# ═══════════════════════════════════════════════════════════════════════════════
# 1. PORT PARSER
# ═══════════════════════════════════════════════════════════════════════════════
section("Port Parser")
from core.port_parser import PortParser, PortParseError
p = PortParser()

test("single port 80",              lambda: ae(p.parse("80"), [80]))
test("single port 1 (min)",         lambda: ae(p.parse("1"), [1]))
test("single port 65535 (max)",     lambda: ae(p.parse("65535"), [65535]))
test("two ports",                   lambda: ae(p.parse("80,443"), [80, 443]))
test("sorted output",               lambda: ae(p.parse("443,22,80"), [22, 80, 443]))
test("deduplication",               lambda: ae(p.parse("80,80,80"), [80]))
test("whitespace stripped",         lambda: ae(p.parse(" 80 , 443 "), [80, 443]))
test("trailing comma ignored",      lambda: ae(p.parse("80,443,"), [80, 443]))
test("range 80-82",                 lambda: ae(p.parse("80-82"), [80, 81, 82]))
test("range single 80-80",          lambda: ae(p.parse("80-80"), [80]))
test("mixed format",                lambda: ae(p.parse("22,80-82,443"), [22, 80, 81, 82, 443]))
test("overlap deduped",             lambda: ae(p.parse("80-82,81"), [80, 81, 82]))
test("all ports '-'",               lambda: at(p.parse("-")[0] == 1 and p.parse("-")[-1] == 65535))
test("top10 returns 10",            lambda: at(len(p.parse("top10")) == 10))
test("top100 returns 100",          lambda: at(len(p.parse("top100")) == 100))
test("top10 sorted",                lambda: at(p.parse("top10") == sorted(p.parse("top10"))))
test("port 0 rejected",             lambda: ar(PortParseError, lambda: p.parse("0")))
test("port 65536 rejected",         lambda: ar(PortParseError, lambda: p.parse("65536")))
test("negative rejected",           lambda: ar(PortParseError, lambda: p.parse("-80")))
test("alpha rejected",              lambda: ar(PortParseError, lambda: p.parse("http")))
test("empty string rejected",       lambda: ar(PortParseError, lambda: p.parse("")))
test("whitespace-only rejected",    lambda: ar(PortParseError, lambda: p.parse("   ")))
test("None rejected",               lambda: ar(PortParseError, lambda: p.parse(None)))
test("list rejected",               lambda: ar(PortParseError, lambda: p.parse([80, 443])))
test("reverse range rejected",      lambda: ar(PortParseError, lambda: p.parse("100-50")))
test("sql injection rejected",      lambda: ar(PortParseError, lambda: p.parse("80; DROP TABLE scans;--")))
test("shell injection rejected",    lambda: ar(PortParseError, lambda: p.parse("80 && rm -rf /")))
test("validate ok",                 lambda: at(p.validate("80,443")[0] is True))
test("validate returns msg",        lambda: at(p.validate("abc")[0] is False and p.validate("abc")[1] != ""))

# ═══════════════════════════════════════════════════════════════════════════════
# 2. TIMING
# ═══════════════════════════════════════════════════════════════════════════════
section("Timing & RTT Tracking")
from core.timing import RTOTracker, RateMeter, get_timing

test("all 6 profiles load",         lambda: at(all(get_timing(n) for n in
                                        ["paranoid","sneaky","polite","normal","aggressive","insane"])))
test("T0 shorthand",                lambda: at(get_timing("t0").name == "T0-Paranoid"))
test("T3 shorthand",                lambda: at(get_timing("t3").name == "T3-Normal"))
test("T4 shorthand",                lambda: at(get_timing("t4").name == "T4-Aggressive"))
test("T5 shorthand",                lambda: at(get_timing("t5").name == "T5-Insane"))
test("invalid profile raises",      lambda: ar(ValueError, lambda: get_timing("bogus")))
test("paranoid < insane timeout",   lambda: at(get_timing("insane").connection_timeout_ms < get_timing("paranoid").connection_timeout_ms))
test("insane > paranoid concurrency",lambda: at(get_timing("insane").max_concurrent_ports > get_timing("paranoid").max_concurrent_ports))

tp = get_timing("normal")
rto = RTOTracker(profile=tp)
test("initial RTO = initial_rtt",   lambda: at(rto.rto_ms == tp.initial_rtt_timeout_ms))
test("samples starts at 0",         lambda: at(rto.samples == 0))
rto.update(10.0); rto.update(20.0); rto.update(15.0)
test("samples tracked",             lambda: at(rto.samples == 3))
test("srtt adapts",                 lambda: at(rto.srtt_ms is not None and 10 <= rto.srtt_ms <= 20))
test("rto clamped to max",          lambda: (r := RTOTracker(profile=tp), r.update(999999), at(r.rto_ms <= tp.max_rtt_timeout_ms))[2])
test("rto clamped to min",          lambda: (r := RTOTracker(profile=tp), r.update(0.001), at(r.rto_ms >= tp.min_rtt_timeout_ms))[2])
test("rto_s = rto_ms / 1000",       lambda: at(abs(rto.rto_s - rto.rto_ms / 1000.0) < 0.001))

rm = RateMeter(window_s=2.0)
rm.update(5.0); rm.update(3.0)
test("rate meter total",            lambda: at(rm.total == 8.0))
test("rate meter overall_rate > 0", lambda: at(rm.overall_rate() > 0))

# ═══════════════════════════════════════════════════════════════════════════════
# 3. OS DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
section("OS Detection")
from core.os_detect import OSDetector, OSGuess
d = OSDetector()

test("nginx Ubuntu → Linux",        lambda: at(d.detect({80: "HTTP/1.1 200\r\nServer: nginx/1.18.0 (Ubuntu)\r\n"}, [80]).os_family == "Linux"))
test("nginx Ubuntu confidence",     lambda: at(d.detect({80: "HTTP/1.1 200\r\nServer: nginx/1.18.0 (Ubuntu)\r\n"}, [80]).confidence >= 0.8))
test("IIS → Windows",               lambda: at(d.detect({80: "HTTP/1.1 200\r\nServer: Microsoft-IIS/10.0\r\n"}, [80]).os_family == "Windows"))
test("IIS confidence high",         lambda: at(d.detect({80: "HTTP/1.1 200\r\nServer: Microsoft-IIS/10.0\r\n"}, [80]).confidence >= 0.85))
test("RDP port → Windows",          lambda: at(d.detect({}, [3389]).os_family == "Windows"))
test("RDP confidence ≥ 0.9",        lambda: at(d.detect({}, [3389]).confidence >= 0.9))
test("SMB port → Windows",          lambda: at(d.detect({}, [445]).os_family == "Windows"))
test("SSH banner → Linux",          lambda: at(d.detect({22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}, [22]).os_family == "Linux"))
test("no data → None",              lambda: at(d.detect({}, []) is None))
test("TTL 60 → Linux/BSD",          lambda: at(d.detect_from_ttl(60).os_family in ("Linux","FreeBSD")))
test("TTL 64 → Linux/BSD",          lambda: at(d.detect_from_ttl(64).os_family in ("Linux","FreeBSD")))
test("TTL 128 → Windows",           lambda: at(d.detect_from_ttl(128).os_family == "Windows"))
test("TTL 255 → Cisco",             lambda: at(d.detect_from_ttl(255).os_family == "Cisco"))
test("format guess OK",             lambda: at("Ubuntu" in d.format_guess(OSGuess("Linux", "Ubuntu Linux", 0.85, "banner_regex"))))
test("format None → Unknown",       lambda: at(d.format_guess(None) == "Unknown"))
test("highest confidence wins",     lambda: at(d.detect({80: "HTTP/1.1 200\r\nServer: Microsoft-IIS/10.0\r\n"}, [22]).os_family == "Windows"))

# ═══════════════════════════════════════════════════════════════════════════════
# 4. SERVICE FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════════
section("Service Fingerprinting")
from core.service_fingerprint import ServiceFingerprinter, fingerprint, ServiceInfo
fp = ServiceFingerprinter()

test("nginx product detected",      lambda: at("nginx" in str(fp.identify(80, "HTTP/1.1 200\r\nServer: nginx/1.24.0\r\nDate:", "http")).lower()))
test("nginx service = http",        lambda: at(fp.identify(80, "HTTP/1.1 200\r\nServer: nginx/1.24.0\r\n", "http").name == "http"))
test("Apache detected",             lambda: at("Apache" in str(fp.identify(80, "HTTP/1.1 200\r\nServer: Apache/2.4.54\r\n", "http"))))
test("IIS detected",                lambda: at("IIS" in str(fp.identify(80, "HTTP/1.1 200\r\nServer: Microsoft-IIS/10.0\r\n", "http")) or "Microsoft" in str(fp.identify(80, "HTTP/1.1 200\r\nServer: Microsoft-IIS/10.0\r\n", "http"))))
test("OpenSSH detected",            lambda: at("OpenSSH" in str(fp.identify(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu", "ssh"))))
test("SSH service name",            lambda: at(fp.identify(22, "SSH-2.0-OpenSSH_8.9p1", "ssh").name == "ssh"))
test("vsftpd detected",             lambda: at("vsftpd" in str(fp.identify(21, "220 (vsFTPd 3.0.5)", "ftp")).lower()))
test("FTP service name",            lambda: at(fp.identify(21, "220 (vsFTPd 3.0.5)", "ftp").name == "ftp"))
test("no banner fallback",          lambda: at(fp.identify(80, None, "http-proxy").name == "http-proxy"))
test("empty banner fallback",       lambda: at(fp.identify(443, "", "https").name == "https"))
test("unknown service fallback",    lambda: at(fp.identify(12345, None, "unknown").name == "unknown"))
test("module function works",       lambda: at(fingerprint(22, "SSH-2.0-OpenSSH_9.0", "ssh") is not None))
test("returns ServiceInfo",         lambda: at(isinstance(fp.identify(80, None, "http"), ServiceInfo)))
test("str representation",          lambda: at(isinstance(str(fp.identify(80, "HTTP/1.1 200\r\nServer: nginx/1.24.0\r\n", "http")), str)))

# ═══════════════════════════════════════════════════════════════════════════════
# 5. DATABASE
# ═══════════════════════════════════════════════════════════════════════════════
section("Database Repository")
from database.repository import Repository
_tmp = tempfile.mkdtemp()
repo = Repository(db_path=f"{_tmp}/test.db")

test("create_scan returns id",      lambda: at(repo.create_scan("tcp_connect", "192.168.1.1") > 0))
sid = repo.create_scan("tcp_connect", "10.0.0.1", "top100", "normal")
test("get_scan by id",              lambda: at(repo.get_scan(sid)["target"] == "10.0.0.1"))
test("get_scan status=running",     lambda: at(repo.get_scan(sid)["status"] == "running"))
test("get_scan scan_type",          lambda: at(repo.get_scan(sid)["scan_type"] == "tcp_connect"))
test("get_scan missing = None",     lambda: at(repo.get_scan(99999) is None))
test("list_scans not empty",        lambda: at(len(repo.list_scans()) >= 1))
test("list_scans limit",            lambda: (
    [repo.create_scan("tcp_connect", f"10.0.{i}.1") for i in range(5)],
    at(len(repo.list_scans(limit=3)) == 3))[1])

hid = repo.save_host(sid, "10.0.0.1", "host.local", True, 150.5,
    [{"port": 80,  "state": "open", "service": "http",  "banner": "nginx/1.24", "response_ms": 5.2},
     {"port": 443, "state": "open", "service": "https", "banner": None,          "response_ms": 8.1}],
    os_guess="Linux")
test("save_host returns id",        lambda: at(isinstance(hid, int) and hid > 0))
test("host in scan",                lambda: at(len(repo.get_scan(sid)["hosts"]) == 1))
test("two ports saved",             lambda: at(len(repo.get_scan(sid)["hosts"][0]["ports"]) == 2))
test("os_guess persisted",          lambda: at(repo.get_scan(sid)["hosts"][0]["os_guess"] == "Linux"))
test("hostname persisted",          lambda: at(repo.get_scan(sid)["hosts"][0]["hostname"] == "host.local"))
test("port numbers correct",        lambda: at({p["port_number"] for p in repo.get_scan(sid)["hosts"][0]["ports"]} == {80, 443}))
test("banner persisted",            lambda: at(any(p.get("banner") == "nginx/1.24" for p in repo.get_scan(sid)["hosts"][0]["ports"])))

# idempotent upsert
repo.save_host(sid, "10.0.0.1", "host.local", True, 150.5,
    [{"port": 80, "state": "open", "service": "http", "banner": "nginx/1.24", "response_ms": 5.2}])
test("upsert no duplicate host",    lambda: at(len(repo.get_scan(sid)["hosts"]) == 1))

repo.finish_scan(sid, 1, 2)
test("finish_scan status",          lambda: at(repo.get_scan(sid)["status"] == "completed"))
test("hosts_found saved",           lambda: at(repo.get_scan(sid)["hosts_found"] == 1))
test("ports_open saved",            lambda: at(repo.get_scan(sid)["ports_open"] == 2))
test("finished_at set",             lambda: at(repo.get_scan(sid)["finished_at"] is not None))
test("duration_s calculated",       lambda: at(repo.get_scan(sid)["duration_s"] is not None))

test("stats total_scans",           lambda: at(repo.stats()["total_scans"] >= 1))
test("stats alive_hosts",           lambda: at(repo.stats()["alive_hosts"] >= 1))
test("stats open_ports",            lambda: at(repo.stats()["open_ports"] >= 1))
test("stats unique_ips",            lambda: at(repo.stats()["unique_ips"] >= 1))

test("delete_scan True",            lambda: at(repo.delete_scan(sid) is True))
test("delete nonexistent False",    lambda: at(repo.delete_scan(99999) is False))
test("deleted scan = None",         lambda: at(repo.get_scan(sid) is None))
test("clear_all resets stats",      lambda: (repo.clear_all(), at(repo.stats()["total_scans"] == 0))[1])

# ── Schema indexes
import sqlite3 as _sq
def _indexes(table):
    c = _sq.connect(f"{_tmp}/test.db")
    r = c.execute(f"SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='{table}'").fetchall()
    c.close(); return [x[0] for x in r]

test("scans has indexes",           lambda: at(len(_indexes("scans")) >= 2))
test("hosts has indexes",           lambda: at(len(_indexes("hosts")) >= 2))
test("ports has indexes",           lambda: at(len(_indexes("ports")) >= 2))

# ═══════════════════════════════════════════════════════════════════════════════
# 6. LAYERING (import boundary enforcement)
# ═══════════════════════════════════════════════════════════════════════════════
section("Layering Enforcement")
ROOT = Path(__file__).parent.parent
FORBIDDEN = {
    "core":      {"database", "dashboard", "reporting"},
    "database":  {"core", "dashboard", "reporting"},
    "dashboard": {"core"},
    "reporting": {"core", "dashboard"},
}

def _get_imports(fp: Path) -> list:
    try:
        tree = ast.parse(fp.read_text())
        return (
            [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module] +
            [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        )
    except Exception:
        return []

for pkg, forbidden in FORBIDDEN.items():
    pkg_dir = ROOT / pkg
    if not pkg_dir.exists():
        continue
    violations = []
    for pyfile in pkg_dir.rglob("*.py"):
        for imp in _get_imports(pyfile):
            if imp.split(".")[0] in forbidden:
                violations.append(f"{pyfile.name} imports '{imp}'")
    test(f"{pkg}/ has 0 layering violations",
         lambda v=violations: at(len(v) == 0))
    if violations:
        for v in violations:
            print(f"    VIOLATION: {v}")

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
total = PASS + FAIL + SKIP
print(f"\n{'═' * 55}")
print(f"  {'✓' if FAIL == 0 else '✗'}  {PASS} passed  ·  {FAIL} failed  ·  {SKIP} skipped  ·  {total} total")
print(f"{'═' * 55}")
if FAIL > 0:
    sys.exit(1)
