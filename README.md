<<<<<<< HEAD
# aegisscan
=======
# 🛡️ AegisScan

**Professional async network reconnaissance scanner — Python 3.8+, zero heavy dependencies**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-58%20passing-brightgreen.svg)](#testing)
[![Architecture](https://img.shields.io/badge/arch-clean%20layered-success.svg)](#architecture)

---

## Features

| Feature | Status | Notes |
|---|---|---|
| TCP Connect Scan | ✅ | Async, no root needed |
| Subnet Sweep `/24` | ✅ | Concurrent hosts + ports |
| Service Detection | ✅ | Regex from nmap-service-probes |
| Banner Grabbing | ✅ | Protocol-aware probes |
| OS Detection | ✅ | TTL + banner heuristics |
| Adaptive RTT Timing | ✅ | RFC 6298 SRTT/RTTVAR model |
| Timing Profiles T0–T5 | ✅ | Mirrors nmap -T0 to -T5 |
| SQLite Database | ✅ | Indexed, WAL, zero deps |
| Web Dashboard | ✅ | Flask, auth-ready |
| PDF Reports | ✅ | ReportLab (optional) |
| HTML Reports | ✅ | Zero deps |
| JSON Export | ✅ | Zero deps |
| SYN Scan (stealth) | 🔜 | v4 — requires scapy + root |
| OS Fingerprint (deep) | 🔜 | v4 — requires raw packets |

---

## Quick Start

```bash
git clone https://github.com/faza-kamal/aegisscan.git
cd aegisscan

# Zero-dependency run (core features)
python3 main.py --scan 192.168.1.1

# With optional packages (PDF reports, faster async)
pip install -r requirements.txt
python3 main.py --scan 192.168.1.0/24 --timing aggressive
```

---

## Installation

### Required
- Python 3.8+
- No external packages for core scanning

### Optional (for full features)
```bash
pip install -r requirements.txt
```

| Package | Why |
|---|---|
| `flask` | Web dashboard |
| `reportlab` | PDF reports |
| `pyyaml` | config.yaml support |
| `uvloop` | 2-4× faster async (Linux/Mac) |
| `colorlog` | Colored console logs |

---

## Usage

```
usage: main.py [-h] [--scan TARGET] [--ports SPEC] [--timing PROFILE]
               [--banner TARGET] [--port PORT] [--benchmark TARGET]
               [--history [N]] [--clear-db] [--report SCAN_ID]
               [--format {json,html,pdf}] [--dashboard]
               [--host HOST] [--dash-port PORT] [--enable-auth]
               [--config FILE] [--quiet] [--version]
```

### Scan Examples

```bash
# Single host — top 100 ports
python3 main.py --scan 192.168.1.1

# Custom ports
python3 main.py --scan 192.168.1.1 --ports 22,80,443,8080-8090

# Port range
python3 main.py --scan 192.168.1.1 --ports 1-1000

# Subnet sweep
python3 main.py --scan 192.168.1.0/24 --ports top100 --timing aggressive

# Banner grab
python3 main.py --banner 192.168.1.1 --port 80

# All 65535 ports (slow — use insane timing)
python3 main.py --scan 192.168.1.1 --ports - --timing insane
```

### Port Specification Formats

| Format | Example | Result |
|---|---|---|
| Single | `80` | Port 80 only |
| Multiple | `80,443,8080` | Those three ports |
| Range | `1-1000` | Ports 1 through 1000 |
| Mixed | `22,80-85,443` | Combined |
| Top-N | `top100` | Top 100 by nmap frequency |
| All | `-` | All 65535 ports |

### Timing Profiles

| Profile | Equiv | Concurrent H | Concurrent P | Timeout |
|---|---|---|---|---|
| `paranoid` | T0 | 1 | 1 | 5000ms |
| `sneaky` | T1 | 1 | 1 | 3000ms |
| `polite` | T2 | 5 | 10 | 1500ms |
| `normal` | T3 | 30 | 50 | 1000ms |
| `aggressive` | T4 | 100 | 200 | 500ms |
| `insane` | T5 | 300 | 500 | 250ms |

### Database & Reports

```bash
# View scan history
python3 main.py --history 20

# Generate JSON report
python3 main.py --report 1 --format json

# Generate HTML report
python3 main.py --report 1 --format html

# Generate PDF report (requires reportlab)
python3 main.py --report 1 --format pdf

# Clear database
python3 main.py --clear-db
```

### Web Dashboard

```bash
# Local only (safe default)
python3 main.py --dashboard

# Network-exposed with auth (production)
python3 main.py --dashboard --host 0.0.0.0 --dash-port 5000 --enable-auth
```

Open: http://127.0.0.1:5000

### Benchmark

```bash
python3 main.py --benchmark 192.168.1.1 --ports 1-1000 --timing aggressive
```

---

## Architecture

```
aegisscan/
├── main.py                    # CLI entry point
├── config.yaml                # Configuration
│
├── core/                      # ← Pure scanning logic (no DB/web imports)
│   ├── scanner_engine.py      # Async TCP connect engine
│   ├── port_parser.py         # Robust port spec parser
│   ├── timing.py              # Adaptive RTT (RFC 6298)
│   ├── os_detect.py           # OS fingerprinting (TTL + banner)
│   └── service_fingerprint.py # Service version detection
│
├── database/                  # ← Data persistence (no core/web imports)
│   ├── models.py              # SQLite schema (pure stdlib)
│   ├── repository.py          # Thread-safe data access layer
│   └── migrations.py          # Schema version management
│
├── reporting/                 # ← Report generation
│   └── report_generator.py    # PDF / HTML / JSON
│
├── dashboard/                 # ← Web interface (reads repo only)
│   ├── app.py                 # Flask, auth-hardened
│   └── templates/
│       └── dashboard.html     # Dark theme UI
│
├── utils/
│   ├── logger.py              # Rotating JSON + colored console
│   └── constants.py           # Port states, timing profiles
│
├── data/
│   └── nmap-services          # Real nmap-services DB (27K entries)
│
└── tests/                     # 58 tests, 0 failures
    ├── test_port_parser.py
    ├── test_scanner.py
    ├── test_database.py
    └── test_layering.py       # Enforces import boundaries
```

### Layering Rules (enforced by test_layering.py)

```
core       → may NOT import: database, dashboard, reporting
database   → may NOT import: core, dashboard, reporting
dashboard  → may NOT import: core directly
reporting  → may NOT import: core, dashboard
```

---

## Technical Details

### Scanner Engine

- `asyncio.open_connection()` — non-blocking, no raw sockets
- Per-host `asyncio.Semaphore` + per-port `asyncio.Semaphore`
- **Adaptive RTT**: RFC 6298 SRTT/RTTVAR algorithm (same as TCP stack)
  ```
  SRTT   = (1-α)·SRTT   + α·RTT       (α = 0.125)
  RTTVAR = (1-β)·RTTVAR + β·|RTT-SRTT| (β = 0.25)
  RTO    = SRTT + 4·RTTVAR
  RTO    ∈ [min_rto, max_rto]
  ```
- Granular exception handling: `TimeoutError`, `ConnectionRefusedError`, `OSError` — no bare `except`

### Service Detection

Matches banners against patterns derived from nmap-service-probes:
- HTTP/HTTPS: nginx, Apache, IIS, lighttpd
- SSH: OpenSSH, Dropbear, Cisco SSH
- FTP: vsftpd, ProFTPD, FileZilla, IIS FTP
- SMTP: Postfix, Sendmail, Exim, Exchange
- Databases: MySQL, PostgreSQL, Redis, MongoDB

### OS Detection

Heuristic (connect-scan, no raw packets):
1. Banner regex matching (highest confidence, 0.75–0.95)
2. Service fingerprint hints (RDP=Windows, SMB=Windows)
3. TTL-based inference (TTL≈64→Linux, TTL≈128→Windows)

### Database

- Pure stdlib `sqlite3` — zero external deps
- WAL journal mode for concurrent reads
- Proper indexes on all foreign keys and filter columns
- Upsert semantics (idempotent saves)
- Migration system with version tracking

---

## Testing

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run specific suite
python3 -m pytest tests/test_port_parser.py -v
python3 -m pytest tests/test_database.py -v
python3 -m pytest tests/test_layering.py -v

# Run without pytest (stdlib only)
python3 tests/run_all.py
```

**Test coverage:**
- Port parser: 17 cases (valid formats, edge cases, injection)
- Timing: 7 cases (RTT tracking, profile shortcuts, clamping)
- OS detection: 9 cases (banner, TTL, port hints)
- Service fingerprint: 6 cases (version extraction, fallbacks)
- Database: 16 cases (CRUD, indexes, stats, clear)
- Layering: 3 packages validated

---

## Security Notes

⚠️ **Use only on networks you own or have explicit permission to scan.**

### Dashboard Security

- `debug=False` hard-coded (cannot be overridden)
- Basic auth via `--enable-auth` (required for `--host 0.0.0.0`)
- Stacktraces never sent to client
- Secret key auto-rotates if placeholder is unchanged

### Scanner

- Scan type: **TCP Connect** (not SYN)
  - Target sees full TCP handshake — not stealthy
  - No root required
  - Logged by target firewalls
- Rate limiting via semaphores prevents network flooding
- All input validated before use

---

## Roadmap

### v3.x (current)
- [x] Async TCP connect engine
- [x] Adaptive RTT timing
- [x] Service fingerprinting
- [x] OS detection (heuristic)
- [x] SQLite with proper schema
- [x] Web dashboard with auth
- [x] PDF/HTML/JSON reports
- [x] 58 unit tests

### v4.0 (planned)
- [ ] SYN scan (scapy, requires root)
- [ ] ICMP host discovery
- [ ] UDP scan
- [ ] IPv6 support
- [ ] Plugin/script engine (NSE-like)
- [ ] CVE lookup integration
- [ ] Scheduled scans
- [ ] Docker image

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Write tests for your changes
4. Ensure 0 layering violations: `python3 -m pytest tests/test_layering.py`
5. Submit a pull request

---

## License

MIT License — see [LICENSE](LICENSE).

---

## Acknowledgments

- [Nmap Project](https://nmap.org) — architecture reference, nmap-services database, service probe patterns
- RFC 6298 — TCP RTT/RTO algorithm
- Python asyncio team

---

*AegisScan v3.0 · For authorized security testing only*
>>>>>>> 4ff4be5 (Initial commit: AegisScan tools and documentation)
