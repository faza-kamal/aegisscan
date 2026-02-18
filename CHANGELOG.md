# Changelog

All notable changes are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [4.1.0] — 2025-02-18

### Bug Fixes
- **`core/scanner_engine.py` — `_resolve()` logic error & dead code removed**
  - Fungsi `_resolve()` sebelumnya rusak total: tubuh fungsi terpotong di file
    (hanya ada `ip, 0)),` dan sisa fragmen — method definition hilang)
  - Diperbaiki menjadi implementasi bersih: satu call `getnameinfo()` tanpa
    `getaddrinfo()` redundant yang tidak pernah dipakai
  - Hemat ~2 detik timeout per host yang di-resolve

- **`reporting/report_generator.py` — XSS via banner/hostname injection**
  - Sebelumnya hanya `.replace("<", "&lt;")` parsial, field lain (service, state,
    hostname, os_guess) tidak di-escape sama sekali
  - Diperbaiki dengan `html.escape()` konsisten untuk semua nilai dari scan data
  - Attack vector: banner `<script>alert(1)</script>` dari target server bisa
    execute JS saat report HTML dibuka di browser

- **`core/os_detect.py` — `detect_from_ttl()` dead code didokumentasikan**
  - Fungsi ini tidak pernah bisa dipanggil dari connect scan (TTL tidak accessible
    via `asyncio.open_connection()`) tapi tidak ada keterangan apapun
  - Ditambah docstring eksplisit: "ONLY usable with raw socket / scapy (v4 SYN scan)"
  - Tidak dihapus karena akan digunakan di v4.0 SYN scan feature

### Added
- **`core/web_recon.py` — Web & Domain Reconnaissance Module** (NEW)
  - `DNSResolver`: async A, AAAA, PTR resolution; optional MX/NS via dnspython
  - `HTTPGrabber`: async HTTP/HTTPS header grab, deteksi tech stack (nginx, Apache,
    IIS, PHP, ASP.NET, Cloudflare, Vercel, AWS CloudFront, WordPress, dll)
  - `PortAnalyzer`: analisis port dominan + distribusi OS dari hasil scan history
  - `WebRecon`: orkestrator + CLI pretty-printer
  - Subdomain common check (passive, 30 subdomain)
  - Zero external deps untuk fitur inti

- **`main.py` — dua CLI flag baru**
  ```
  --recon <domain/ip>       DNS info + HTTP headers + tech stack detection
  --subdomains              Tambahan: cek common subdomains (pakai dengan --recon)
  --analyze <scan_id>       Port dominance + OS distribution dari scan history
  ```

- **`core/__init__.py`** — ekspor `WebRecon`, `PortAnalyzer`, `DNSResolver`, `HTTPGrabber`

### Examples
```bash
# Recon domain
python3 main.py --recon github.com

# Recon + cek subdomains
python3 main.py --recon target.com --subdomains

# Analisis port dominan dari scan sebelumnya
python3 main.py --analyze 3

# Recon IP langsung
python3 main.py --recon 192.168.1.1
```

---



### Added
- **Multi-strategy alive check** — concurrent TCP probes across 12 ports;
  `ConnectionRefusedError` (RST) is now treated as proof-of-life, eliminating
  false-negatives on hosts that close all 6 previous well-known ports
- **bcrypt password hashing** — `dashboard/app.py` now ships `hash_password()`
  and `verify_password()` helpers using `passlib[bcrypt]`; falls back to
  salted HMAC-SHA256 when passlib is not installed; plaintext passwords
  trigger a startup warning (`install passlib[bcrypt] for production`)
- **`scan_delay_ms` implemented** — `_scan_port()` now honours the
  `scan_delay_ms` field from `TimingProfile`; T0/T1 profiles (paranoid/sneaky)
  now correctly throttle inter-probe delays as designed
- **Modern dashboard UI** — complete redesign of `dashboard.html` + `style.css`:
  industrial cyber aesthetic, Syne + Space Mono typography, animated stat cards
  with RTT counters, slide-in detail drawer, filter tabs, live search, badge
  system for scan types & statuses, responsive layout, keyboard shortcuts (Esc)
- **`/health` reports bcrypt availability** — JSON key `"bcrypt": true/false`
- **`passlib[bcrypt]` added to `requirements.txt`**

### Fixed
- `_alive_check()` false-negative on hosts that close all 6 hardcoded ports —
  now probes 12 ports concurrently and short-circuits on first positive
- `scan_delay_ms` silently ignored in scanner engine (was set in constants but
  never read in `_scan_port`) — now applied per port probe
- Dashboard basic-auth using plain `hmac.compare_digest` on raw passwords
  without hashing — replaced with bcrypt-based `verify_password()`

### Changed
- `_alive_check()` timeout raised from 0.8 s to `min(rto.rto_s, 1.0)` and
  probes now run concurrently (not sequentially), making host discovery faster
- `dashboard/app.py` removes unused imports (`functools`, `hashlib`, `g`,
  `b64decode`) left over from early drafts

---

## [3.0.0] — 2025-02-17

### Added
- **Adaptive RTT timing** — RFC 6298 SRTT/RTTVAR algorithm, same as TCP stack
- **Timing profiles T0–T5** — mirrors nmap -T0 (paranoid) to -T5 (insane)
- **OS detection** — heuristic via banner regex + service port hints + TTL analysis
- **Service fingerprinting** — version extraction from banners (nginx, Apache, IIS, OpenSSH, vsftpd, MySQL, Redis…)
- **Real nmap-services DB** — 27,476 TCP entries for accurate service name lookup
- **PDF reports** — professional ReportLab output with host/port tables
- **HTML reports** — dark-theme, zero-dependency report generation
- **JSON export** — full scan data with OS/version metadata
- **Web dashboard** — Flask, live stats, scan history, per-host drill-down
- **Database migrations** — schema versioning with rollback-safe ALTER TABLE
- **`pyproject.toml`** — installable via `pip install .`
- **GitHub Actions CI** — multi-version matrix (Python 3.8–3.12)
- **111 unit tests** — port parser, timing, OS detect, service FP, DB, layering
- **`tests/run_all.py`** — zero-dependency test runner (no pytest needed)
- **Public APIs** in `core/__init__.py`, `database/__init__.py`, `utils/__init__.py`
- **`utils/validators.py`** — IP/CIDR/port validation helpers

### Changed
- **Database** — migrated from SQLAlchemy ORM to pure stdlib `sqlite3` (zero deps)
- **Scanner engine** — per-host AND per-port semaphores (was flat pool in v2)
- **Logger** — fixed ColorFormatter to use `%`-style (was causing KeyError on asctime)
- **Migrations** — fixed `ALTER TABLE IF NOT EXISTS` (not supported SQLite < 3.35)
- **`main.py`** — integrates OS detection + service fingerprint into scan output
- **`requirements.txt`** — all deps are optional; core works with stdlib only

### Fixed
- Logger `KeyError: 'asctime'` when using Python 3.12
- Migration `near "EXISTS": syntax error` on older SQLite versions
- Port parser trailing comma edge case
- `upsert` race condition in `repository.save_host`

---

## [2.0.0] — 2025-01-XX

### Added
- Full asyncio engine replacing sequential blocking socket
- Semaphore concurrency control
- YAML configuration system
- Rotating log handlers
- Flask dashboard (basic)
- Benchmark CLI flag

### Fixed
- Port parser crashing on invalid input
- No validation on dashboard exposure

---

## [1.0.0] — 2024-XX-XX

### Initial Release
- Sequential TCP connect scanner
- Basic port parser
- print()-based output
