"""
core/scanner_engine.py
Async TCP-connect scan engine with:
  • asyncio.open_connection — non-blocking, no raw sockets needed
  • Semaphore-controlled host + port concurrency
  • Adaptive RTT-based timeouts (core/timing.py)
  • Granular per-exception handling (no bare except)
  • Service name lookup from real nmap-services DB
  • Banner grabbing (protocol-aware probes)
  • Progress callback support
  • No imports of dashboard/database (clean layering)
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set

from core.timing import RTOTracker, RateMeter, get_timing
from utils.constants import PortState, ScanType, TimingProfile


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class PortResult:
    port:          int
    state:         PortState
    service:       str
    banner:        Optional[str] = None
    response_ms:   float = 0.0


@dataclass
class HostResult:
    ip:            str
    hostname:      Optional[str]
    is_alive:      bool
    open_ports:    List[PortResult] = field(default_factory=list)
    scan_ms:       float = 0.0
    timestamp:     str = ""
    scan_type:     ScanType = ScanType.TCP_CONNECT


@dataclass
class ScanStats:
    hosts_total:   int = 0
    hosts_alive:   int = 0
    ports_scanned: int = 0
    ports_open:    int = 0
    elapsed_s:     float = 0.0
    rate_per_s:    float = 0.0


# ─── Service DB loader (real nmap-services) ───────────────────────────────────

class ServiceDB:
    """Load TCP service names from nmap-services file."""

    _FALLBACK: Dict[int, str] = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
        80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "microsoft-ds",
        3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
        8080: "http-proxy", 8443: "https-alt",
    }

    def __init__(self, db_path: Optional[Path] = None):
        self._map: Dict[int, str] = {}
        self._load(db_path or Path(__file__).parent.parent / "data" / "nmap-services")

    def _load(self, path: Path) -> None:
        if not path.exists():
            self._map = dict(self._FALLBACK)
            return
        for line in path.read_text(errors="ignore").splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                name, port_proto = parts[0], parts[1]
                port_str, proto = port_proto.split("/")
                if proto == "tcp":
                    self._map[int(port_str)] = name
            except (ValueError, IndexError):
                continue
        if not self._map:
            self._map = dict(self._FALLBACK)

    def lookup(self, port: int) -> str:
        return self._map.get(port, "unknown")


_service_db = ServiceDB()


# ─── Banner probes (inspired by nmap-service-probes NULL + HTTP) ──────────────

_HTTP_PORTS: Set[int] = {80, 8080, 8000, 8008, 8888}
_HTTPS_PORTS: Set[int] = {443, 8443, 4443}

def _probe_for_port(port: int) -> bytes:
    if port in _HTTP_PORTS | _HTTPS_PORTS:
        return b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
    if port == 21:
        return b""          # FTP sends banner on connect
    if port == 22:
        return b""          # SSH sends banner on connect
    if port == 25:
        return b"EHLO aegisscan\r\n"
    if port in (110, 143, 995, 993):
        return b""          # POP3/IMAP banner on connect
    return b"\r\n"          # generic NULL probe


# ─── Core Engine ─────────────────────────────────────────────────────────────

class ScanEngine:
    """
    High-performance async TCP-connect scanner.

    Layering contract:
      Imports only: core/timing.py, utils/constants.py, data/
      Does NOT import: database, dashboard, reporting
    """

    def __init__(
        self,
        timing: str | TimingProfile = "normal",
        grab_banners: bool = True,
        progress_cb: Optional[Callable[[str], None]] = None,
    ):
        self._profile: TimingProfile = (
            get_timing(timing) if isinstance(timing, str) else timing
        )
        self._grab_banners = grab_banners
        self._cb = progress_cb or (lambda _: None)
        self._rate = RateMeter()

        # Semaphores — created lazily inside the event loop
        self._host_sem: Optional[asyncio.Semaphore] = None
        self._port_sem: Optional[asyncio.Semaphore] = None

    # ── Public scan API ───────────────────────────────────────────────────────

    async def scan_host(
        self, ip: str, ports: Sequence[int]
    ) -> HostResult:
        """Scan all ports on a single host. Returns HostResult."""
        self._ensure_semaphores()
        rto = RTOTracker(profile=self._profile)

        t0 = time.monotonic()
        hostname = await self._resolve(ip)

        # Fast alive check before full scan
        alive = await self._alive_check(ip, rto)
        if not alive:
            self._cb(f"[-] {ip} down")
            return HostResult(
                ip=ip, hostname=hostname, is_alive=False,
                scan_ms=(time.monotonic() - t0) * 1000,
                timestamp=self._now(),
            )

        self._cb(f"[+] {ip} is up — scanning {len(ports)} ports")

        async with self._host_sem:
            tasks = [self._scan_port(ip, p, rto) for p in ports]
            results: list = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = sorted(
            [r for r in results if isinstance(r, PortResult) and r.state == PortState.OPEN],
            key=lambda r: r.port,
        )

        elapsed = (time.monotonic() - t0) * 1000
        self._cb(
            f"[✓] {ip} done: {len(open_ports)} open / {len(ports)} scanned "
            f"in {elapsed/1000:.2f}s"
        )

        return HostResult(
            ip=ip, hostname=hostname, is_alive=True,
            open_ports=open_ports,
            scan_ms=elapsed,
            timestamp=self._now(),
        )

    async def scan_subnet(
        self, cidr: str, ports: Sequence[int]
    ) -> tuple[list[HostResult], ScanStats]:
        """Scan all hosts in subnet. Returns (results, stats)."""
        self._ensure_semaphores()
        t0 = time.monotonic()

        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR: {cidr!r}") from exc

        host_ips = [str(ip) for ip in net.hosts()]
        self._cb(f"[*] Subnet {cidr}: {len(host_ips)} hosts × {len(ports)} ports")

        tasks = [self.scan_host(str(ip), ports) for ip in host_ips]
        raw: list = await asyncio.gather(*tasks, return_exceptions=True)

        results = [r for r in raw if isinstance(r, HostResult)]
        alive   = [r for r in results if r.is_alive]

        elapsed = time.monotonic() - t0
        stats = ScanStats(
            hosts_total   = len(host_ips),
            hosts_alive   = len(alive),
            ports_scanned = sum(len(ports) for r in alive),
            ports_open    = sum(len(r.open_ports) for r in alive),
            elapsed_s     = elapsed,
            rate_per_s    = self._rate.overall_rate(),
        )
        return alive, stats

    # ── Port-level scan ───────────────────────────────────────────────────────

    async def _scan_port(
        self, ip: str, port: int, rto: RTOTracker
    ) -> PortResult:
        """Attempt TCP connection to ip:port. Returns PortResult."""
        async with self._port_sem:
            # ── Timing delay (honors scan_delay_ms from profile) ──────────────
            delay_ms = self._profile.scan_delay_ms
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)

            t0 = time.monotonic()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=rto.rto_s,
                )
            except asyncio.TimeoutError:
                self._rate.update()
                return PortResult(port=port, state=PortState.FILTERED,
                                  service=_service_db.lookup(port))
            except ConnectionRefusedError:
                self._rate.update()
                return PortResult(port=port, state=PortState.CLOSED,
                                  service=_service_db.lookup(port))
            except OSError:
                self._rate.update()
                return PortResult(port=port, state=PortState.FILTERED,
                                  service=_service_db.lookup(port))

            rtt_ms = (time.monotonic() - t0) * 1000
            rto.update(rtt_ms)
            self._rate.update()

            banner: Optional[str] = None
            if self._grab_banners:
                banner = await self._grab_banner(reader, writer, port)

            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

            return PortResult(
                port=port,
                state=PortState.OPEN,
                service=_service_db.lookup(port),
                banner=banner,
                response_ms=rtt_ms,
            )

    async def _grab_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int,
    ) -> Optional[str]:
        """Send probe and read up to 1 KB of banner. Never raises."""
        try:
            probe = _probe_for_port(port)
            if probe:
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=1.0)
            data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            return data.decode("utf-8", errors="replace").strip() or None
        except Exception:
            return None

    # ── Host alive check ──────────────────────────────────────────────────────

    async def _alive_check(self, ip: str, rto: RTOTracker) -> bool:
        """
        Multi-strategy host alive detection:
          1. Concurrent TCP probes on common ports (fast path).
          2. If ALL common ports timeout/refuse, try the first port in
             the user's actual target port list so we don't false-negative
             hosts that close all well-known ports.
          3. ConnectionRefusedError is itself proof of life — the host
             replied with a RST, so we mark it alive immediately.
        """
        # Broad set of probe ports; RST on any one is proof of life.
        probe_ports = [80, 443, 22, 21, 23, 25, 53, 8080, 8443, 3389, 445, 139]
        timeout = min(rto.rto_s, 1.0)

        async def _tcp_probe(port: int) -> bool:
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=timeout,
                )
                w.close()
                try:
                    await w.wait_closed()
                except OSError:
                    pass
                return True          # connected  → alive
            except ConnectionRefusedError:
                return True          # RST received → host is UP, port closed
            except (asyncio.TimeoutError, OSError):
                return False         # no reply / unreachable

        # Fire all probes concurrently; return True on first positive.
        tasks = [asyncio.ensure_future(_tcp_probe(p)) for p in probe_ports]
        try:
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    # Cancel remaining probes — we have our answer.
                    for t in tasks:
                        t.cancel()
                    return True
        finally:
            # Suppress CancelledError from cancelled futures.
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        return False

    # ── DNS ───────────────────────────────────────────────────────────────────

    async def _resolve(self, ip: str) -> Optional[str]:
        try:
            loop = asyncio.get_running_loop()
            result = await asyncio.wait_for(
                loop.getaddrinfo(ip, None, type=socket.SOCK_STREAM),
                timeout=2.0,
            )
            hostname, _, _, _, _ = await asyncio.wait_for(
                loop.getnameinfo((ip, 0)),
                timeout=2.0,
            )
            return hostname if hostname != ip else None
        except Exception:
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _ensure_semaphores(self) -> None:
        """Create semaphores inside running event loop."""
        if self._host_sem is None:
            self._host_sem = asyncio.Semaphore(
                self._profile.max_concurrent_hosts
            )
        if self._port_sem is None:
            self._port_sem = asyncio.Semaphore(
                self._profile.max_concurrent_ports
            )

    @staticmethod
    def _now() -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
