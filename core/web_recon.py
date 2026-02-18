"""
core/web_recon.py
Web/Domain Reconnaissance module for AegisScan.

Fitur:
  - DNS resolution (A, AAAA, MX, NS, TXT, CNAME) via stdlib socket + dns
  - Reverse DNS (PTR)
  - HTTP/HTTPS header grab (Server, X-Powered-By, teknologi stack)
  - Port dominan analisis dari hasil scan
  - Whois info (domain registrar, creation date) via stdlib
  - Subdomain common check (passive)
  - Teknologi fingerprint dari HTTP headers

Tidak butuh external deps untuk fitur inti.
Optional: dnspython untuk DNS records lebih lengkap.

Layering: TIDAK import database, dashboard, reporting.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone

from utils.logger import get_logger

log = get_logger("web_recon")


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class DNSInfo:
    """Hasil DNS resolution untuk satu target."""
    target: str
    ip_addresses: List[str] = field(default_factory=list)      # A records
    ipv6_addresses: List[str] = field(default_factory=list)    # AAAA records
    hostnames: List[str] = field(default_factory=list)         # PTR / reverse
    mx_records: List[str] = field(default_factory=list)        # Mail servers
    ns_records: List[str] = field(default_factory=list)        # Name servers
    cname: Optional[str] = None
    error: Optional[str] = None


@dataclass
class HTTPInfo:
    """Hasil HTTP header grab."""
    url: str
    status_code: Optional[int] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    content_type: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    redirect_to: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    response_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class PortDominance:
    """Analisis port paling dominan dari hasil scan."""
    port: int
    service: str
    count: int          # berapa host yang buka port ini
    percentage: float   # persen dari total host alive
    versions: List[str] = field(default_factory=list)


@dataclass
class ReconResult:
    """Gabungan semua hasil recon."""
    target: str
    is_domain: bool
    dns: Optional[DNSInfo] = None
    http_80: Optional[HTTPInfo] = None
    http_443: Optional[HTTPInfo] = None
    port_dominance: List[PortDominance] = field(default_factory=list)
    os_distribution: Dict[str, int] = field(default_factory=dict)
    scan_summary: Dict = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ─── Teknologi fingerprint dari HTTP headers ──────────────────────────────────

_TECH_PATTERNS: List[Tuple[str, str, re.Pattern]] = [
    # (header, tech_name, pattern)
    ("server",          "nginx",          re.compile(r"nginx",          re.I)),
    ("server",          "Apache",         re.compile(r"apache",         re.I)),
    ("server",          "IIS",            re.compile(r"Microsoft-IIS",  re.I)),
    ("server",          "LiteSpeed",      re.compile(r"LiteSpeed",      re.I)),
    ("server",          "Caddy",          re.compile(r"Caddy",          re.I)),
    ("server",          "Cloudflare",     re.compile(r"cloudflare",     re.I)),
    ("x-powered-by",    "PHP",            re.compile(r"PHP/[\d.]+",     re.I)),
    ("x-powered-by",    "ASP.NET",        re.compile(r"ASP\.NET",       re.I)),
    ("x-powered-by",    "Express",        re.compile(r"Express",        re.I)),
    ("x-generator",     "WordPress",      re.compile(r"WordPress",      re.I)),
    ("x-generator",     "Drupal",         re.compile(r"Drupal",         re.I)),
    ("x-drupal-cache",  "Drupal",         re.compile(r".*",             re.I)),
    ("via",             "Varnish",        re.compile(r"varnish",        re.I)),
    ("cf-ray",          "Cloudflare CDN", re.compile(r".*",             re.I)),
    ("x-amz-cf-id",     "AWS CloudFront", re.compile(r".*",             re.I)),
    ("x-vercel-id",     "Vercel",         re.compile(r".*",             re.I)),
    ("x-github-request-id", "GitHub Pages", re.compile(r".*",          re.I)),
]


# ─── Common subdomains untuk passive check ────────────────────────────────────

COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "ssh",
    "api", "dev", "staging", "test", "admin", "portal",
    "vpn", "remote", "cdn", "static", "assets", "media",
    "ns1", "ns2", "dns", "mx", "mx1", "mx2",
    "blog", "shop", "store", "app", "mobile",
]


# ─── DNS Resolver ─────────────────────────────────────────────────────────────

class DNSResolver:
    """
    Async DNS resolver menggunakan stdlib socket + asyncio.
    Optional: pakai dnspython untuk MX/NS/TXT records.
    """

    async def resolve(self, target: str) -> DNSInfo:
        """Resolve target (domain atau IP) ke DNSInfo."""
        info = DNSInfo(target=target)

        is_ip = self._is_ip(target)

        if is_ip:
            # Reverse DNS
            info.ip_addresses = [target]
            info.hostnames = await self._reverse_dns(target)
        else:
            # Forward DNS: A records
            info.ip_addresses = await self._resolve_a(target)
            # AAAA
            info.ipv6_addresses = await self._resolve_aaaa(target)
            # Reverse untuk IP yang ditemukan
            for ip in info.ip_addresses[:3]:  # max 3
                rdns = await self._reverse_dns(ip)
                info.hostnames.extend(rdns)

            # MX via dnspython (optional)
            info.mx_records = await self._resolve_mx(target)
            info.ns_records = await self._resolve_ns(target)

        return info

    async def resolve_subdomains(
        self, domain: str, subdomains: List[str] = None
    ) -> Dict[str, List[str]]:
        """
        Cek subdomain common. Return dict {subdomain: [ip, ...]}
        Hanya yang resolve (exist).
        """
        subs = subdomains or COMMON_SUBDOMAINS
        found: Dict[str, List[str]] = {}

        async def _check(sub: str):
            fqdn = f"{sub}.{domain}"
            ips = await self._resolve_a(fqdn)
            if ips:
                found[fqdn] = ips

        tasks = [_check(s) for s in subs]
        await asyncio.gather(*tasks, return_exceptions=True)
        return found

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _is_ip(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    @staticmethod
    async def _resolve_a(domain: str) -> List[str]:
        try:
            loop = asyncio.get_running_loop()
            results = await asyncio.wait_for(
                loop.getaddrinfo(domain, None, family=socket.AF_INET),
                timeout=5.0,
            )
            return list({r[4][0] for r in results})
        except Exception:
            return []

    @staticmethod
    async def _resolve_aaaa(domain: str) -> List[str]:
        try:
            loop = asyncio.get_running_loop()
            results = await asyncio.wait_for(
                loop.getaddrinfo(domain, None, family=socket.AF_INET6),
                timeout=5.0,
            )
            return list({r[4][0] for r in results})
        except Exception:
            return []

    @staticmethod
    async def _reverse_dns(ip: str) -> List[str]:
        try:
            loop = asyncio.get_running_loop()
            hostname, _ = await asyncio.wait_for(
                loop.getnameinfo((ip, 0)),
                timeout=3.0,
            )
            return [hostname] if hostname and hostname != ip else []
        except Exception:
            return []

    @staticmethod
    async def _resolve_mx(domain: str) -> List[str]:
        """MX via dnspython jika tersedia, fallback ke kosong."""
        try:
            import dns.resolver  # type: ignore
            answers = dns.resolver.resolve(domain, "MX")
            return sorted(
                [str(r.exchange).rstrip(".") for r in answers],
                key=lambda x: x
            )
        except Exception:
            return []

    @staticmethod
    async def _resolve_ns(domain: str) -> List[str]:
        """NS via dnspython jika tersedia."""
        try:
            import dns.resolver  # type: ignore
            answers = dns.resolver.resolve(domain, "NS")
            return [str(r).rstrip(".") for r in answers]
        except Exception:
            return []


# ─── HTTP Header Grabber ──────────────────────────────────────────────────────

class HTTPGrabber:
    """Grab HTTP/HTTPS headers dari target. Stdlib only."""

    async def grab(self, host: str, port: int = 80,
                   https: bool = False, timeout: float = 8.0) -> HTTPInfo:
        scheme = "https" if https else "http"
        url = f"{scheme}://{host}"
        if (https and port != 443) or (not https and port != 80):
            url += f":{port}"

        info = HTTPInfo(url=url)
        t0 = time.monotonic()

        try:
            loop = asyncio.get_running_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_grab, url),
                timeout=timeout,
            )
            info = result
            info.response_ms = (time.monotonic() - t0) * 1000
        except asyncio.TimeoutError:
            info.error = "timeout"
        except Exception as e:
            info.error = str(e)[:100]

        return info

    def _sync_grab(self, url: str) -> HTTPInfo:
        """Sync HTTP HEAD request (dijalankan di executor)."""
        info = HTTPInfo(url=url)
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "AegisScan/4.0 (security-scanner)"},
                method="HEAD",
            )
            with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
                info.status_code = resp.status
                headers = dict(resp.headers)
                info.headers = {k.lower(): v for k, v in headers.items()}
                info.server = info.headers.get("server")
                info.powered_by = info.headers.get("x-powered-by")
                info.content_type = info.headers.get("content-type")
                # Teknologi fingerprint
                info.technologies = self._fingerprint(info.headers)
        except urllib.error.HTTPError as e:
            info.status_code = e.code
            try:
                hdr = dict(e.headers)
                info.headers = {k.lower(): v for k, v in hdr.items()}
                info.server = info.headers.get("server")
                info.technologies = self._fingerprint(info.headers)
            except Exception:
                pass
        except urllib.error.URLError as e:
            info.error = str(e.reason)[:100]
        except Exception as e:
            info.error = str(e)[:100]

        return info

    @staticmethod
    def _fingerprint(headers: Dict[str, str]) -> List[str]:
        """Deteksi teknologi dari headers."""
        techs = []
        seen = set()
        for header_name, tech_name, pattern in _TECH_PATTERNS:
            val = headers.get(header_name, "")
            if val and pattern.search(val) and tech_name not in seen:
                techs.append(tech_name)
                seen.add(tech_name)
        return techs


# ─── Port Dominance Analyzer ─────────────────────────────────────────────────

class PortAnalyzer:
    """
    Analisis statistik port dari hasil scan:
    - Port paling sering terbuka (dominan)
    - Distribusi OS
    - Service paling umum
    """

    def analyze(self, scan_data: dict) -> Tuple[List[PortDominance], Dict[str, int]]:
        """
        Analisis dari scan_data dict (dari repository.get_scan()).

        Returns:
            (port_dominance_list, os_distribution)
        """
        hosts = [h for h in scan_data.get("hosts", []) if h.get("is_alive")]
        total_hosts = len(hosts)

        if not hosts:
            return [], {}

        # Hitung frekuensi port
        port_count: Dict[int, int] = {}
        port_service: Dict[int, str] = {}
        port_versions: Dict[int, List[str]] = {}

        for host in hosts:
            for p in host.get("ports", []):
                port = p["port"]
                port_count[port] = port_count.get(port, 0) + 1
                port_service[port] = p.get("service", "unknown")
                if p.get("version"):
                    if port not in port_versions:
                        port_versions[port] = []
                    port_versions[port].append(p["version"])

        # Sort by frekuensi
        sorted_ports = sorted(port_count.items(), key=lambda x: x[1], reverse=True)

        dominance = []
        for port, count in sorted_ports[:20]:  # top 20
            pct = (count / total_hosts) * 100 if total_hosts > 0 else 0
            versions = list(set(port_versions.get(port, [])))[:5]
            dominance.append(PortDominance(
                port=port,
                service=port_service.get(port, "unknown"),
                count=count,
                percentage=round(pct, 1),
                versions=versions,
            ))

        # Distribusi OS
        os_dist: Dict[str, int] = {}
        for host in hosts:
            os_raw = host.get("os_guess", "") or "Unknown"
            # Simplifikasi OS family
            if "Windows" in os_raw:
                os_key = "Windows"
            elif "Linux" in os_raw or "Ubuntu" in os_raw or "Debian" in os_raw:
                os_key = "Linux"
            elif "Cisco" in os_raw:
                os_key = "Cisco IOS"
            elif "FreeBSD" in os_raw or "BSD" in os_raw:
                os_key = "BSD"
            else:
                os_key = "Unknown"
            os_dist[os_key] = os_dist.get(os_key, 0) + 1

        return dominance, os_dist

    def format_report(
        self, dominance: List[PortDominance], os_dist: Dict[str, int],
        total_hosts: int
    ) -> str:
        """Format hasil analisis ke string untuk CLI output."""
        lines = []
        lines.append(f"\n{'═'*60}")
        lines.append("  PORT DOMINANCE ANALYSIS")
        lines.append(f"{'─'*60}")
        lines.append(f"  {'PORT':<8} {'SERVICE':<20} {'HOSTS':>6} {'%':>7}")
        lines.append(f"  {'─'*50}")

        for d in dominance[:15]:
            bar_len = int(d.percentage / 5)
            bar = "█" * bar_len
            lines.append(
                f"  {d.port:<8} {d.service:<20} {d.count:>6} {d.percentage:>6.1f}%  {bar}"
            )

        lines.append(f"\n{'─'*60}")
        lines.append("  OS DISTRIBUTION")
        lines.append(f"{'─'*60}")
        for os_name, count in sorted(os_dist.items(), key=lambda x: x[1], reverse=True):
            pct = (count / total_hosts * 100) if total_hosts else 0
            bar = "█" * int(pct / 5)
            lines.append(f"  {os_name:<20} {count:>4} hosts  {pct:>5.1f}%  {bar}")

        lines.append(f"{'═'*60}\n")
        return "\n".join(lines)


# ─── Web Recon Orchestrator ──────────────────────────────────────────────────

class WebRecon:
    """
    Orkestrator untuk semua fitur web recon.
    Panggil dari CLI: python3 main.py --recon <domain/ip>
    """

    def __init__(self):
        self._dns = DNSResolver()
        self._http = HTTPGrabber()
        self._port_analyzer = PortAnalyzer()

    async def recon(
        self, target: str,
        check_subdomains: bool = False,
        grab_http: bool = True,
    ) -> ReconResult:
        """
        Jalankan full recon terhadap domain atau IP.

        Args:
            target: Domain name atau IP address
            check_subdomains: Cek common subdomains (hanya untuk domain)
            grab_http: Grab HTTP/HTTPS headers

        Returns:
            ReconResult
        """
        is_domain = not self._is_ip(target)
        result = ReconResult(target=target, is_domain=is_domain)

        print(f"\n  [*] Starting recon: {target}")
        print(f"  [*] Target type   : {'Domain' if is_domain else 'IP Address'}")

        # 1. DNS Resolution
        print(f"  [*] DNS resolution...")
        result.dns = await self._dns.resolve(target)

        # Determine IP to probe
        probe_ip = target if not is_domain else (
            result.dns.ip_addresses[0] if result.dns.ip_addresses else None
        )

        # 2. HTTP/HTTPS header grab
        if grab_http and probe_ip:
            print(f"  [*] HTTP probe on {probe_ip}:80 ...")
            result.http_80 = await self._http.grab(probe_ip, 80, https=False)

            print(f"  [*] HTTPS probe on {probe_ip}:443 ...")
            result.http_443 = await self._http.grab(probe_ip, 443, https=True)

        # 3. Subdomain check (domain only, optional)
        if check_subdomains and is_domain:
            print(f"  [*] Checking common subdomains...")
            subs = await self._dns.resolve_subdomains(target)
            result.scan_summary["subdomains"] = subs

        print(f"  [✓] Recon complete.\n")
        return result

    def analyze_scan(self, scan_data: dict) -> Tuple[List[PortDominance], Dict[str, int]]:
        """Analisis hasil scan dari database."""
        return self._port_analyzer.analyze(scan_data)

    def print_recon(self, result: ReconResult) -> None:
        """Pretty-print ReconResult ke stdout."""
        print(f"\n{'═'*60}")
        print(f"  RECON RESULTS: {result.target}")
        print(f"{'═'*60}")

        # DNS
        dns = result.dns
        if dns:
            print(f"\n  ┌─ DNS INFORMATION")
            if dns.ip_addresses:
                print(f"  │  IPv4       : {', '.join(dns.ip_addresses)}")
            if dns.ipv6_addresses:
                print(f"  │  IPv6       : {', '.join(dns.ipv6_addresses[:3])}")
            if dns.hostnames:
                print(f"  │  Hostnames  : {', '.join(dns.hostnames[:5])}")
            if dns.mx_records:
                print(f"  │  MX Records : {', '.join(dns.mx_records[:3])}")
            if dns.ns_records:
                print(f"  │  NS Records : {', '.join(dns.ns_records[:4])}")
            if dns.error:
                print(f"  │  Error      : {dns.error}")
            print(f"  └─")

        # HTTP
        for label, http_info in [("HTTP :80", result.http_80), ("HTTPS:443", result.http_443)]:
            if http_info and not http_info.error:
                print(f"\n  ┌─ {label}")
                print(f"  │  Status     : {http_info.status_code}")
                if http_info.server:
                    print(f"  │  Server     : {http_info.server}")
                if http_info.powered_by:
                    print(f"  │  Powered-By : {http_info.powered_by}")
                if http_info.technologies:
                    print(f"  │  Tech Stack : {', '.join(http_info.technologies)}")
                print(f"  │  RTT        : {http_info.response_ms:.1f}ms")
                print(f"  └─")
            elif http_info and http_info.error:
                print(f"\n  ┌─ {label}")
                print(f"  │  Status     : unreachable ({http_info.error})")
                print(f"  └─")

        # Subdomains
        subs = result.scan_summary.get("subdomains", {})
        if subs:
            print(f"\n  ┌─ SUBDOMAINS FOUND ({len(subs)})")
            for fqdn, ips in list(subs.items())[:20]:
                print(f"  │  {fqdn:<40} → {', '.join(ips)}")
            print(f"  └─")

        print(f"\n{'═'*60}\n")

    @staticmethod
    def _is_ip(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False


# ─── Module-level convenience ────────────────────────────────────────────────

_recon = WebRecon()


async def recon(target: str, **kwargs) -> ReconResult:
    """Module-level convenience function."""
    return await _recon.recon(target, **kwargs)
