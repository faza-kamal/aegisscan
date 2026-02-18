"""
core/os_detect.py
Lightweight OS detection based on TTL + TCP window size.
Inspired by nmap's OS fingerprinting (nmap-os-db) but using
connect-scan observables only (no raw packets needed).

Detection method: heuristic TTL fingerprinting
  - Linux:   TTL ≈ 64  (kernel default net.ipv4.ip_default_ttl=64)
  - Windows: TTL ≈ 128 (HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters)
  - Cisco:   TTL ≈ 255 (IOS default)
  - Solaris: TTL ≈ 255
  - FreeBSD: TTL ≈ 64

Works without root — TTL inferred from banner headers (HTTP Server header)
or service banner patterns.

For proper SYN-based fingerprinting, see core/syn_scan.py (requires root).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class OSGuess:
    """OS detection result."""
    os_family: str           # Linux, Windows, Cisco, BSD, Unknown
    os_version: str          # e.g. "Linux 4.x/5.x", "Windows Server 2016-2022"
    confidence: float        # 0.0 – 1.0
    method: str              # ttl_heuristic, banner_regex, service_fingerprint
    cpe: Optional[str] = None


# ─── TTL → OS mapping (from nmap-os-db patterns) ─────────────────────────────

_TTL_MAP = [
    # (min_ttl, max_ttl, os_family, os_version, confidence, cpe)
    (60,  68,  "Linux",   "Linux 4.x/5.x",          0.75, "cpe:/o:linux:linux_kernel"),
    (60,  68,  "FreeBSD", "FreeBSD/OpenBSD",         0.55, "cpe:/o:freebsd:freebsd"),
    (120, 135, "Windows", "Windows (Desktop/Server)", 0.80, "cpe:/o:microsoft:windows"),
    (250, 255, "Cisco",   "Cisco IOS / Solaris",      0.70, "cpe:/o:cisco:ios"),
]


# ─── Banner → OS regex patterns ───────────────────────────────────────────────

_BANNER_PATTERNS: list[tuple[re.Pattern, str, str, float, str]] = [
    # (pattern, os_family, os_version, confidence, cpe)
    (re.compile(r"Server:\s*nginx.*Ubuntu",    re.I), "Linux",   "Ubuntu Linux",          0.85, "cpe:/o:canonical:ubuntu_linux"),
    (re.compile(r"Server:\s*nginx.*Debian",    re.I), "Linux",   "Debian Linux",          0.85, "cpe:/o:debian:debian_linux"),
    (re.compile(r"Server:\s*Apache.*Win",      re.I), "Windows", "Windows + Apache",      0.80, "cpe:/o:microsoft:windows"),
    (re.compile(r"Server:\s*IIS/",             re.I), "Windows", "Windows IIS Server",    0.90, "cpe:/o:microsoft:windows"),
    (re.compile(r"Server:\s*Microsoft",        re.I), "Windows", "Windows",               0.85, "cpe:/o:microsoft:windows"),
    (re.compile(r"SSH-2\.0-OpenSSH.*Ubuntu",   re.I), "Linux",   "Ubuntu Linux",          0.90, "cpe:/o:canonical:ubuntu_linux"),
    (re.compile(r"SSH-2\.0-OpenSSH.*Debian",   re.I), "Linux",   "Debian Linux",          0.90, "cpe:/o:debian:debian_linux"),
    (re.compile(r"SSH-2\.0-OpenSSH.*FreeBSD",  re.I), "FreeBSD", "FreeBSD",               0.90, "cpe:/o:freebsd:freebsd"),
    (re.compile(r"SSH-1\.\d+-Cisco",           re.I), "Cisco",   "Cisco IOS",             0.92, "cpe:/o:cisco:ios"),
    (re.compile(r"220.*FileZilla",             re.I), "Windows", "Windows + FileZilla",   0.75, "cpe:/o:microsoft:windows"),
    (re.compile(r"220.*vsftpd",                re.I), "Linux",   "Linux + vsftpd",        0.80, "cpe:/o:linux:linux_kernel"),
    (re.compile(r"nginx/",                     re.I), "Linux",   "Linux (nginx)",         0.60, "cpe:/o:linux:linux_kernel"),
    (re.compile(r"Apache/\d.*\(Win",           re.I), "Windows", "Windows",               0.80, "cpe:/o:microsoft:windows"),
    (re.compile(r"Apache/\d.*\(Unix\)",        re.I), "Linux",   "Unix/Linux",            0.65, "cpe:/o:linux:linux_kernel"),
]


# ─── Service-level OS hints ────────────────────────────────────────────────────

_SERVICE_HINTS: dict[int, tuple[str, str, float]] = {
    3389: ("Windows", "Windows (RDP open)",     0.95),
    445:  ("Windows", "Windows (SMB open)",     0.90),
    1433: ("Windows", "Windows (MSSQL open)",   0.85),
    5985: ("Windows", "Windows (WinRM open)",   0.90),
    22:   ("Linux",   "Unix/Linux (SSH open)",  0.40),  # low — SSH on all OSes
}


# ─── Detector ────────────────────────────────────────────────────────────────

class OSDetector:
    """
    Infer OS from observable connect-scan artifacts.
    No root required. Lower confidence than nmap SYN fingerprint.
    """

    def detect(
        self,
        banners: dict[int, str],
        open_ports: list[int],
    ) -> Optional[OSGuess]:
        """
        Detect OS from banners and open port set.

        Args:
            banners:    {port: banner_text}
            open_ports: list of open port numbers

        Returns:
            Best OSGuess or None if insufficient data.
        """
        candidates: list[OSGuess] = []

        # 1. Banner regex matching (highest quality)
        for port, banner in banners.items():
            if not banner:
                continue
            for pattern, fam, ver, conf, cpe in _BANNER_PATTERNS:
                if pattern.search(banner):
                    candidates.append(OSGuess(
                        os_family=fam, os_version=ver,
                        confidence=conf, method="banner_regex", cpe=cpe,
                    ))

        # 2. Service-level hints
        for port in open_ports:
            if port in _SERVICE_HINTS:
                fam, ver, conf = _SERVICE_HINTS[port]
                candidates.append(OSGuess(
                    os_family=fam, os_version=ver,
                    confidence=conf, method="service_fingerprint",
                ))

        if not candidates:
            return None

        # Return highest-confidence guess
        return max(candidates, key=lambda g: g.confidence)

    def detect_from_ttl(self, ttl: int) -> Optional[OSGuess]:
        """
        Guess OS from observed IP TTL value.
        TTL is decremented each hop, so we look for nearest standard value.

        NOTE: This method requires the raw TTL from the IP header, which is
        NOT accessible via asyncio.open_connection() (TCP connect scan).
        Use this only when TTL is obtained from a raw socket / ICMP ping
        (e.g. scapy-based scan in a future SYN scan implementation).
        For connect scans, use detect() with banners + open_ports instead.
        """
        # Reconstruct original TTL: round up to nearest standard (64, 128, 255)
        standard_ttls = [64, 128, 255]
        original = min(standard_ttls, key=lambda s: s - ttl if s >= ttl else float('inf'))

        for min_t, max_t, fam, ver, conf, cpe in _TTL_MAP:
            if min_t <= original <= max_t:
                return OSGuess(
                    os_family=fam, os_version=ver,
                    confidence=conf, method="ttl_heuristic", cpe=cpe,
                )
        return None

    @staticmethod
    def format_guess(guess: Optional[OSGuess]) -> str:
        if not guess:
            return "Unknown"
        pct = int(guess.confidence * 100)
        return f"{guess.os_version} ({pct}% confidence, {guess.method})"
