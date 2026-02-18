"""
core/service_fingerprint.py
Service version detection via banner regex matching.
Pattern format inspired directly by nmap-service-probes.

nmap probe format:
  match <svc> m|<regex>| p/<product>/ v/<version>/ i/<info>/ o/<os>/

We parse a subset of this for version extraction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ServiceInfo:
    """Detected service information."""
    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    os_hint: Optional[str] = None
    cpe: Optional[str] = None

    def __str__(self) -> str:
        parts = [self.name]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        if self.extra_info:
            parts.append(f"({self.extra_info})")
        return " ".join(parts)


# ─── Hardcoded high-quality patterns (from nmap-service-probes analysis) ──────

_BUILTIN_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # (regex, service_name, version_template)
    # HTTP
    (re.compile(r"^HTTP/\d\.\d \d+.*\r\nServer: (nginx)/([\d.]+)", re.I | re.S),
     "http", "nginx/{2}"),
    (re.compile(r"^HTTP/\d\.\d \d+.*\r\nServer: Apache/([\d.]+)", re.I | re.S),
     "http", "Apache httpd/{1}"),
    (re.compile(r"^HTTP/\d\.\d \d+.*\r\nServer: Microsoft-IIS/([\d.]+)", re.I | re.S),
     "http", "Microsoft IIS httpd/{1}"),
    (re.compile(r"^HTTP/\d\.\d \d+.*\r\nServer: lighttpd/([\d.]+)", re.I | re.S),
     "http", "lighttpd/{1}"),
    (re.compile(r"^HTTP/\d\.\d \d+.*\r\nServer: ([\w/._-]+)", re.I | re.S),
     "http", "{1}"),

    # SSH
    (re.compile(r"^SSH-([\d.]+)-(OpenSSH)_([\d.p]+)", re.I),
     "ssh", "OpenSSH/{3}"),
    (re.compile(r"^SSH-([\d.]+)-([A-Za-z_]+[\w./-]+)", re.I),
     "ssh", "{2}"),

    # FTP
    (re.compile(r"^220[\s-].*?(vsftpd|ProFTPD|Pure-FTPd|FileZilla)[\s/]?([\d.]*)", re.I),
     "ftp", "{1}/{2}"),
    (re.compile(r"^220[\s-](Microsoft FTP)", re.I),
     "ftp", "Microsoft FTP Service"),
    (re.compile(r"^220[\s-]([^\r\n]{1,60})", re.I),
     "ftp", "{1}"),

    # SMTP
    (re.compile(r"^220[\s-].*?(Postfix|Sendmail|Exim|Microsoft Exchange|MailEnable)[\s/]?([\d.]*)", re.I),
     "smtp", "{1}"),

    # MySQL
    (re.compile(r"^.\x00\x00\x00\n([\d.]+)", re.S),
     "mysql", "MySQL/{1}"),

    # Redis
    (re.compile(r"\$\d+\r\nredis_version:([\d.]+)", re.I),
     "redis", "Redis/{1}"),

    # MongoDB
    (re.compile(r'"version"\s*:\s*"([\d.]+)"', re.I),
     "mongodb", "MongoDB/{1}"),

    # PostgreSQL
    (re.compile(r"PostgreSQL ([\d.]+)", re.I),
     "postgresql", "PostgreSQL/{1}"),

    # RDP
    (re.compile(r"\x03\x00\x00.\x0e\xd0\x00\x00", re.S),
     "ms-wbt-server", "Microsoft Terminal Services"),

    # SMB
    (re.compile(r"\xffSMB", re.S),
     "microsoft-ds", "Microsoft Windows netbios-ssn"),

    # Telnet
    (re.compile(r"^\xff[\xfb-\xfe]", re.S),
     "telnet", "telnetd"),

    # LDAP
    (re.compile(r"^\x30", re.S),
     "ldap", "OpenLDAP"),

    # Generic HTTP version catch-all
    (re.compile(r"^HTTP/(\d\.\d)", re.I),
     "http", "HTTP/{1}"),
]


# ─── Service Fingerprinter ────────────────────────────────────────────────────

class ServiceFingerprinter:
    """
    Match banner text against service patterns to extract version info.
    """

    def __init__(self):
        self._patterns = _BUILTIN_PATTERNS

    def identify(self, port: int, banner: Optional[str], service_name: str = "unknown") -> ServiceInfo:
        """
        Identify service from port + banner.

        Args:
            port: Port number (used for context)
            banner: Raw banner text
            service_name: Name from nmap-services db (fallback)

        Returns:
            ServiceInfo with detected details
        """
        if not banner:
            return ServiceInfo(name=service_name)

        # Try each pattern
        for pattern, svc_name, version_tmpl in self._patterns:
            m = pattern.search(banner)
            if m:
                # Substitute capture groups into version template
                version = version_tmpl
                for i, grp in enumerate(m.groups(), start=1):
                    if grp:
                        version = version.replace(f"{{{i}}}", grp.strip())
                    else:
                        version = version.replace(f"{{{i}}}", "")

                # Clean up version
                version = re.sub(r"/+$", "", version).strip()
                parts = version.split("/", 1)

                return ServiceInfo(
                    name=svc_name,
                    product=parts[0] if parts else None,
                    version=parts[1] if len(parts) > 1 else None,
                )

        # No pattern matched — return name from service db
        return ServiceInfo(name=service_name)

    def identify_all(
        self,
        port_banners: dict[int, tuple[str, Optional[str]]]
    ) -> dict[int, ServiceInfo]:
        """
        Identify services on multiple ports.

        Args:
            port_banners: {port: (service_name, banner_text)}

        Returns:
            {port: ServiceInfo}
        """
        return {
            port: self.identify(port, banner, svc)
            for port, (svc, banner) in port_banners.items()
        }


# ─── Module-level singleton ───────────────────────────────────────────────────

_fingerprinter = ServiceFingerprinter()


def fingerprint(port: int, banner: Optional[str], service: str = "unknown") -> ServiceInfo:
    """Module-level convenience function."""
    return _fingerprinter.identify(port, banner, service)
