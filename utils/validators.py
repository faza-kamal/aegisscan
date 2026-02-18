"""
utils/validators.py
Input validation helpers used across the codebase.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Tuple


def validate_ip(ip: str) -> Tuple[bool, str]:
    """Validate IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True, ""
    except ValueError:
        return False, f"Invalid IPv4 address: {ip!r}"


def validate_cidr(cidr: str) -> Tuple[bool, str]:
    """Validate CIDR notation (e.g. 192.168.1.0/24)."""
    try:
        ipaddress.IPv4Network(cidr, strict=False)
        return True, ""
    except ValueError:
        return False, f"Invalid CIDR: {cidr!r}"


def validate_target(target: str) -> Tuple[bool, str]:
    """Validate scan target — IP or CIDR."""
    if "/" in target:
        return validate_cidr(target)
    return validate_ip(target)


def validate_port(port: int) -> Tuple[bool, str]:
    """Validate single port number."""
    if not isinstance(port, int):
        return False, f"Port must be int, got {type(port).__name__}"
    if not (1 <= port <= 65535):
        return False, f"Port {port} out of range [1, 65535]"
    return True, ""


def sanitize_banner(banner: str, max_len: int = 512) -> str:
    """Strip non-printable chars from banner, truncate to max_len."""
    if not banner:
        return ""
    cleaned = re.sub(r"[^\x20-\x7e\r\n\t]", ".", banner)
    return cleaned[:max_len].strip()
