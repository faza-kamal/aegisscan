"""
utils/validators.py
Input validation and sanitization functions
"""

import ipaddress
import re
from typing import Tuple


def validate_target(target: str) -> Tuple[bool, str]:
    """
    Validate that target is a valid IP address or CIDR subnet.
    
    Args:
        target: IP address (e.g. "192.168.1.1") or CIDR (e.g. "192.168.1.0/24")
    
    Returns:
        (is_valid, error_message) tuple
    """
    if not target or not isinstance(target, str):
        return (False, "Target must be a non-empty string")
    
    target = target.strip()
    
    try:
        # Try to parse as IP network (supports both single IPs and CIDR)
        ipaddress.ip_network(target, strict=False)
        return (True, "")
    except ValueError as e:
        return (False, f"Invalid IP address or CIDR: {e}")


def validate_port(port: int) -> Tuple[bool, str]:
    """
    Validate that port number is in valid range [1-65535].
    
    Args:
        port: Port number to validate
    
    Returns:
        (is_valid, error_message) tuple
    """
    if not isinstance(port, int):
        return (False, "Port must be an integer")
    
    if port < 1 or port > 65535:
        return (False, f"Port {port} out of valid range [1-65535]")
    
    return (True, "")


def sanitize_banner(banner: str, max_length: int = 500) -> str:
    """
    Sanitize a service banner by:
    - Truncating to max_length
    - Removing control characters except newlines/tabs
    - Stripping leading/trailing whitespace
    
    Args:
        banner: Raw banner string
        max_length: Maximum allowed length (default: 500)
    
    Returns:
        Sanitized banner string
    """
    if not banner or not isinstance(banner, str):
        return ""
    
    # Remove control characters except \n, \r, \t
    # Keep printable ASCII + common whitespace
    sanitized = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]', '', banner)
    
    # Truncate
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."
    
    # Strip and collapse multiple spaces
    sanitized = ' '.join(sanitized.split())
    
    return sanitized


__all__ = ["validate_target", "validate_port", "sanitize_banner"]
