"""
AegisScan Core — Public API

from core import scan_host, scan_subnet, parse_ports
"""
from core.port_parser   import PortParser, parse_ports, PortParseError
from core.timing        import get_timing, RTOTracker
from core.os_detect     import OSDetector
from core.service_fingerprint import ServiceFingerprinter, fingerprint
from core.scanner_engine import ScanEngine, PortResult, HostResult, ScanStats
from core.web_recon     import WebRecon, PortAnalyzer, DNSResolver, HTTPGrabber

__all__ = [
    "ScanEngine", "PortResult", "HostResult", "ScanStats",
    "PortParser", "parse_ports", "PortParseError",
    "get_timing", "RTOTracker",
    "OSDetector",
    "ServiceFingerprinter", "fingerprint",
    "WebRecon", "PortAnalyzer", "DNSResolver", "HTTPGrabber",
]
