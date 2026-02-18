"""AegisScan Data — Bundled data files

This package contains read-only data files used by the scanner:

  nmap-services     — TCP/UDP port-to-service name mapping and frequency scores
                      (from the Nmap project; used for top-N port selection and
                      service name lookup in scanner_engine and port_parser)

  service-probes.txt — Service detection probe patterns
                       (inspired by nmap-service-probes format)

These files are accessed via their filesystem path using pathlib:

    from pathlib import Path
    DATA_DIR = Path(__file__).parent
    NMAP_SERVICES  = DATA_DIR / "nmap-services"
    SERVICE_PROBES = DATA_DIR / "service-probes.txt"
"""
from pathlib import Path as _Path

DATA_DIR       = _Path(__file__).parent
NMAP_SERVICES  = DATA_DIR / "nmap-services"
SERVICE_PROBES = DATA_DIR / "service-probes.txt"

__all__ = [
    "DATA_DIR",
    "NMAP_SERVICES",
    "SERVICE_PROBES",
]
