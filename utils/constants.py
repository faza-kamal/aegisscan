"""
AegisScan Constants & Enums
Inspired by nmap's portlist.h port states and timing.h models
"""

from enum import IntEnum, Enum
from dataclasses import dataclass, field


# ─── Port States (mirrors nmap portlist.h defines) ───────────────────────────
class PortState(IntEnum):
    UNKNOWN   = 0
    CLOSED    = 1
    OPEN      = 2
    FILTERED  = 3
    TESTING   = 4
    OPEN_FILTERED = 5
    CLOSED_FILTERED = 6
    UNFILTERED = 7


# ─── Scan Types ───────────────────────────────────────────────────────────────
class ScanType(str, Enum):
    TCP_CONNECT = "tcp_connect"   # Full 3-way handshake (no root needed)
    TCP_SYN     = "tcp_syn"       # SYN scan (root / scapy)
    UDP         = "udp"           # UDP scan
    BANNER      = "banner"        # Banner grabbing
    SUBNET      = "subnet"        # Subnet sweep


# ─── Timing Presets (mirrors nmap -T0 to -T5) ─────────────────────────────────
@dataclass
class TimingProfile:
    """Scan timing profile - inspired by nmap's scan_performance_vars"""
    name: str
    max_concurrent_hosts: int
    max_concurrent_ports: int
    connection_timeout_ms: float  # milliseconds
    max_retries: int
    max_rtt_timeout_ms: float
    min_rtt_timeout_ms: float
    initial_rtt_timeout_ms: float
    scan_delay_ms: float           # min delay between probes
    max_scan_delay_ms: float
    max_rate: int                  # packets per second, 0 = unlimited


TIMING_PROFILES = {
    "paranoid":  TimingProfile("T0-Paranoid",  max_concurrent_hosts=1,   max_concurrent_ports=1,
                               connection_timeout_ms=5000, max_retries=5,
                               max_rtt_timeout_ms=5000, min_rtt_timeout_ms=100,
                               initial_rtt_timeout_ms=5000,
                               scan_delay_ms=300000, max_scan_delay_ms=1000000, max_rate=0),

    "sneaky":    TimingProfile("T1-Sneaky",    max_concurrent_hosts=1,   max_concurrent_ports=1,
                               connection_timeout_ms=3000, max_retries=3,
                               max_rtt_timeout_ms=10000, min_rtt_timeout_ms=100,
                               initial_rtt_timeout_ms=3000,
                               scan_delay_ms=15000, max_scan_delay_ms=1000000, max_rate=0),

    "polite":    TimingProfile("T2-Polite",    max_concurrent_hosts=5,   max_concurrent_ports=10,
                               connection_timeout_ms=1500, max_retries=3,
                               max_rtt_timeout_ms=5000, min_rtt_timeout_ms=100,
                               initial_rtt_timeout_ms=1500,
                               scan_delay_ms=400, max_scan_delay_ms=1000, max_rate=0),

    "normal":    TimingProfile("T3-Normal",    max_concurrent_hosts=30,  max_concurrent_ports=50,
                               connection_timeout_ms=1000, max_retries=2,
                               max_rtt_timeout_ms=3000, min_rtt_timeout_ms=100,
                               initial_rtt_timeout_ms=1000,
                               scan_delay_ms=0, max_scan_delay_ms=0, max_rate=0),

    "aggressive":TimingProfile("T4-Aggressive",max_concurrent_hosts=100, max_concurrent_ports=200,
                               connection_timeout_ms=500, max_retries=2,
                               max_rtt_timeout_ms=1250, min_rtt_timeout_ms=100,
                               initial_rtt_timeout_ms=500,
                               scan_delay_ms=0, max_scan_delay_ms=0, max_rate=0),

    "insane":    TimingProfile("T5-Insane",    max_concurrent_hosts=300, max_concurrent_ports=500,
                               connection_timeout_ms=250, max_retries=1,
                               max_rtt_timeout_ms=300, min_rtt_timeout_ms=50,
                               initial_rtt_timeout_ms=250,
                               scan_delay_ms=0, max_scan_delay_ms=0, max_rate=0),
}

DEFAULT_TIMING = "normal"

# ─── Port Parser Limits ───────────────────────────────────────────────────────
PORT_MIN        = 1
PORT_MAX        = 65535
PORT_MAX_BATCH  = 65535   # max ports per scan
MAX_SAFE_BATCH  = 10_000  # warn if above this

# ─── Layering Contract (hard import rules - enforced by tests) ───────────────
# core → may import: utils, data
# database → may import: utils
# dashboard → may import: database.repository, utils
# reporting → may import: database.repository, utils
# NEVER: core imports database, dashboard imports core directly

# ─── DB Index Columns ─────────────────────────────────────────────────────────
DB_INDEX_COLUMNS = {
    "scans":   ["target", "started_at", "status"],
    "hosts":   ["scan_id", "ip_address", "is_alive"],
    "ports":   ["host_id", "port_number", "state"],
}
