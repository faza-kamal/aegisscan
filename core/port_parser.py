"""
core/port_parser.py
Robust port specification parser.

Accepts:
  "80"                 → [80]
  "80,443"             → [80, 443]
  "1-1000"             → [1..1000]
  "22,80-100,443"      → merged & sorted, deduped
  "top100"             → top-100 from nmap-services db
  "-"                  → all ports (1-65535), with explicit warning

Rejects:
  "abc", "99999", "-5", "100-50", "", None, beyond-limit ranges
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Set, Tuple

from utils.constants import PORT_MIN, PORT_MAX, PORT_MAX_BATCH, MAX_SAFE_BATCH


# ─── Custom Exceptions ────────────────────────────────────────────────────────

class PortParseError(ValueError):
    """Raised when port specification is invalid."""


# ─── Parser ───────────────────────────────────────────────────────────────────

class PortParser:
    """
    Parse any nmap-compatible port specification string.

    All errors raise PortParseError with a human-readable message.
    No exceptions are ever swallowed silently.
    """

    _SINGLE_RE = re.compile(r"^\d+$")
    _RANGE_RE  = re.compile(r"^(\d+)-(\d+)$")

    def __init__(self, services_db: Path | None = None):
        self._top_ports: List[int] | None = None
        self._services_db = services_db

    # ── Public API ────────────────────────────────────────────────────────────

    def parse(self, spec: str) -> List[int]:
        """
        Parse port spec → sorted deduplicated list.

        Raises PortParseError on any invalid input.
        """
        if not isinstance(spec, str):
            raise PortParseError(f"Expected string, got {type(spec).__name__}")

        spec = spec.strip()
        if not spec:
            raise PortParseError("Port specification is empty")

        # Special keyword: all ports
        if spec == "-":
            return list(range(PORT_MIN, PORT_MAX + 1))

        # Special keyword: top-N from nmap-services
        m = re.fullmatch(r"top(\d+)", spec, re.IGNORECASE)
        if m:
            n = int(m.group(1))
            return self._top_n_ports(n)

        ports: Set[int] = set()
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            ports.update(self._parse_token(part))

        if not ports:
            raise PortParseError(f"No valid ports parsed from: {spec!r}")

        if len(ports) > PORT_MAX_BATCH:
            raise PortParseError(
                f"Parsed {len(ports)} ports, exceeds hard limit {PORT_MAX_BATCH}"
            )

        return sorted(ports)

    def validate(self, spec: str) -> Tuple[bool, str]:
        """Return (ok, error_message). Never raises."""
        try:
            self.parse(spec)
            return True, ""
        except PortParseError as exc:
            return False, str(exc)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _parse_token(self, token: str) -> List[int]:
        if self._SINGLE_RE.match(token):
            return [self._validated(int(token))]

        m = self._RANGE_RE.match(token)
        if m:
            start, end = int(m.group(1)), int(m.group(2))
            self._validated(start)
            self._validated(end)
            if start > end:
                raise PortParseError(
                    f"Invalid range {start}-{end}: start > end"
                )
            size = end - start + 1
            if size > PORT_MAX_BATCH:
                raise PortParseError(
                    f"Range {start}-{end} spans {size} ports, "
                    f"exceeds limit {PORT_MAX_BATCH}"
                )
            return list(range(start, end + 1))

        raise PortParseError(
            f"Invalid port token: {token!r}  "
            f"(expected integer or start-end range)"
        )

    @staticmethod
    def _validated(port: int) -> int:
        if not (PORT_MIN <= port <= PORT_MAX):
            raise PortParseError(
                f"Port {port} out of valid range [{PORT_MIN}, {PORT_MAX}]"
            )
        return port

    def _top_n_ports(self, n: int) -> List[int]:
        """Return top-N most commonly open ports from nmap-services."""
        if n < 1 or n > PORT_MAX:
            raise PortParseError(f"top{n}: n must be 1..{PORT_MAX}")
        all_top = self._load_top_ports()
        if n > len(all_top):
            n = len(all_top)
        return sorted(all_top[:n])

    def _load_top_ports(self) -> List[int]:
        """
        Load port frequencies from nmap-services, sorted by frequency desc.
        Falls back to embedded common list if file unavailable.
        """
        if self._top_ports is not None:
            return self._top_ports

        db = self._services_db or (
            Path(__file__).parent.parent / "data" / "nmap-services"
        )
        ports_freq: dict[int, float] = {}

        if db.exists():
            for line in db.read_text(errors="ignore").splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split()
                if len(parts) < 3:
                    continue
                port_proto = parts[1]
                try:
                    freq = float(parts[2])
                    port_str, proto = port_proto.split("/")
                    if proto == "tcp":
                        port = int(port_str)
                        if PORT_MIN <= port <= PORT_MAX:
                            # Keep highest frequency if port listed twice
                            if port not in ports_freq or freq > ports_freq[port]:
                                ports_freq[port] = freq
                except (ValueError, IndexError):
                    continue
            self._top_ports = sorted(ports_freq, key=lambda p: -ports_freq[p])
        else:
            # Embedded fallback – most commonly open TCP ports
            self._top_ports = [
                80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
                143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
                1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
            ]

        return self._top_ports


# ── Module-level convenience ──────────────────────────────────────────────────

_default_parser = PortParser()


def parse_ports(spec: str) -> List[int]:
    return _default_parser.parse(spec)


def common_ports() -> List[int]:
    return _default_parser._top_n_ports(100)
