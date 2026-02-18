"""
core/timing.py
Adaptive RTT-based timeout model.

Ported conceptually from nmap's timing.h ultra_timing_vals and timeout_info.
Tracks smoothed RTT (SRTT), RTT variance (RTTVAR), and dynamically
adjusts connection timeout – same algorithm TCP uses for retransmission.

Key formulas (RFC 6298 / nmap):
  SRTT   = (1-alpha)*SRTT   + alpha*RTT       alpha ≈ 0.125
  RTTVAR = (1-beta)*RTTVAR  + beta*|RTT-SRTT|  beta  ≈ 0.25
  RTO    = SRTT + 4*RTTVAR
  clamped to [min_rto_ms, max_rto_ms]
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from utils.constants import TimingProfile, TIMING_PROFILES, DEFAULT_TIMING


# ─── RTT Tracker ──────────────────────────────────────────────────────────────

@dataclass
class RTOTracker:
    """
    Thread-safe adaptive RTO (Retransmit TimeOut) calculator.
    One instance per scan target.
    """

    profile: TimingProfile
    _lock:   threading.Lock = field(default_factory=threading.Lock, init=False)

    # RFC 6298 constants
    _alpha: float = 0.125
    _beta:  float = 0.25

    # State (ms)
    _srtt:   Optional[float] = field(default=None, init=False)
    _rttvar: float = field(default=0.0,  init=False)
    _rto:    Optional[float] = field(default=None, init=False)

    # Stats
    _samples: int = field(default=0, init=False)

    def update(self, rtt_ms: float) -> None:
        """Feed one RTT sample. Thread-safe."""
        with self._lock:
            if self._srtt is None:
                # First measurement (RFC 6298 §2.2)
                self._srtt   = rtt_ms
                self._rttvar = rtt_ms / 2.0
            else:
                delta         = abs(rtt_ms - self._srtt)
                self._rttvar  = (1 - self._beta) * self._rttvar + self._beta * delta
                self._srtt    = (1 - self._alpha) * self._srtt  + self._alpha * rtt_ms

            raw_rto = self._srtt + 4 * self._rttvar
            self._rto = max(
                self.profile.min_rtt_timeout_ms,
                min(raw_rto, self.profile.max_rtt_timeout_ms),
            )
            self._samples += 1

    @property
    def rto_ms(self) -> float:
        """Current RTO in milliseconds."""
        with self._lock:
            if self._rto is None:
                return self.profile.initial_rtt_timeout_ms
            return self._rto

    @property
    def rto_s(self) -> float:
        """Current RTO in seconds (for asyncio.wait_for)."""
        return self.rto_ms / 1000.0

    @property
    def samples(self) -> int:
        with self._lock:
            return self._samples

    @property
    def srtt_ms(self) -> Optional[float]:
        with self._lock:
            return self._srtt


# ─── Scan Rate Meter (mirrors nmap RateMeter) ─────────────────────────────────

class RateMeter:
    """
    Tracks current and lifetime average scan rates.
    Thread-safe.
    """

    def __init__(self, window_s: float = 5.0):
        self._window   = window_s
        self._lock     = threading.Lock()
        self._history: list[tuple[float, float]] = []  # (timestamp, amount)
        self._total    = 0.0
        self._start    = time.monotonic()

    def update(self, amount: float = 1.0) -> None:
        now = time.monotonic()
        with self._lock:
            self._history.append((now, amount))
            self._total += amount
            # prune old entries
            cutoff = now - self._window
            self._history = [(t, a) for t, a in self._history if t >= cutoff]

    def current_rate(self) -> float:
        """Items/second in sliding window."""
        now = time.monotonic()
        with self._lock:
            cutoff = now - self._window
            recent = [a for t, a in self._history if t >= cutoff]
            if not recent:
                return 0.0
            elapsed = min(self._window, now - self._start)
            return sum(recent) / elapsed if elapsed > 0 else 0.0

    def overall_rate(self) -> float:
        elapsed = time.monotonic() - self._start
        if elapsed <= 0:
            return 0.0
        with self._lock:
            return self._total / elapsed

    @property
    def total(self) -> float:
        with self._lock:
            return self._total


# ─── Convenience factory ──────────────────────────────────────────────────────

def get_timing(name: str = DEFAULT_TIMING) -> TimingProfile:
    """
    Get a timing profile by name.
    Accepts: paranoid, sneaky, polite, normal, aggressive, insane
             or T0 .. T5 shorthand.
    """
    # Map T0-T5 shorthand
    shorthand = {"t0": "paranoid", "t1": "sneaky", "t2": "polite",
                 "t3": "normal",   "t4": "aggressive", "t5": "insane"}
    key = shorthand.get(name.lower(), name.lower())
    if key not in TIMING_PROFILES:
        raise ValueError(
            f"Unknown timing profile {name!r}. "
            f"Choose from: {list(TIMING_PROFILES)}"
        )
    return TIMING_PROFILES[key]
