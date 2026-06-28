from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Iterable, Optional, Tuple

from scapy.packet import Packet

from backend.core.models import Alert


def iso_timestamp(ts: Optional[float] = None) -> str:
    """Return an ISO 8601 timestamp with UTC timezone."""
    current = datetime.now(timezone.utc) if ts is None else datetime.fromtimestamp(ts, timezone.utc)
    return current.isoformat()


def packet_ts(packet: Packet) -> float:
    """Extract packet timestamp; fallback to current time for synthetic packets."""
    try:
        return float(packet.time)
    except Exception:
        return datetime.now(timezone.utc).timestamp()


class WindowCounter:
    """Keeps a count of events that happened within a sliding window."""

    def __init__(self, window_seconds: int) -> None:
        self.window_seconds = window_seconds
        self._events: Deque[Tuple[float, int]] = deque()
        self._sum = 0

    def add(self, ts: float, amount: int = 1) -> None:
        self._events.append((ts, amount))
        self._sum += amount
        self.prune(ts)

    def prune(self, now_ts: float) -> None:
        cutoff = now_ts - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            _, amount = self._events.popleft()
            self._sum -= amount

    def total(self, now_ts: float) -> int:
        self.prune(now_ts)
        return self._sum


class BaseDetector(ABC):
    """Base detector contract used by the NIDS engine."""

    name: str = "base_detector"

    @abstractmethod
    def process(self, packet: Packet) -> Iterable[Alert]:
        """Process one packet and return zero or more alerts."""

    def make_alert(
        self,
        attack_type: str,
        severity: str,
        message: str,
        evidence: Dict[str, Any],
        ts: Optional[float] = None,
    ) -> Alert:
        """Convert detector information into an Alert object."""
        return Alert(
            detector=self.name,
            attack_type=attack_type,
            severity=severity,
            message=message,
            evidence=evidence,
            ts=iso_timestamp(ts),
        )
