from __future__ import annotations
import ipaddress
from collections import defaultdict, deque
from statistics import mean, pstdev
from typing import Deque, Dict, Iterable, List, Tuple
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet
# local imports
from backend.detection.base import BaseDetector, packet_ts

LAB_DESTINATIONS = {"93.184.216.34", "8.8.8.8", "1.1.1.1"}


class BeaconingDetector(BaseDetector):
    """
    Detects beaconing flows by measuring average interval and jitter (stdev of intervals).
    Attackers use jitter to make their attacks look more random and avoid detection.
    """
    name = "beaconing_detector"

    def __init__(
        self,
        min_events: int = 6,
        max_jitter_seconds: float = 0.35,
        min_avg_interval_seconds: float = 5.0,
        max_avg_interval_seconds: float = 180.0,
        alert_cooldown_seconds: int = 120,
    ) -> None:
        self.min_events = min_events
        self.max_jitter_seconds = max_jitter_seconds
        self.min_avg_interval_seconds = min_avg_interval_seconds
        self.max_avg_interval_seconds = max_avg_interval_seconds
        self.alert_cooldown_seconds = alert_cooldown_seconds
        self.flow_timestamps: Dict[Tuple[str, str, int, int, str], Deque[float]] = defaultdict(deque)
        self.last_alert_ts: Dict[Tuple[str, str, int, int, str], float] = {}

    def process(self, packet: Packet) -> Iterable[Alert]:
        if not packet.haslayer(IP):
            return []

        ip = packet[IP]
        if not self._is_private(ip.src):
            return []
        if ip.dst in LAB_DESTINATIONS:
            return []

        sport = None
        port = None
        proto = None
        if packet.haslayer(TCP):
            sport = int(packet[TCP].sport)
            port = int(packet[TCP].dport)
            proto = "TCP"
        elif packet.haslayer(UDP):
            sport = int(packet[UDP].sport)
            port = int(packet[UDP].dport)
            proto = "UDP"
        else:
            return []

        # Maintains a queue of timestamps for each connection.
        ts = packet_ts(packet)
        key = (ip.src, ip.dst, sport, port, proto)
        queue = self.flow_timestamps[key]
        queue.append(ts)
        if len(queue) > 20:
            queue.popleft()
        if len(queue) < self.min_events:
            return []

        # Analyze the intervals between timestamps.
        intervals = [queue[idx] - queue[idx - 1] for idx in range(1, len(queue)) if queue[idx] - queue[idx - 1] > 0]
        if len(intervals) < self.min_events - 2:
            return []
        avg_interval = mean(intervals)
        jitter = pstdev(intervals) if len(intervals) > 1 else 0.0
        if (
            avg_interval < self.min_avg_interval_seconds
            or avg_interval > self.max_avg_interval_seconds
            or jitter > self.max_jitter_seconds
        ):
            return []
        if not self._should_alert(key, ts):
            return []

        return [
            self.make_alert(
                attack_type="beaconing",
                severity="medium",
                message=f"Possible beaconing flow {key[0]} -> {key[1]}:{key[3]} ({key[4]}).",
                evidence={
                    "src_ip": key[0],
                    "dst_ip": key[1],
                    "src_port": key[2],
                    "dst_port": key[3],
                    "protocol": key[4],
                    "sample_count": len(queue),
                    "avg_interval_seconds": round(avg_interval, 3),
                    "jitter_seconds": round(jitter, 3),
                },
                ts=ts,
            )
        ]

    @staticmethod
    def _is_private(ip_str: str) -> bool:
        try:
            return ipaddress.ip_address(ip_str).is_private
        except ValueError:
            return False

    def _should_alert(self, key: Tuple[str, str, int, int, str], ts: float) -> bool:
        prev_ts = self.last_alert_ts.get(key)
        if prev_ts is not None and ts - prev_ts < self.alert_cooldown_seconds:
            return False
        self.last_alert_ts[key] = ts
        return True
