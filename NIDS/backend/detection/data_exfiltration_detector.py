from __future__ import annotations
import ipaddress
from collections import defaultdict
from typing import Dict, Iterable, List
from scapy.layers.inet import IP
from scapy.packet import Packet
# local imports
from backend.detection.base import BaseDetector, WindowCounter, packet_ts


class DataExfiltrationDetector(BaseDetector):
    """Detects unusually large outbound traffic."""
    name = "data_exfiltration_detector"

    def __init__(
        self,
        local_cidr: str = "192.168.0.0/16",
        window_seconds: int = 60,
        burst_bytes_threshold: int = 500_000,
    ) -> None:
        self.local_net = ipaddress.ip_network(local_cidr, strict=False)
        self.window_seconds = window_seconds
        self.burst_bytes_threshold = burst_bytes_threshold
        self.outbound_by_src: Dict[str, WindowCounter] = defaultdict(lambda: WindowCounter(window_seconds))
        self.last_alert_ts: Dict[str, float] = {}

    def process(self, packet: Packet) -> Iterable[Alert]:
        if not packet.haslayer(IP):
            return []
        ip = packet[IP]
        if not self._is_local(ip.src) or self._is_local(ip.dst):
            return []

        ts = packet_ts(packet)
        size = len(packet)
        self.outbound_by_src[ip.src].add(ts, amount=size)
        outbound_window = self.outbound_by_src[ip.src].total(ts)

        if outbound_window < self.burst_bytes_threshold:
            return []
        if not self._should_alert(ip.src, ts):
            return []

        return [
            self.make_alert(
                attack_type="data_exfiltration",
                severity="high",
                message=f"High outbound data volume from {ip.src} to external destinations.",
                evidence={
                    "src_ip": ip.src,
                    "sample_external_dst": ip.dst,
                    "outbound_bytes_window": outbound_window,
                    "window_seconds": self.window_seconds,
                    "threshold_bytes": self.burst_bytes_threshold,
                },
                ts=ts,
            )
        ]

    def _is_local(self, ip_str: str) -> bool:
        try:
            return ipaddress.ip_address(ip_str) in self.local_net
        except ValueError:
            return False

    def _should_alert(self, src_ip: str, ts: float) -> bool:
        prev_ts = self.last_alert_ts.get(src_ip)
        if prev_ts is not None and ts - prev_ts < self.window_seconds:
            return False
        self.last_alert_ts[src_ip] = ts
        return True

