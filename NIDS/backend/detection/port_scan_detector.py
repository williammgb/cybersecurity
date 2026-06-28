from __future__ import annotations
from collections import defaultdict, deque
from typing import Deque, Dict, Iterable, List, Set, Tuple
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
# local imports
from backend.detection.base import BaseDetector, packet_ts


class _PortScanTracker:
    """Shared SYN scan event tracking for horizontal and vertical detectors."""

    def __init__(self, window_seconds: int = 20) -> None:
        self.window_seconds = window_seconds
        self.by_src: Dict[str, Deque[Tuple[float, str, str, int]]] = defaultdict(deque)
        self.last_alert_key: Dict[Tuple[str, str], float] = {}

    def track(self, packet: Packet) -> Tuple[float, str, str, int] | None:
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return None
        tcp = packet[TCP]
        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
            return None
        ts = packet_ts(packet)
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dport = int(tcp.dport)
        events = self.by_src[src_ip]
        events.append((ts, src_ip, dst_ip, dport))
        self._prune(events, ts)
        return ts, src_ip, dst_ip, dport

    def _prune(self, events: Deque[Tuple[float, str, str, int]], now_ts: float) -> None:
        cutoff = now_ts - self.window_seconds
        while events and events[0][0] < cutoff:
            events.popleft()

    def _should_alert(self, key: Tuple[str, str], ts: float) -> bool:
        prev_ts = self.last_alert_key.get(key)
        if prev_ts is not None and ts - prev_ts < self.window_seconds:
            return False
        self.last_alert_key[key] = ts
        return True


class PortScanHorizontalDetector(BaseDetector):
    """Detect horizontal port scans: one port probed across many destination IPs."""

    name = "port_scan_horizontal_detector"

    def __init__(
        self,
        window_seconds: int = 20,
        horizontal_threshold_unique_ips: int = 12,
    ) -> None:
        self.tracker = _PortScanTracker(window_seconds)
        self.horizontal_threshold_unique_ips = horizontal_threshold_unique_ips

    def process(self, packet: Packet) -> Iterable[Alert]:
        tracked = self.tracker.track(packet)
        if tracked is None:
            return []
        ts, src_ip, _, _ = tracked
        events = self.tracker.by_src[src_ip]
        horizontal_map: Dict[int, Set[str]] = defaultdict(set)
        for _, _, event_dst_ip, event_dport in events:
            horizontal_map[event_dport].add(event_dst_ip)

        alerts: List[Alert] = []
        for port, ips in horizontal_map.items():
            if len(ips) >= self.horizontal_threshold_unique_ips and self.tracker._should_alert((src_ip, f"h:{port}"), ts):
                alerts.append(
                    self.make_alert(
                        attack_type="port_scan_horizontal",
                        severity="high",
                        message=f"Possible horizontal scan from {src_ip} targeting port {port}.",
                        evidence={
                            "src_ip": src_ip,
                            "target_port": port,
                            "unique_destination_ips": len(ips),
                            "window_seconds": self.tracker.window_seconds,
                        },
                        ts=ts,
                    )
                )
        return alerts


class PortScanVerticalDetector(BaseDetector):
    """Detect vertical port scans: many ports probed on one destination IP."""

    name = "port_scan_vertical_detector"

    def __init__(
        self,
        window_seconds: int = 20,
        vertical_threshold_unique_ports: int = 12,
    ) -> None:
        self.tracker = _PortScanTracker(window_seconds)
        self.vertical_threshold_unique_ports = vertical_threshold_unique_ports

    def process(self, packet: Packet) -> Iterable[Alert]:
        tracked = self.tracker.track(packet)
        if tracked is None:
            return []
        ts, src_ip, _, _ = tracked
        events = self.tracker.by_src[src_ip]
        vertical_map: Dict[str, Set[int]] = defaultdict(set)
        for _, _, event_dst_ip, event_dport in events:
            vertical_map[event_dst_ip].add(event_dport)

        alerts: List[Alert] = []
        for target_ip, ports in vertical_map.items():
            if len(ports) >= self.vertical_threshold_unique_ports and self.tracker._should_alert((src_ip, f"v:{target_ip}"), ts):
                alerts.append(
                    self.make_alert(
                        attack_type="port_scan_vertical",
                        severity="high",
                        message=f"Possible vertical scan from {src_ip} against {target_ip}.",
                        evidence={
                            "src_ip": src_ip,
                            "target_ip": target_ip,
                            "unique_destination_ports": len(ports),
                            "window_seconds": self.tracker.window_seconds,
                        },
                        ts=ts,
                    )
                )
        return alerts
