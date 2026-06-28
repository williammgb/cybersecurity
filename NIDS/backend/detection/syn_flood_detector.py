from __future__ import annotations
from collections import defaultdict
from typing import Dict, Iterable, List, Tuple
# Local imports
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from backend.detection.base import BaseDetector, WindowCounter, packet_ts


class SynFloodDetector(BaseDetector):
    """
    Detect likely SYN flood behavior using SYN/ACK imbalance ratio.
    Attacker sends many SYN packets, but rarely sends ACK packets.
    """
    name = "syn_flood_detector"

    def __init__(
        self,
        window_seconds: int = 15,
        min_syn_threshold: int = 40,
        min_syn_ack_ratio: float = 5.0,
    ) -> None:
        self.window_seconds = window_seconds
        self.min_syn_threshold = min_syn_threshold
        self.min_syn_ack_ratio = min_syn_ack_ratio
        self.syn_counts: Dict[Tuple[str, int], WindowCounter] = defaultdict(lambda: WindowCounter(window_seconds))
        self.ack_counts: Dict[Tuple[str, int], WindowCounter] = defaultdict(lambda: WindowCounter(window_seconds))
        self.last_alert_ts: Dict[Tuple[str, int], float] = {}

    def process(self, packet: Packet) -> Iterable[Alert]:
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return []

        ts = packet_ts(packet)
        ip = packet[IP]
        tcp = packet[TCP]
        key = (ip.dst, int(tcp.dport))

        # count SYN (0x02) and ACK (0x10) packets
        if tcp.flags & 0x02 and not (tcp.flags & 0x10):
            self.syn_counts[key].add(ts)
        if tcp.flags & 0x10:
            self.ack_counts[key].add(ts)

        syn_total = self.syn_counts[key].total(ts)
        ack_total = self.ack_counts[key].total(ts)
        ratio = syn_total / max(1, ack_total)

        if syn_total < self.min_syn_threshold or ratio < self.min_syn_ack_ratio:
            return []
        if not self._should_alert(key, ts):
            return []

        return [
            self.make_alert(
                attack_type="syn_flood",
                severity="critical",
                message=f"Likely SYN flood against {key[0]}:{key[1]} (SYN/ACK imbalance).",
                evidence={
                    "target_ip": key[0],
                    "target_port": key[1],
                    "syn_count_window": syn_total,
                    "ack_count_window": ack_total,
                    "syn_ack_ratio": round(ratio, 2),
                    "window_seconds": self.window_seconds,
                },
                ts=ts,
            )
        ]

    def _should_alert(self, key: Tuple[str, int], ts: float) -> bool:
        prev_ts = self.last_alert_ts.get(key)
        if prev_ts is not None and ts - prev_ts < self.window_seconds:
            return False
        self.last_alert_ts[key] = ts
        return True

