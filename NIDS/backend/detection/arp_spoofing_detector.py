from __future__ import annotations
from collections import defaultdict, deque
from typing import Deque, Dict, Iterable, List, Tuple
from scapy.layers.l2 import ARP
from scapy.packet import Packet
from backend.detection.base import BaseDetector, packet_ts


class ArpSpoofingDetector(BaseDetector):
    """Raise alerts when one IP claims multiple MAC addresses in a short period."""
    name = "arp_spoofing_detector"

    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds
        self.claims_by_ip: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        self.last_alert_ts: Dict[str, float] = {}

    def process(self, packet: Packet) -> Iterable[Alert]:
        """
        Process an ARP packet and return alerts if it's a spoofing attempt 
        (e.g., one IP claims multiple MAC addresses in a short period).
        """
        if not packet.haslayer(ARP):
            return []
        arp = packet[ARP]
        # filter for only ARP request or reply
        if int(arp.op) not in (1, 2):
            return []

        # Obtain the IP and MAC address from the ARP packet and store it.
        ip = str(arp.psrc)
        mac = str(arp.hwsrc).lower()
        ts = packet_ts(packet)
        queue = self.claims_by_ip[ip]
        queue.append((ts, mac))
        self._prune(queue, ts)
        unique_macs = sorted({entry_mac for _, entry_mac in queue})

        if len(unique_macs) < 2 or not self._should_alert(ip, ts):
            return []

        confidence = "medium" if len(unique_macs) == 2 else "high"
        return [
            self.make_alert(
                attack_type="arp_spoofing",
                severity=confidence,
                message=f"Potential ARP spoofing: {ip} observed with multiple MAC addresses.",
                evidence={
                    "claimed_ip": ip,
                    "mac_addresses_seen": unique_macs,
                    "window_seconds": self.window_seconds,
                    "note": "Multiple MACs can occur during DHCP churn, but rapid switch is suspicious.",
                },
                ts=ts,
            )
        ]

    def _prune(self, queue: Deque[Tuple[float, str]], now_ts: float) -> None:
        """Remove old entries (older than window_seconds) from the queue to keep it manageable."""
        cutoff = now_ts - self.window_seconds
        while queue and queue[0][0] < cutoff:
            queue.popleft()

    def _should_alert(self, ip: str, ts: float) -> bool:
        """
        Check if we should alert for this IP based on the last alert timestamp.
        If the last alert for this IP was less than window_seconds ago, don't alert again.
        """
        prev_ts = self.last_alert_ts.get(ip)
        if prev_ts is not None and ts - prev_ts < self.window_seconds:
            return False
        self.last_alert_ts[ip] = ts
        return True

