from __future__ import annotations
import math
import re
from collections import defaultdict, deque
from typing import Deque, Dict, Iterable, List, Tuple
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP
from scapy.packet import Packet
# local imports
from backend.detection.base import BaseDetector, packet_ts
from backend.traffic.common import dns_query_name

BASE32_RE = re.compile(r"^[A-Z2-7=]+$", re.IGNORECASE)
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def shannon_entropy(text: str) -> float:
    """
    Calculate the Shannon entropy (randomness) of a string.
    Encoded data in DNS queries means the query string has high entropy.
    """
    if not text:
        return 0.0
    frequencies = {ch: text.count(ch) / len(text) for ch in set(text)}
    return -sum(p * math.log2(p) for p in frequencies.values())


class DnsTunnelingDetector(BaseDetector):
    """Detect potential DNS tunneling and encoded data exfiltration via DNS queries."""
    name = "dns_tunneling_detector"

    def __init__(
        self,
        window_seconds: int = 30,
        query_rate_threshold: int = 40,
        label_len_threshold: int = 40,
        entropy_threshold: float = 4.0,
    ) -> None:
        self.window_seconds = window_seconds
        self.query_rate_threshold = query_rate_threshold
        self.label_len_threshold = label_len_threshold
        self.entropy_threshold = entropy_threshold
        self.by_src: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        self.last_alert_ts: Dict[str, float] = {}

    def process(self, packet: Packet) -> Iterable[Alert]:
        if not (packet.haslayer(IP) and packet.haslayer(DNS)):
            return []
        dns = packet[DNS]
        # ignore responses and non-DNS queries
        if dns.qr != 0 or not packet.haslayer(DNSQR):
            return []

        # Obtain packet information
        src_ip = packet[IP].src
        ts = packet_ts(packet)
        qname = dns_query_name(packet).rstrip(".").lower()
        if not qname:
            return []
        self.by_src[src_ip].append((ts, qname))
        self._prune(src_ip, ts)
        
        # Analyze the DNS query
        labels = [label for label in qname.split(".") if label]
        suspicious_labels = [label for label in labels if self._is_encoded_or_random(label)]
        rate = len(self.by_src[src_ip])
        max_label_len = max((len(label) for label in labels), default=0)
        high_entropy = any(shannon_entropy(label) >= self.entropy_threshold for label in labels)

        indicators = 0
        indicators += 1 if max_label_len >= self.label_len_threshold else 0
        indicators += 1 if high_entropy else 0
        indicators += 1 if bool(suspicious_labels) else 0
        # Alert either on very high rate or when repeated suspicious query structure appears.
        is_suspicious = rate >= self.query_rate_threshold or (rate >= 5 and indicators >= 2)
        if not is_suspicious or not self._should_alert(src_ip, ts):
            return []

        return [
            self.make_alert(
                attack_type="dns_tunneling",
                severity="high",
                message=f"Potential DNS tunneling pattern detected from {src_ip}.",
                evidence={
                    "src_ip": src_ip,
                    "query_rate_window": rate,
                    "window_seconds": self.window_seconds,
                    "max_label_length": max_label_len,
                    "high_entropy_detected": high_entropy,
                    "encoded_like_labels": suspicious_labels[:3],
                    "sample_qname": qname,
                },
                ts=ts,
            )
        ]

    def _prune(self, src_ip: str, now_ts: float) -> None:
        queue = self.by_src[src_ip]
        cutoff = now_ts - self.window_seconds
        while queue and queue[0][0] < cutoff:
            queue.popleft()

    def _should_alert(self, src_ip: str, ts: float) -> bool:
        prev_ts = self.last_alert_ts.get(src_ip)
        if prev_ts is not None and ts - prev_ts < self.window_seconds:
            return False
        self.last_alert_ts[src_ip] = ts
        return True

    @staticmethod
    def _is_encoded_or_random(label: str) -> bool:
        if len(label) < 16:
            return False
        return bool(BASE32_RE.match(label) or BASE64_RE.match(label) or HEX_RE.match(label))

