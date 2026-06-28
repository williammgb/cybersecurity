from __future__ import annotations
import re
from typing import Dict, Iterable, List, Pattern, Set, Tuple
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw
# local imports
from backend.detection.base import BaseDetector, packet_ts


class SuspiciousPayloadDetector(BaseDetector):
    """
    Detect suspicious plaintext payload patterns in observable traffic.
    Checks payload for common command injection and malware indicators.
    """
    name = "suspicious_payload_detector"

    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds
        self.signatures: List[Tuple[str, Pattern[str]]] = [
            ("cmd_injection_semicolon", re.compile(r"(;|\|\||&&)\s*(curl|wget|powershell|cmd\.exe|bash)\b", re.I)),
            ("cmd_injection_subshell", re.compile(r"(\$\(|`[^`]+`)", re.I)),
            ("path_traversal", re.compile(r"\.\./\.\./|/etc/passwd|system32", re.I)),
            ("download_execute", re.compile(r"(certutil|bitsadmin|mshta|rundll32)\b", re.I)),
            ("reverse_shell", re.compile(r"(nc\s+-e|bash\s+-i|/dev/tcp/)", re.I)),
        ]
        self.last_alert_ts: Dict[Tuple[str, str], float] = {}
        self.flow_signatures: Dict[Tuple[str, str], Set[str]] = {}
        self.flow_previews: Dict[Tuple[str, str], List[str]] = {}
        self.flow_packet_count: Dict[Tuple[str, str], int] = {}

    def process(self, packet: Packet) -> Iterable[Alert]:
        if not (packet.haslayer(IP) and packet.haslayer(Raw)):
            return []
        payload = bytes(packet[Raw].load)
        if not payload:
            return []

        decoded = payload.decode("utf-8", errors="ignore")
        findings = [name for name, pattern in self.signatures if pattern.search(decoded)]
        if not findings:
            return []

        ip = packet[IP]
        flow_key = (ip.src, ip.dst)
        ts = packet_ts(packet)

        self.flow_signatures.setdefault(flow_key, set()).update(findings)
        previews = self.flow_previews.setdefault(flow_key, [])
        if len(previews) < 3:
            previews.append(decoded[:120])
        self.flow_packet_count[flow_key] = self.flow_packet_count.get(flow_key, 0) + 1

        if not self._should_alert(flow_key, ts):
            return []

        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "UNKNOWN"
        evidence = {
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "protocol": proto,
            "matched_signatures": sorted(self.flow_signatures[flow_key]),
            "packet_count": self.flow_packet_count[flow_key],
            "payload_previews": list(self.flow_previews[flow_key]),
            "note": "Payload inspection works only for plaintext-visible traffic; encrypted sessions hide content.",
        }
        return [
            self.make_alert(
                attack_type="suspicious_payload",
                severity="medium",
                message=f"Suspicious plaintext payload pattern from {ip.src} to {ip.dst}.",
                evidence=evidence,
                ts=ts,
            )
        ]

    def _should_alert(self, flow_key: Tuple[str, str], ts: float) -> bool:
        prev_ts = self.last_alert_ts.get(flow_key)
        if prev_ts is not None and ts - prev_ts < self.window_seconds:
            return False
        self.last_alert_ts[flow_key] = ts
        return True
