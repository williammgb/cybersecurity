from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Set

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.packet import Packet

from backend.core.models import Alert, AnalysisResult, DetectorConfig
from backend.detection import (
    ArpSpoofingDetector,
    BeaconingDetector,
    DataExfiltrationDetector,
    DnsTunnelingDetector,
    PortScanHorizontalDetector,
    PortScanVerticalDetector,
    SuspiciousPayloadDetector,
    SynFloodDetector,
)
from backend.detection.base import BaseDetector

# Registry of all available detectors
DETECTOR_REGISTRY: Dict[str, type] = {
    "port_scan_horizontal": PortScanHorizontalDetector,
    "port_scan_vertical": PortScanVerticalDetector,
    "syn_flood": SynFloodDetector,
    "dns_tunneling": DnsTunnelingDetector,
    "suspicious_payload": SuspiciousPayloadDetector,
    "beaconing": BeaconingDetector,
    "data_exfiltration": DataExfiltrationDetector,
    "arp_spoofing": ArpSpoofingDetector,
}


class NIDSEngine:
    """Routes each observed packet through detectors and returns normalized alerts."""

    def __init__(self, detectors: Optional[List[BaseDetector]] = None) -> None:
        self.detectors = detectors if detectors is not None else self.default_detectors()

    @staticmethod
    def default_detectors() -> List[BaseDetector]:
        """Build all detectors from the registry."""
        return [cls() for cls in DETECTOR_REGISTRY.values()]

    @staticmethod
    def build_detectors(
        enabled: Optional[List[str]] = None,
        detector_config: Optional[DetectorConfig] = None,
    ) -> List[BaseDetector]:
        """Only activate the detectors that are given in the enabled list."""
        if enabled is None:
            return NIDSEngine.default_detectors()
        config = detector_config or DetectorConfig()
        config_map = config.to_dict()
        detectors: List[BaseDetector] = []
        for name in enabled:
            cls = DETECTOR_REGISTRY.get(name)
            if cls is not None:
                kwargs = config_map.get(name, {})
                detectors.append(cls(**kwargs))
        return detectors

    def process_packet(self, packet: Packet) -> List[Alert]:
        """Run one packet through all detectors and return collected alerts."""
        collected: List[Alert] = []
        for detector in self.detectors:
            for alert in detector.process(packet):
                collected.append(alert)
        return collected

    def analyze_packets(
        self,
        packets: List[Packet],
        enabled_detectors: Optional[List[str]] = None,
        detector_config: Optional[DetectorConfig] = None,
    ) -> AnalysisResult:
        """Replay packets silently and return alerts with row highlight mapping."""
        # Step 1: Use only the detectors the caller enabled.
        engine = NIDSEngine(
            detectors=self.build_detectors(enabled_detectors, detector_config=detector_config)
        )
        alerts: List[Alert] = []
        highlight_map: Dict[int, str] = {}

        for index, packet in enumerate(packets):
            for alert in engine.process_packet(packet):
                matched = _match_alert_indices(alert, packets, index)
                alert.packet_indices = matched
                alerts.append(alert)
                for row_index in matched:
                    highlight_map[row_index] = "attack"

        return AnalysisResult(rows=[], alerts=alerts, highlight_map=highlight_map)


def _is_pure_syn(packet: Packet) -> bool:
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return False
    tcp = packet[TCP]
    return bool(tcp.flags & 0x02) and not (tcp.flags & 0x10)


def _is_local_ip(ip_str: str, local_cidr: str = "192.168.0.0/16") -> bool:
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(local_cidr, strict=False)
    except ValueError:
        return False


def _match_alert_indices(alert: Alert, packets: List[Packet], trigger_index: int) -> List[int]:
    """Map an alert to packet row indices using attack-specific AND constraints."""
    evidence = alert.evidence
    attack_type = alert.attack_type
    indices: Set[int] = {trigger_index}

    if attack_type == "syn_flood":
        target_ip = evidence.get("target_ip")
        target_port = evidence.get("target_port")
        for index, packet in enumerate(packets):
            if not (packet.haslayer(IP) and packet.haslayer(TCP)):
                continue
            ip = packet[IP]
            tcp = packet[TCP]
            if target_ip and ip.dst != target_ip:
                continue
            if target_port is not None and int(tcp.dport) != int(target_port):
                continue
            if _is_pure_syn(packet):
                indices.add(index)

    elif attack_type == "port_scan_horizontal":
        src_ip = evidence.get("src_ip")
        target_port = evidence.get("target_port")
        for index, packet in enumerate(packets):
            if not (packet.haslayer(IP) and packet.haslayer(TCP)):
                continue
            ip = packet[IP]
            tcp = packet[TCP]
            if src_ip and ip.src != src_ip:
                continue
            if target_port is not None and int(tcp.dport) != int(target_port):
                continue
            if _is_pure_syn(packet):
                indices.add(index)

    elif attack_type == "port_scan_vertical":
        src_ip = evidence.get("src_ip")
        target_ip = evidence.get("target_ip")
        for index, packet in enumerate(packets):
            if not (packet.haslayer(IP) and packet.haslayer(TCP)):
                continue
            ip = packet[IP]
            if src_ip and ip.src != src_ip:
                continue
            if target_ip and ip.dst != target_ip:
                continue
            if _is_pure_syn(packet):
                indices.add(index)

    elif attack_type == "beaconing":
        src_ip = evidence.get("src_ip")
        dst_ip = evidence.get("dst_ip")
        dst_port = evidence.get("dst_port")
        protocol = evidence.get("protocol")
        for index, packet in enumerate(packets):
            if not packet.haslayer(IP):
                continue
            ip = packet[IP]
            if src_ip and ip.src != src_ip:
                continue
            if dst_ip and ip.dst != dst_ip:
                continue
            packet_port = None
            packet_proto = None
            if packet.haslayer(TCP):
                packet_port = int(packet[TCP].dport)
                packet_proto = "TCP"
            elif packet.haslayer(UDP):
                packet_port = int(packet[UDP].dport)
                packet_proto = "UDP"
            else:
                continue
            if dst_port is not None and packet_port != int(dst_port):
                continue
            if protocol and packet_proto != protocol:
                continue
            indices.add(index)

    elif attack_type == "dns_tunneling":
        src_ip = evidence.get("src_ip")
        for index, packet in enumerate(packets):
            if not (packet.haslayer(IP) and packet.haslayer(DNS)):
                continue
            if src_ip and packet[IP].src != src_ip:
                continue
            indices.add(index)

    elif attack_type == "data_exfiltration":
        src_ip = evidence.get("src_ip")
        sample_dst = evidence.get("sample_external_dst")
        for index, packet in enumerate(packets):
            if not packet.haslayer(IP):
                continue
            ip = packet[IP]
            if src_ip and ip.src != src_ip:
                continue
            if not _is_local_ip(ip.src) or _is_local_ip(ip.dst):
                continue
            if sample_dst and ip.dst != sample_dst:
                continue
            indices.add(index)

    elif attack_type == "suspicious_payload":
        src_ip = evidence.get("src_ip")
        dst_ip = evidence.get("dst_ip")
        for index, packet in enumerate(packets):
            if not packet.haslayer(IP):
                continue
            ip = packet[IP]
            if src_ip and ip.src != src_ip:
                continue
            if dst_ip and ip.dst != dst_ip:
                continue
            indices.add(index)

    elif attack_type == "arp_spoofing":
        claimed_ip = evidence.get("claimed_ip")
        for index, packet in enumerate(packets):
            if not packet.haslayer(ARP):
                continue
            if claimed_ip and str(packet[ARP].psrc) == claimed_ip:
                indices.add(index)

    return sorted(indices)
