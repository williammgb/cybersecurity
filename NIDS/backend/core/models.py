"""Shared dataclasses used across backend and GUI."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Alert:
    """Normalized alert produced by an attack detector."""

    detector: str
    attack_type: str
    severity: str
    message: str
    evidence: Dict[str, Any]
    ts: str
    packet_indices: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector": self.detector,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
            "timestamp": self.ts,
            "packet_indices": self.packet_indices,
        }


@dataclass
class TrafficConfig:
    """User-selected options for synthetic PCAP generation."""

    num_hosts: int = 3
    packets_per_host: int = 14
    subnet_base: str = "192.168.1"
    attack_scenarios: List[str] = field(default_factory=lambda: ["port_scan"])
    port_scan_type: str = "both"
    syn_count: int = 50
    dns_query_count: int = 20
    exfil_packet_count: int = 50
    beacon_count: int = 10
    output_path: Optional[str] = None
    random_seed: int = 42
    start_timestamp: float = 0.0
    benign_step_seconds: float = 0.25
    benign_jitter_seconds: float = 0.12
    attack_gap_seconds: float = 5.0
    attack_step_seconds: float = 0.25
    syn_flood_step_seconds: float = 0.05
    beacon_step_seconds: float = 10.0
    include_benign: bool = True
    ordering_mode: str = "sequential"
    mixed_benign_lead: int = 5
    arp_packet_count: int = 3


@dataclass
class DetectorConfig:
    """Per-detector threshold overrides for PCAP analysis."""

    port_scan_horizontal: Dict[str, Any] = field(
        default_factory=lambda: {"window_seconds": 20, "horizontal_threshold_unique_ips": 12}
    )
    port_scan_vertical: Dict[str, Any] = field(
        default_factory=lambda: {"window_seconds": 20, "vertical_threshold_unique_ports": 12}
    )
    syn_flood: Dict[str, Any] = field(
        default_factory=lambda: {"window_seconds": 15, "min_syn_threshold": 40, "min_syn_ack_ratio": 5.0}
    )
    dns_tunneling: Dict[str, Any] = field(
        default_factory=lambda: {
            "window_seconds": 30,
            "query_rate_threshold": 40,
            "label_len_threshold": 40,
            "entropy_threshold": 4.0,
        }
    )
    suspicious_payload: Dict[str, Any] = field(default_factory=lambda: {"window_seconds": 60})
    beaconing: Dict[str, Any] = field(
        default_factory=lambda: {
            "min_events": 6,
            "max_jitter_seconds": 0.35,
            "min_avg_interval_seconds": 5.0,
            "max_avg_interval_seconds": 180.0,
            "alert_cooldown_seconds": 120,
        }
    )
    data_exfiltration: Dict[str, Any] = field(
        default_factory=lambda: {
            "local_cidr": "192.168.0.0/16",
            "window_seconds": 60,
            "burst_bytes_threshold": 500_000,
        }
    )
    arp_spoofing: Dict[str, Any] = field(default_factory=lambda: {"window_seconds": 60})

    def to_dict(self) -> Dict[str, Dict[str, Any]]:
        return {
            "port_scan_horizontal": dict(self.port_scan_horizontal),
            "port_scan_vertical": dict(self.port_scan_vertical),
            "syn_flood": dict(self.syn_flood),
            "dns_tunneling": dict(self.dns_tunneling),
            "suspicious_payload": dict(self.suspicious_payload),
            "beaconing": dict(self.beaconing),
            "data_exfiltration": dict(self.data_exfiltration),
            "arp_spoofing": dict(self.arp_spoofing),
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "DetectorConfig":
        if not data:
            return cls()
        defaults = cls().to_dict()
        merged: Dict[str, Dict[str, Any]] = {}
        for key, default_values in defaults.items():
            incoming = data.get(key, {})
            merged[key] = {**default_values, **(incoming or {})}
        return cls(**merged)


@dataclass
class AnalysisResult:
    """Full output of a PCAP analysis run for the GUI."""

    rows: List[Dict[str, Any]]
    alerts: List[Alert] = field(default_factory=list)
    highlight_map: Dict[int, str] = field(default_factory=dict)
    pcap_path: str = ""
