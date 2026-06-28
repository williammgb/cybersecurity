"""Run PCAP analysis with attack detectors."""

from __future__ import annotations

from typing import List, Optional

from scapy.packet import Packet
from scapy.utils import PcapReader

from backend.core.engine import NIDSEngine
from backend.core.features import extract_row
from backend.core.models import AnalysisResult, DetectorConfig
from backend.core.log_util import log
from backend.traffic.common import normalize_timestamps


def run_analysis(
    pcap_path: str,
    enabled_attacks: Optional[List[str]] = None,
    detector_config: Optional[DetectorConfig] = None,
) -> AnalysisResult:
    """Load a PCAP and return table rows plus alerts."""
    log(f"Analysis start: pcap={pcap_path}, detectors={enabled_attacks}")
    packets = _load_pcap(pcap_path)
    normalize_timestamps(packets)
    log(f"Loaded {len(packets)} packets from PCAP")

    rows = [extract_row(packet, index) for index, packet in enumerate(packets)]

    engine = NIDSEngine()
    attack_result = engine.analyze_packets(
        packets,
        enabled_detectors=enabled_attacks,
        detector_config=detector_config,
    )

    for row_index, kind in attack_result.highlight_map.items():
        if 0 <= row_index < len(rows):
            rows[row_index]["highlight"] = kind

    log(f"Attack analysis done: {len(attack_result.alerts)} alerts, {len(attack_result.highlight_map)} highlighted rows")
    return AnalysisResult(
        rows=rows,
        alerts=attack_result.alerts,
        highlight_map=attack_result.highlight_map,
        pcap_path=pcap_path,
    )


def _load_pcap(pcap_path: str) -> List[Packet]:
    """Read every packet from a PCAP file."""
    packets: List[Packet] = []
    with PcapReader(pcap_path) as reader:
        for packet in reader:
            packets.append(packet)
    return packets
