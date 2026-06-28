from __future__ import annotations

from typing import List

from scapy.packet import Packet

from backend.traffic.common import tcp_packet


def build_data_exfiltration_traffic(
    src_ip: str = "192.168.1.205",
    dst_ip: str = "198.51.100.45",
    packet_count: int = 50,
) -> List[Packet]:
    """Generate large outbound payload packets for exfiltration simulation."""
    packets: List[Packet] = []
    # ~10 KB application data so 50 packets exceed the 500 KB detector window.
    chunk = b"A" * 10050

    # Step 1: Send many large TCP payloads from an internal host to an external IP.
    for idx in range(packet_count):
        packets.append(tcp_packet(src_ip, dst_ip, 63000 + (idx % 1000), 443, flags="PA", payload=chunk))

    return packets
