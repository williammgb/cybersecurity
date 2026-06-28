from __future__ import annotations

from typing import List

from scapy.packet import Packet

from backend.traffic.common import tcp_packet


def build_beaconing_traffic(
    agent_ip: str = "192.168.1.204",
    c2_ip: str = "45.9.148.20",
    dport: int = 443,
    beacon_count: int = 10,
) -> List[Packet]:
    """Generate periodic traffic that resembles C2 beaconing check-ins."""
    packets: List[Packet] = []

    # Step 1: Emit evenly spaced check-in payloads to the same C2 endpoint.
    for idx in range(beacon_count):
        packets.append(tcp_packet(agent_ip, c2_ip, 62000, dport, flags="PA", payload=b"checkin=ok"))

    return packets
