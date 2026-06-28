from __future__ import annotations

from typing import List

from scapy.packet import Packet

from backend.traffic.common import tcp_packet


def build_syn_flood_traffic(
    attacker_ip: str = "192.168.1.201",
    victim_ip: str = "192.168.1.60",
    victim_port: int = 80,
    syn_count: int = 50,
) -> List[Packet]:
    """Generate SYN flood traffic with minimal ACK completion."""
    packets: List[Packet] = []

    # Step 1: Send many SYN packets with different source ports (half-open connections).
    for idx in range(syn_count):
        packets.append(tcp_packet(attacker_ip, victim_ip, 32000 + idx, victim_port, flags="S"))

    # Step 2: Add a few ACK packets to create an unrealistic SYN/ACK ratio.
    for idx in range(5):
        packets.append(tcp_packet(attacker_ip, victim_ip, 42000 + idx, victim_port, flags="A"))

    return packets
