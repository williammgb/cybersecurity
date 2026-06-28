from __future__ import annotations
from typing import List
from scapy.packet import Packet
# local imports
from backend.traffic.common import arp_claim_packet


def build_arp_spoofing_traffic(
    claimed_ip: str = "192.168.1.1",
    packet_count: int = 3,
    requester_ip: str = "192.168.1.100",
) -> List[Packet]:
    """Generate conflicting ARP claims for spoofing simulation."""
    packets: List[Packet] = []
    count = max(2, packet_count)
    for idx in range(count):
        mac = f"de:ad:be:ef:00:{idx + 1:02x}"
        packets.append(arp_claim_packet(claimed_ip, mac, requester_ip))
    return packets
