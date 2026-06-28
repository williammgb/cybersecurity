from __future__ import annotations

from typing import List

from scapy.packet import Packet

from backend.traffic.common import tcp_packet


def build_port_scan_traffic(
    horizontal_attacker_ip: str = "192.168.1.210",
    vertical_attacker_ip: str = "192.168.1.211",
    scan_type: str = "both",
    target_count: int = 35,
    subnet_base: str = "192.168.1",
) -> List[Packet]:
    """Simulate horizontal and/or vertical port scanning traffic using SYN packets."""
    valid_scan_types = {"horizontal", "vertical", "both"}
    if scan_type not in valid_scan_types:
        raise ValueError(f"Unknown port scan type: {scan_type}. Expected one of {sorted(valid_scan_types)}")

    packets: List[Packet] = []

    if scan_type in {"horizontal", "both"}:
        for host in range(10, 10 + target_count):
            packets.append(
                tcp_packet(horizontal_attacker_ip, f"{subnet_base}.{host}", 50000 + host, 22, flags="S")
            )

    if scan_type in {"vertical", "both"}:
        target = f"{subnet_base}.50"
        for port in range(20, 20 + min(target_count, 50)):
            packets.append(
                tcp_packet(vertical_attacker_ip, target, 51000 + port, port, flags="S")
            )

    return packets
