"""Extract display-friendly fields from Scapy packets for the GUI table."""

from __future__ import annotations

from typing import Any, Dict

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

from backend.traffic.common import dns_query_name


def extract_row(packet: Packet, index: int) -> Dict[str, Any]:
    """Build one table row dict from a Scapy packet."""
    row: Dict[str, Any] = {
        "index": index,
        "time": round(float(getattr(packet, "time", 0)), 3),
        "length": len(packet),
        "ip_src": "",
        "ip_dst": "",
        "protocol": "",
        "src_port": "",
        "dst_port": "",
        "tcp_flags": "",
        "dns_qname": "",
        "payload_preview": "",
        "highlight": "",
        "mac_src": "",
        "mac_dst": "",
    }

    if packet.haslayer(Ether):
        row["mac_src"] = packet[Ether].src
        row["mac_dst"] = packet[Ether].dst

    if packet.haslayer(IP):
        row["ip_src"] = packet[IP].src
        row["ip_dst"] = packet[IP].dst

    if packet.haslayer(TCP):
        row["protocol"] = "TCP"
        row["src_port"] = int(packet[TCP].sport)
        row["dst_port"] = int(packet[TCP].dport)
        row["tcp_flags"] = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        row["protocol"] = "UDP"
        row["src_port"] = int(packet[UDP].sport)
        row["dst_port"] = int(packet[UDP].dport)

    if packet.haslayer(DNS):
        qname = dns_query_name(packet)
        if qname:
            row["protocol"] = "DNS"
            row["dns_qname"] = qname.rstrip(".")

    if packet.haslayer(ARP):
        row["protocol"] = "ARP"
        row["ip_src"] = packet[ARP].psrc
        row["ip_dst"] = packet[ARP].pdst

    if packet.haslayer(Raw):
        preview = bytes(packet[Raw].load)[:60]
        row["payload_preview"] = preview.decode("utf-8", errors="replace")

    return row
