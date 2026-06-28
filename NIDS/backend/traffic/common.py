"""Shared helpers for synthetic traffic generation and PCAP export."""

from __future__ import annotations

import backend.scapy_quiet  # noqa: F401
import random
from typing import Iterable, List

from scapy.config import conf
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

# Step 1: Disable verbose Scapy output for synthetic packet construction.
conf.verb = 0

# Step 2: Fixed MAC addresses avoid getmacbyip() lookups when building synthetic frames.
_LAB_SRC_MAC = "00:11:22:33:44:55"
_LAB_DST_MAC = "aa:bb:cc:dd:ee:ff"
_LAB_GW_MAC = "00:aa:bb:cc:dd:01"


def _ether_frame() -> Ether:
    """Return a pre-filled Ethernet header for offline synthetic packets."""
    return Ether(src=_LAB_SRC_MAC, dst=_LAB_DST_MAC)


def write_pcap(path: str, packets: Iterable[Packet]) -> None:
    """Write generated packets to a pcap file."""
    packet_list = list(packets)
    wrpcap(path, packet_list)


def stamp_packets(packets: Iterable[Packet], start_ts: float, step_seconds: float) -> None:
    """Set deterministic packet timestamps for replay-friendly timing behavior."""
    ts = start_ts
    for packet in packets:
        packet.time = ts
        ts += step_seconds


def stamp_packets_jittered(
    packets: Iterable[Packet],
    start_ts: float,
    step_seconds: float,
    jitter_seconds: float = 0.12,
    seed: int = 42,
) -> None:
    """Stamp packets with small random jitter to avoid perfectly periodic flows."""
    rng = random.Random(seed)
    ts = start_ts
    for packet in packets:
        packet.time = ts
        ts += step_seconds + rng.uniform(-jitter_seconds, jitter_seconds)
        if ts <= packet.time:
            ts = packet.time + 0.01


def normalize_timestamps(packets: List[Packet]) -> None:
    """Shift all packet times so the earliest packet starts at 0.0."""
    if not packets:
        return
    base_ts = min(float(getattr(packet, "time", 0.0)) for packet in packets)
    for packet in packets:
        packet.time = float(getattr(packet, "time", 0.0)) - base_ts


def interleave_packets(
    benign: List[Packet],
    attacks: List[Packet],
    seed: int = 42,
    benign_lead: int = 0,
) -> List[Packet]:
    """Randomly interleave benign packets between attack packets."""
    lead_count = max(0, min(benign_lead, len(benign)))
    mixed: List[Packet] = list(benign[:lead_count])
    remaining_benign = benign[lead_count:]

    rng = random.Random(seed)
    bi, ai = 0, 0
    while ai < len(attacks) or bi < len(remaining_benign):
        if ai < len(attacks):
            mixed.append(attacks[ai])
            ai += 1
        if bi < len(remaining_benign):
            burst = rng.randint(0, min(4, len(remaining_benign) - bi))
            mixed.extend(remaining_benign[bi : bi + burst])
            bi += burst
    mixed.extend(remaining_benign[bi:])
    return mixed


def max_packet_time(packets: List[Packet]) -> float:
    """Return the latest timestamp among packets, or 0.0 when empty."""
    if not packets:
        return 0.0
    return max(float(getattr(packet, "time", 0.0)) for packet in packets)


def dns_query_name(packet: Packet) -> str:
    """Extract the queried domain name from a DNS query packet."""
    if not packet.haslayer(DNS):
        return ""
    dns = packet[DNS]
    if int(getattr(dns, "qr", 0)) != 0:
        return ""
    qname_raw = None
    if packet.haslayer(DNSQR):
        qname_raw = packet[DNSQR].qname
    elif dns.qd is not None:
        try:
            qname_raw = dns.qd[0].qname  # type: ignore[index]
        except (IndexError, TypeError, AttributeError):
            return ""
    if qname_raw is None:
        return ""
    if isinstance(qname_raw, bytes):
        return qname_raw.decode("utf-8", errors="replace")
    return str(qname_raw)


def tcp_packet(src_ip: str, dst_ip: str, sport: int, dport: int, flags: str = "S", payload: bytes = b"") -> Packet:
    """Create a TCP packet with explicit L2 headers (no live interface lookup)."""
    packet = _ether_frame() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        packet = packet / Raw(load=payload)
    return packet


def udp_packet(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes = b"") -> Packet:
    """Create a UDP packet with explicit L2 headers (no live interface lookup)."""
    packet = _ether_frame() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
    if payload:
        packet = packet / Raw(load=payload)
    return packet


def dns_query_packet(src_ip: str, dst_ip: str, qname: str, sport: int = 53000) -> Packet:
    """Create a DNS query packet; rd=1 requests recursive resolution from the resolver."""
    return (
        _ether_frame()
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname))
    )


def arp_claim_packet(src_ip: str, src_mac: str, requester_ip: str) -> Packet:
    """Create an ARP reply (op=2) claiming an IP-to-MAC mapping."""
    return Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, psrc=src_ip, hwsrc=src_mac, pdst=requester_ip, hwdst=_LAB_GW_MAC
    )
