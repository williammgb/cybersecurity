from __future__ import annotations

import random
from typing import List

from scapy.packet import Packet

from backend.traffic.common import arp_claim_packet, dns_query_packet, tcp_packet, udp_packet

_EXTERNAL_HTTPS = ("93.184.216.34", "198.51.100.10", "203.0.113.50")
_DNS_RESOLVERS = ("8.8.8.8", "1.1.1.1", "9.9.9.9")
_UDP_SERVICES = ((123, b""), (53, b""), (443, b"\x16\x03\x01\x00"))
_HTTP_PATHS = (b"/", b"/index.html", b"/api/v1/status", b"/favicon.ico", b"/health")
_HTTP_METHODS = (b"GET", b"HEAD", b"POST")
_DNS_LABELS = ("www", "mail", "api", "cdn", "static", "auth", "dev", "staging")
_DNS_ZONES = ("example.com", "example.org", "corp.local", "services.net", "cloud.lab")


def build_normal_traffic(
    num_hosts: int = 3,
    packets_per_host: int = 14,
    subnet_base: str = "192.168.1",
    random_seed: int = 42,
) -> List[Packet]:
    """Generate varied benign background traffic with randomized flows and payloads."""
    rng = random.Random(random_seed)
    packets: List[Packet] = []
    host_ips = [f"{subnet_base}.{10 + idx}" for idx in range(num_hosts)]

    for host_idx, host_ip in enumerate(host_ips):
        for pkt_idx in range(packets_per_host):
            sport_base = host_idx * 10000 + pkt_idx * 17 + rng.randint(0, 9)
            packets.append(_random_benign_packet(rng, host_ip, host_ips, sport_base))

            if rng.random() < 0.35:
                packets.append(_random_benign_packet(rng, host_ip, host_ips, sport_base + rng.randint(1, 50)))

    packets.append(arp_claim_packet(f"{subnet_base}.1", "aa:bb:cc:dd:ee:01", f"{subnet_base}.100"))
    rng.shuffle(packets)
    return packets


def _random_benign_packet(
    rng: random.Random,
    host_ip: str,
    host_ips: List[str],
    sport_base: int,
) -> Packet:
    kind = rng.choice(("http", "http", "dns", "udp", "internal", "ack"))
    sport = 40000 + (sport_base % 20000)

    if kind == "http":
        dst_ip = rng.choice(_EXTERNAL_HTTPS)
        dport = rng.choice((443, 443, 80, 8080))
        method = rng.choice(_HTTP_METHODS)
        path = rng.choice(_HTTP_PATHS)
        host_header = dst_ip.encode()
        if method == b"POST":
            body = rng.choice((b"ping=1", b"status=ok", b"action=sync"))
            payload = (
                f"{method.decode()} {path.decode()} HTTP/1.1\r\n"
                f"Host: {host_header.decode()}\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            ).encode() + body
        else:
            payload = f"{method.decode()} {path.decode()} HTTP/1.1\r\nHost: {host_header.decode()}\r\n\r\n".encode()
        return tcp_packet(host_ip, dst_ip, sport, dport, flags="PA", payload=payload)

    if kind == "dns":
        label = rng.choice(_DNS_LABELS)
        zone = rng.choice(_DNS_ZONES)
        suffix = rng.randint(1, 9999)
        qname = f"{label}{suffix}.{zone}"
        return dns_query_packet(host_ip, rng.choice(_DNS_RESOLVERS), qname, sport=sport)

    if kind == "udp":
        dst_ip = rng.choice(_DNS_RESOLVERS + _EXTERNAL_HTTPS[:2])
        dport, payload = rng.choice(_UDP_SERVICES)
        if not payload and rng.random() < 0.5:
            payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(8, 32)))
        return udp_packet(host_ip, dst_ip, sport, dport, payload=payload)

    if kind == "internal":
        peers = [ip for ip in host_ips if ip != host_ip] or host_ips
        dst_ip = rng.choice(peers)
        dport = rng.choice((445, 139, 22, 8080, 5353))
        payload = rng.choice((b"", b"\x00\x01", b"keepalive"))
        flags = "PA" if payload else "A"
        return tcp_packet(host_ip, dst_ip, sport, dport, flags=flags, payload=payload)

    dst_ip = rng.choice(_EXTERNAL_HTTPS)
    return tcp_packet(host_ip, dst_ip, sport, 443, flags="A")
