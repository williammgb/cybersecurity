"""Orchestrate configurable benign + attack PCAP generation."""

from __future__ import annotations

import os
import random
from datetime import datetime
from typing import Dict, List, Tuple

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from backend.core.models import TrafficConfig
from backend.core.log_util import log
from backend.traffic import (
    build_arp_spoofing_traffic,
    build_beaconing_traffic,
    build_data_exfiltration_traffic,
    build_dns_tunneling_traffic,
    build_normal_traffic,
    build_port_scan_traffic,
    build_suspicious_payload_traffic,
    build_syn_flood_traffic,
)
from backend.traffic.common import (
    interleave_packets,
    max_packet_time,
    normalize_timestamps,
    stamp_packets,
    stamp_packets_jittered,
    write_pcap,
)

def _attack_ip(cfg: TrafficConfig, host_octet: int) -> str:
    return f"{cfg.subnet_base}.{host_octet}"


ATTACK_BUILDERS = {
    "port_scan": lambda cfg: build_port_scan_traffic(
        horizontal_attacker_ip=_attack_ip(cfg, 210),
        vertical_attacker_ip=_attack_ip(cfg, 211),
        scan_type=cfg.port_scan_type,
        subnet_base=cfg.subnet_base,
    ),
    "syn_flood": lambda cfg: build_syn_flood_traffic(
        attacker_ip=_attack_ip(cfg, 201),
        syn_count=cfg.syn_count,
    ),
    "dns_tunneling": lambda cfg: build_dns_tunneling_traffic(
        attacker_ip=_attack_ip(cfg, 202),
        query_count=cfg.dns_query_count,
        random_seed=cfg.random_seed,
    ),
    "suspicious_payload": lambda cfg: build_suspicious_payload_traffic(
        attacker_ip=_attack_ip(cfg, 203),
    ),
    "beaconing": lambda cfg: build_beaconing_traffic(
        agent_ip=_attack_ip(cfg, 204),
        beacon_count=cfg.beacon_count,
    ),
    "data_exfiltration": lambda cfg: build_data_exfiltration_traffic(
        src_ip=_attack_ip(cfg, 205),
        packet_count=cfg.exfil_packet_count,
    ),
    "arp_spoofing": lambda cfg: build_arp_spoofing_traffic(
        claimed_ip=f"{cfg.subnet_base}.1",
        packet_count=cfg.arp_packet_count,
        requester_ip=f"{cfg.subnet_base}.100",
    ),
}

SCENARIO_ABBREVS = {
    "syn_flood": "sf",
    "dns_tunneling": "dt",
    "suspicious_payload": "sp",
    "beaconing": "bc",
    "data_exfiltration": "de",
    "arp_spoofing": "as",
}


def build_mixed_pcap(config: TrafficConfig) -> Tuple[List[Packet], str]:
    """Build mixed traffic and write a PCAP file."""
    log(
        f"Building traffic: hosts={config.num_hosts}, packets/host={config.packets_per_host}, "
        f"attacks={config.attack_scenarios}, seed={config.random_seed}, "
        f"benign={config.include_benign}, mode={config.ordering_mode}"
    )

    benign: List[Packet] = []
    if config.include_benign:
        benign = build_normal_traffic(
            num_hosts=config.num_hosts,
            packets_per_host=config.packets_per_host,
            subnet_base=config.subnet_base,
            random_seed=config.random_seed,
        )

    attack_batches: List[Tuple[str, List[Packet]]] = []
    for scenario in config.attack_scenarios:
        builder = ATTACK_BUILDERS.get(scenario)
        if builder is not None:
            attack_batches.append((scenario, builder(config)))

    all_attacks: List[Packet] = []
    for _scenario, batch in attack_batches:
        all_attacks.extend(batch)

    use_mixed = (
        config.ordering_mode == "mixed"
        and config.include_benign
        and benign
        and all_attacks
    )

    if use_mixed:
        mixed = interleave_packets(
            benign,
            all_attacks,
            seed=config.random_seed,
            benign_lead=config.mixed_benign_lead,
        )
        stamp_packets_jittered(
            mixed,
            start_ts=config.start_timestamp,
            step_seconds=config.benign_step_seconds,
            jitter_seconds=config.benign_jitter_seconds,
            seed=config.random_seed,
        )
    else:
        mixed = _build_sequential_packets(config, benign, attack_batches)

    mixed.sort(key=lambda packet: float(getattr(packet, "time", 0)))
    _compress_syn_flood_timestamps(mixed, step_seconds=config.syn_flood_step_seconds)
    normalize_timestamps(mixed)

    output_path = config.output_path or _output_path_from_config(config)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    write_pcap(output_path, mixed)
    log(f"Wrote {len(mixed)} packets -> PCAP: {output_path}")
    return mixed, output_path


def _build_sequential_packets(
    config: TrafficConfig,
    benign: List[Packet],
    attack_batches: List[Tuple[str, List[Packet]]],
) -> List[Packet]:
    """Stamp benign first, then attack batches with gaps (legacy sequential ordering)."""
    if benign:
        stamp_packets_jittered(
            benign,
            start_ts=config.start_timestamp,
            step_seconds=config.benign_step_seconds,
            jitter_seconds=config.benign_jitter_seconds,
            seed=config.random_seed,
        )

    mixed: List[Packet] = list(benign)
    if benign:
        attack_start = max_packet_time(benign) + config.attack_gap_seconds
    else:
        attack_start = config.start_timestamp

    for scenario, batch in attack_batches:
        if scenario == "syn_flood":
            stamp_packets(batch, attack_start, config.syn_flood_step_seconds)
        elif scenario == "beaconing":
            stamp_packets(batch, attack_start, config.beacon_step_seconds)
        else:
            stamp_packets(batch, attack_start, config.attack_step_seconds)
        mixed.extend(batch)
        attack_start = max_packet_time(batch) + 2.0

    return mixed


def _pattern_abbreviations(config: TrafficConfig) -> List[str]:
    """Build ordered attack-pattern abbreviations for the PCAP filename."""
    parts: List[str] = []
    if config.include_benign:
        parts.append("b")
    for scenario in config.attack_scenarios:
        if scenario == "port_scan":
            scan_type = config.port_scan_type
            if scan_type == "horizontal":
                parts.append("ph")
            elif scan_type == "vertical":
                parts.append("pv")
            else:
                parts.extend(["ph", "pv"])
        else:
            abbrev = SCENARIO_ABBREVS.get(scenario)
            if abbrev:
                parts.append(abbrev)
    return parts or ["none"]


def _output_path_from_config(config: TrafficConfig) -> str:
    """Return a descriptive PCAP path under data/."""
    patterns = "_".join(_pattern_abbreviations(config))
    mode = "mix" if config.ordering_mode == "mixed" else "seq"
    stamp = datetime.now().strftime("%d%m%H%M")
    filename = f"{patterns}_{mode}_{stamp}.pcap"
    return os.path.join("data", filename)


def _compress_syn_flood_timestamps(packets: List[Packet], step_seconds: float = 0.05) -> None:
    """Re-stamp dense SYN bursts so sliding-window detectors see enough events."""
    groups: Dict[Tuple[str, int], List[Packet]] = {}
    for packet in packets:
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            continue
        tcp = packet[TCP]
        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
            continue
        key = (packet[IP].dst, int(tcp.dport))
        groups.setdefault(key, []).append(packet)

    for group in groups.values():
        if len(group) < 40:
            continue
        base_ts = min(float(getattr(packet, "time", 0.0)) for packet in group)
        for offset, packet in enumerate(group):
            packet.time = base_ts + (offset * step_seconds)
