"""Dash tab for configuring and generating synthetic PCAP traffic."""

from __future__ import annotations

import os
import traceback
from typing import Any, List

import dash_bootstrap_components as dbc
from dash import Input, Output, State, dcc, html
from dash.exceptions import PreventUpdate

from backend.core.models import TrafficConfig
from backend.services.traffic_builder import build_mixed_pcap
from gui.log_util import log
from gui.theme import labeled_input, page_header

ATTACK_OPTIONS = [
    {"label": "Port Scan", "value": "port_scan"},
    {"label": "SYN Flood", "value": "syn_flood"},
    {"label": "DNS Tunneling", "value": "dns_tunneling"},
    {"label": "Suspicious Payload", "value": "suspicious_payload"},
    {"label": "Beaconing", "value": "beaconing"},
    {"label": "Data Exfiltration", "value": "data_exfiltration"},
    {"label": "ARP Spoofing", "value": "arp_spoofing"},
]

PORT_SCAN_OPTIONS = [
    {"label": "Horizontal", "value": "horizontal"},
    {"label": "Vertical", "value": "vertical"},
    {"label": "Both", "value": "both"},
]


def _num(value: Any, default: float | int) -> float | int:
    try:
        return type(default)(value)
    except (TypeError, ValueError):
        return default


def _build_config(
    num_hosts: int,
    packets_per_host: int,
    subnet: str,
    random_seed: int,
    start_timestamp: float,
    benign_step: float,
    benign_jitter: float,
    attack_gap: float,
    attack_step: float,
    syn_step: float,
    beacon_step: float,
    attacks: List[str],
    port_scan_type: str,
    syn_count: int,
    dns_count: int,
    beacon_count: int,
    exfil_count: int,
    include_benign: bool,
    ordering_mode: str,
    mixed_benign_lead: int,
    arp_count: int,
) -> TrafficConfig:
    """Map GUI form values into a TrafficConfig object."""
    return TrafficConfig(
        num_hosts=int(_num(num_hosts, 3)),
        packets_per_host=int(_num(packets_per_host, 14)),
        subnet_base=subnet or "192.168.1",
        random_seed=int(_num(random_seed, 42)),
        start_timestamp=float(_num(start_timestamp, 0.0)),
        benign_step_seconds=float(_num(benign_step, 0.25)),
        benign_jitter_seconds=float(_num(benign_jitter, 0.12)),
        attack_gap_seconds=float(_num(attack_gap, 5.0)),
        attack_step_seconds=float(_num(attack_step, 0.25)),
        syn_flood_step_seconds=float(_num(syn_step, 0.05)),
        beacon_step_seconds=float(_num(beacon_step, 10.0)),
        attack_scenarios=attacks or [],
        port_scan_type=port_scan_type or "both",
        syn_count=int(_num(syn_count, 50)),
        dns_query_count=int(_num(dns_count, 20)),
        beacon_count=int(_num(beacon_count, 10)),
        exfil_packet_count=int(_num(exfil_count, 50)),
        include_benign=bool(include_benign),
        ordering_mode=ordering_mode or "sequential",
        mixed_benign_lead=int(_num(mixed_benign_lead, 5)),
        arp_packet_count=int(_num(arp_count, 3)),
    )


def layout() -> html.Div:
    """Build the traffic generation tab layout."""
    return html.Div(
        [
            page_header("Traffic Generator"),
            dbc.Row(
                [
                    dbc.Col(
                        dbc.Card(
                            [
                                dbc.CardHeader("Benign Traffic"),
                                dbc.CardBody(
                                    [
                                        labeled_input("Hosts", dbc.Input(id="traffic-num-hosts", type="number", value=3, min=1, max=50)),
                                        labeled_input("Packets / host", dbc.Input(id="traffic-packets-per-host", type="number", value=14, min=1, max=100)),
                                        labeled_input("Subnet", dbc.Input(id="traffic-subnet", type="text", value="192.168.1")),
                                        labeled_input("Random seed", dbc.Input(id="traffic-random-seed", type="number", value=42, min=0, max=999999)),
                                        dbc.Checklist(
                                            id="traffic-include-benign",
                                            options=[{"label": "Include benign traffic", "value": "yes"}],
                                            value=["yes"],
                                            className="mt-2",
                                            inputStyle={"marginRight": "8px"},
                                        ),
                                        labeled_input(
                                            "Ordering",
                                            dbc.RadioItems(
                                                id="traffic-ordering-mode",
                                                options=[
                                                    {"label": "Sequential (benign then attack)", "value": "sequential"},
                                                    {"label": "Mixed (random interleave)", "value": "mixed"},
                                                ],
                                                value="sequential",
                                                labelStyle={"display": "block", "fontSize": "0.85rem"},
                                                inputStyle={"marginRight": "8px"},
                                            ),
                                        ),
                                        labeled_input(
                                            "Benign offset",
                                            dbc.Input(
                                                id="traffic-mixed-benign-lead",
                                                type="number",
                                                value=5,
                                                min=0,
                                                max=100,
                                            ),
                                        ),
                                        html.P(
                                            "Applies in mixed ordering mode: benign packets placed before interleaving.",
                                            className="text-muted small mb-0",
                                        ),
                                    ]
                                ),
                            ],
                            className="cs-card h-100",
                        ),
                        lg=3,
                        className="mb-2",
                    ),
                    dbc.Col(
                        dbc.Card(
                            [
                                dbc.CardHeader("Timing"),
                                dbc.CardBody(
                                    [
                                        labeled_input("Start timestamp", dbc.Input(id="traffic-start-ts", type="number", value=0, min=0, step=0.01)),
                                        labeled_input("Benign step (s)", dbc.Input(id="traffic-benign-step", type="number", value=0.25, min=0.01, step=0.01)),
                                        labeled_input("Benign jitter (s)", dbc.Input(id="traffic-benign-jitter", type="number", value=0.12, min=0, step=0.01)),
                                        labeled_input("Attack gap (s)", dbc.Input(id="traffic-attack-gap", type="number", value=5, min=0, step=0.5)),
                                        labeled_input("Attack step (s)", dbc.Input(id="traffic-attack-step", type="number", value=0.25, min=0.01, step=0.01)),
                                        labeled_input("SYN step (s)", dbc.Input(id="traffic-syn-step", type="number", value=0.05, min=0.01, step=0.01)),
                                        labeled_input("Beacon interval (s)", dbc.Input(id="traffic-beacon-step", type="number", value=10, min=1, step=0.5)),
                                    ]
                                ),
                            ],
                            className="cs-card h-100",
                        ),
                        lg=3,
                        className="mb-2",
                    ),
                    dbc.Col(
                        dbc.Card(
                            [
                                dbc.CardHeader("Attack Scenarios"),
                                dbc.CardBody(
                                    [
                                        dcc.Checklist(
                                            id="traffic-attacks",
                                            options=ATTACK_OPTIONS,
                                            value=[item["value"] for item in ATTACK_OPTIONS],
                                            className="cs-attack-checklist",
                                            inputStyle={"marginRight": "6px"},
                                            labelStyle={"display": "block", "fontSize": "0.8rem", "marginBottom": "1px"},
                                        ),
                                        html.Hr(className="my-2"),
                                        html.Div("Attack parameters", className="cs-label", style={"marginTop": 0}),
                                        html.Div(
                                            id="param-port-scan",
                                            style={"display": "block"},
                                            children=[
                                                labeled_input("Scan type", dbc.Select(id="traffic-port-scan-type", options=PORT_SCAN_OPTIONS, value="both")),
                                            ],
                                        ),
                                        html.Div(
                                            id="param-syn-flood",
                                            style={"display": "block"},
                                            children=[labeled_input("SYN count", dbc.Input(id="traffic-syn-count", type="number", value=50, min=20, max=500))],
                                        ),
                                        html.Div(
                                            id="param-dns",
                                            style={"display": "block"},
                                            children=[labeled_input("DNS queries", dbc.Input(id="traffic-dns-count", type="number", value=20, min=5, max=200))],
                                        ),
                                        html.Div(
                                            id="param-beacon",
                                            style={"display": "block"},
                                            children=[labeled_input("Beacons", dbc.Input(id="traffic-beacon-count", type="number", value=10, min=3, max=30))],
                                        ),
                                        html.Div(
                                            id="param-exfil",
                                            style={"display": "block"},
                                            children=[labeled_input("Exfil pkts", dbc.Input(id="traffic-exfil-count", type="number", value=50, min=10, max=500))],
                                        ),
                                        html.Div(
                                            id="param-arp-spoofing",
                                            style={"display": "block"},
                                            children=[
                                                labeled_input(
                                                    "ARP packets",
                                                    dbc.Input(id="traffic-arp-count", type="number", value=3, min=2, max=20),
                                                ),
                                            ],
                                        ),
                                    ],
                                    className="cs-attack-scenarios-body",
                                ),
                            ],
                            className="cs-card cs-attack-scenarios-card",
                        ),
                        lg=3,
                        className="mb-2",
                    ),
                    dbc.Col(
                        dbc.Card(
                            [
                                dbc.CardHeader("Generate PCAP"),
                                dbc.CardBody(
                                    [
                                        html.Div(
                                            html.Button(
                                                "Generate PCAP",
                                                id="traffic-generate-btn",
                                                n_clicks=0,
                                                type="button",
                                                className="btn btn-primary btn-sm",
                                            ),
                                            className="mb-2",
                                        ),
                                        html.Div(id="traffic-summary", className="cs-summary-box", children="Ready — click Generate PCAP."),
                                    ]
                                ),
                            ],
                            className="cs-card h-100",
                        ),
                        lg=3,
                        className="mb-2",
                    ),
                ],
                className="g-2",
            ),
        ],
        className="tab-content",
    )


def register_callbacks(app: Any) -> None:
    """Wire traffic tab inputs to the traffic builder service."""

    @app.callback(
        Output("param-port-scan", "style"),
        Output("param-syn-flood", "style"),
        Output("param-dns", "style"),
        Output("param-beacon", "style"),
        Output("param-exfil", "style"),
        Output("param-arp-spoofing", "style"),
        Input("traffic-attacks", "value"),
    )
    def toggle_attack_params(attacks: List[str]) -> tuple:
        attacks = attacks or []
        show = {"display": "block"}
        hide = {"display": "none"}
        return (
            show if "port_scan" in attacks else hide,
            show if "syn_flood" in attacks else hide,
            show if "dns_tunneling" in attacks else hide,
            show if "beaconing" in attacks else hide,
            show if "data_exfiltration" in attacks else hide,
            show if "arp_spoofing" in attacks else hide,
        )

    @app.callback(
        Output("traffic-request", "data"),
        Input("traffic-generate-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def queue_traffic_request(gen_clicks: int) -> dict:
        log(f"Generate PCAP clicked (n={gen_clicks})")
        return {"action": "generate", "clicks": gen_clicks}

    @app.callback(
        Output("traffic-summary", "children"),
        Output("shared-pcap-path", "data"),
        Input("traffic-request", "data"),
        State("traffic-num-hosts", "value"),
        State("traffic-packets-per-host", "value"),
        State("traffic-subnet", "value"),
        State("traffic-random-seed", "value"),
        State("traffic-start-ts", "value"),
        State("traffic-benign-step", "value"),
        State("traffic-benign-jitter", "value"),
        State("traffic-attack-gap", "value"),
        State("traffic-attack-step", "value"),
        State("traffic-syn-step", "value"),
        State("traffic-beacon-step", "value"),
        State("traffic-attacks", "value"),
        State("traffic-port-scan-type", "value"),
        State("traffic-syn-count", "value"),
        State("traffic-dns-count", "value"),
        State("traffic-beacon-count", "value"),
        State("traffic-exfil-count", "value"),
        State("traffic-include-benign", "value"),
        State("traffic-ordering-mode", "value"),
        State("traffic-mixed-benign-lead", "value"),
        State("traffic-arp-count", "value"),
        prevent_initial_call=True,
    )
    def run_traffic_generation(
        request: dict,
        num_hosts: int,
        packets_per_host: int,
        subnet: str,
        random_seed: int,
        start_timestamp: float,
        benign_step: float,
        benign_jitter: float,
        attack_gap: float,
        attack_step: float,
        syn_step: float,
        beacon_step: float,
        attacks: List[str],
        port_scan_type: str,
        syn_count: int,
        dns_count: int,
        beacon_count: int,
        exfil_count: int,
        include_benign_values: List[str],
        ordering_mode: str,
        mixed_benign_lead: int,
        arp_count: int,
    ) -> tuple[str, str]:
        if not request:
            raise PreventUpdate

        log(f"Running generation: {request}")
        try:
            config = _build_config(
                num_hosts,
                packets_per_host,
                subnet,
                random_seed,
                start_timestamp,
                benign_step,
                benign_jitter,
                attack_gap,
                attack_step,
                syn_step,
                beacon_step,
                attacks,
                port_scan_type,
                syn_count,
                dns_count,
                beacon_count,
                exfil_count,
                "yes" in (include_benign_values or []),
                ordering_mode,
                mixed_benign_lead,
                arp_count,
            )
            packets, output_path = build_mixed_pcap(config)
            first_ts = float(packets[0].time) if packets else 0.0
            summary = (
                f"Status: SUCCESS\n"
                f"Total packets: {len(packets)}\n"
                f"First timestamp: {first_ts:.3f}\n"
                f"Random seed: {config.random_seed}\n"
                f"Benign: {'yes' if config.include_benign else 'no'}\n"
                f"Ordering: {config.ordering_mode}\n"
                f"Benign offset: {config.mixed_benign_lead}\n"
                f"Attacks: {', '.join(config.attack_scenarios) or 'none'}\n"
                f"PCAP:\n  {os.path.basename(output_path)}\n"
                f"  {os.path.abspath(output_path)}"
            )
            log(f"Generation complete: {len(packets)} packets")
            return summary, output_path
        except Exception as exc:
            log(f"Generation FAILED: {exc}")
            log(traceback.format_exc())
            return f"Status: ERROR\n{exc}\n\n{traceback.format_exc()}", ""
