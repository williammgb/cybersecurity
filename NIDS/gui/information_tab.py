"""Dash tab with the in-app GUI guide (mirrors README)."""

from __future__ import annotations

import dash_bootstrap_components as dbc
from dash import html

from gui.theme import page_header


def _table(headers: list[str], rows: list[list[str]]) -> dbc.Table:
    return dbc.Table(
        [
            html.Thead(html.Tr([html.Th(h) for h in headers])),
            html.Tbody([html.Tr([html.Td(cell) for cell in row]) for row in rows]),
        ],
        bordered=True,
        hover=True,
        size="sm",
        className="mb-3",
    )


def layout() -> html.Div:
    """Build the information tab with the GUI guide."""
    return html.Div(
        [
            page_header(
                "Information",
                "GUI guide for Traffic Generation, Detector Configuration, and Packet Analysis",
            ),
            html.H5("Traffic Generation", className="mt-2"),
            html.P(
                "Builds a PCAP under data/ with a descriptive filename "
                "(attack abbreviations, seq/mix mode, timestamp)."
            ),
            html.H6("Benign Traffic", className="mt-3"),
            _table(
                ["Control", "What it does"],
                [
                    ["Hosts", "Number of simulated LAN clients (e.g. 192.168.1.10, .11, …)."],
                    ["Packets / host", "Per-host mix of HTTP-like TCP, DNS, UDP, and internal flows."],
                    ["Subnet", "First three octets of the lab network (default 192.168.1)."],
                    ["Random seed", "Seed for reproducible benign traffic variation."],
                    ["Include benign traffic", "When unchecked, only attack packets are generated."],
                    ["Ordering", "Sequential = benign block then attacks; Mixed = random interleave."],
                    ["Benign offset", "Mixed mode only: number of benign packets placed before interleaving starts."],
                ],
            ),
            html.H6("Timing", className="mt-3"),
            _table(
                ["Control", "What it does"],
                [
                    ["Start timestamp", "Base time for the capture (default 0.0)."],
                    ["Benign step / jitter", "Spacing between benign packets, with random jitter."],
                    ["Attack gap", "Delay after benign traffic before attack batches start (sequential mode)."],
                    ["Attack step", "Spacing between packets in most attack batches."],
                    ["SYN step", "Spacing used for SYN flood bursts."],
                    ["Beacon interval", "Fixed interval between beaconing check-in packets."],
                ],
            ),
            html.H6("Attack Scenarios", className="mt-3"),
            _table(
                ["Attack", "Parameter", "Effect"],
                [
                    ["Port Scan", "Scan type", "horizontal = one port across many IPs; vertical = many ports on one IP; both."],
                    ["SYN Flood", "SYN count", "Half-open handshake flood (default 50)."],
                    ["DNS Tunneling", "DNS queries", "Long encoded subdomain queries (default 20)."],
                    ["Beaconing", "Beacons", "Periodic C2-style check-in packets (default 10)."],
                    ["Data Exfiltration", "Exfil pkts", "Large outbound TCP payloads (default 50)."],
                    ["Suspicious Payload", "(fixed)", "Cleartext command-injection style HTTP payloads."],
                    ["ARP Spoofing", "ARP packets", "Conflicting ARP replies for the gateway IP (default 3)."],
                ],
            ),
            html.H6("Buttons", className="mt-3"),
            _table(
                ["Button", "Action"],
                [
                    ["Generate PCAP", "Writes a PCAP to data/ and auto-selects it in Packet Analysis."],
                ],
            ),
            html.Hr(),
            html.H5("Detector Configuration", className="mt-2"),
            html.P(
                "Tune per-detector thresholds before running analysis on the Packet Analysis tab. "
                "Click Apply Settings to save values to the shared detector store."
            ),
            html.H6("Port Scan (Horizontal)", className="mt-3"),
            _table(
                ["Field", "What it means", "If you increase", "If you decrease"],
                [
                    [
                        "window_seconds",
                        "Rolling time window for counting SYN probes from one source.",
                        "Older probes stay counted longer — easier to reach the threshold.",
                        "Window shrinks — scanning must be faster to trigger an alert.",
                    ],
                    [
                        "horizontal_threshold_unique_ips",
                        "Unique destination IPs probed on the same port before alerting.",
                        "Fewer IPs needed — more sensitive, more false positives.",
                        "More IPs needed — only large horizontal sweeps alert.",
                    ],
                ],
            ),
            html.H6("Port Scan (Vertical)", className="mt-3"),
            _table(
                ["Field", "What it means", "If you increase", "If you decrease"],
                [
                    [
                        "window_seconds",
                        "Rolling time window for SYN probes (same as horizontal).",
                        "Probes accumulate over a longer period.",
                        "Only recent probes count toward the threshold.",
                    ],
                    [
                        "vertical_threshold_unique_ports",
                        "Unique ports probed on one target IP before alerting.",
                        "Fewer ports needed — more sensitive.",
                        "More ports needed — only deep vertical scans alert.",
                    ],
                ],
            ),
            html.H6("SYN Flood", className="mt-3"),
            _table(
                ["Field", "What it means", "If you increase", "If you decrease"],
                [
                    [
                        "window_seconds",
                        "Time window for SYN and ACK counts per target IP:port.",
                        "Counts accumulate longer — slow floods may still alert.",
                        "Only short bursts count — may miss prolonged low-rate floods.",
                    ],
                    [
                        "min_syn_threshold",
                        "Minimum SYN packets in the window required to consider an alert.",
                        "Harder to alert — small SYN bursts are ignored.",
                        "Easier to alert on smaller floods.",
                    ],
                    [
                        "min_syn_ack_ratio",
                        "Required ratio of SYN count to ACK count (imbalance).",
                        "Stronger imbalance needed — fewer false positives.",
                        "Weaker imbalance still triggers — more sensitive.",
                    ],
                ],
            ),
            html.H6("DNS Tunneling", className="mt-3"),
            _table(
                ["Field", "What it means", "If you increase", "If you decrease"],
                [
                    [
                        "window_seconds",
                        "How long DNS queries from each source are remembered.",
                        "Sustained high query rates count longer.",
                        "Only recent query bursts contribute to the rate.",
                    ],
                    [
                        "query_rate_threshold",
                        "Query count in the window that alone triggers an alert.",
                        "Only very chatty DNS clients alert on rate alone.",
                        "Busy legitimate DNS may false-positive.",
                    ],
                    [
                        "label_len_threshold",
                        "Longest subdomain label length treated as suspicious.",
                        "Shorter labels are ignored.",
                        "Moderately long labels also count as suspicious.",
                    ],
                    [
                        "entropy_threshold",
                        "Shannon entropy (randomness) of labels — encoded data scores high.",
                        "Only very random-looking labels count.",
                        "More encoded-looking labels are flagged.",
                    ],
                ],
            ),
            html.P(
                "Also alerts when rate ≥ 5 and at least two of: long label, high entropy, "
                "or base32/base64/hex-like subdomain labels.",
                className="text-muted small mb-3",
            ),
            html.H6("Suspicious Payload", className="mt-3"),
            _table(
                ["Field", "What it means", "If you increase", "If you decrease"],
                [
                    [
                        "window_seconds",
                        "Cooldown between repeat alerts for the same src→dst flow.",
                        "Same flow re-alerts less often.",
                        "Same flow can re-alert sooner.",
                    ],
                ],
            ),
            html.P(
                "Signatures are fixed (command injection, path traversal, download-execute, reverse shell). "
                "Only plaintext-visible payloads match; encrypted traffic is not inspected.",
                className="text-muted small mb-3",
            ),
            html.H6("Beaconing", className="mt-3"),
            _table(
                ["Field", "What it means", "If you increase", "If you decrease"],
                [
                    [
                        "min_events",
                        "Packets per flow before timing analysis runs.",
                        "Longer pattern required before alerting.",
                        "Alerts on shorter periodic sequences.",
                    ],
                    [
                        "max_jitter_seconds",
                        "Maximum allowed standard deviation of inter-packet gaps.",
                        "Only very regular (low-jitter) beacons match.",
                        "Irregular traffic may false-positive as beaconing.",
                    ],
                    [
                        "min_avg_interval_seconds",
                        "Shortest average gap between packets considered beaconing.",
                        "Fast chatter is ignored.",
                        "Faster periodic traffic can alert.",
                    ],
                    [
                        "max_avg_interval_seconds",
                        "Longest average gap between packets considered beaconing.",
                        "Slow beacons are ignored.",
                        "Very slow periodic traffic can alert.",
                    ],
                    [
                        "alert_cooldown_seconds",
                        "Minimum time between repeat alerts for the same flow.",
                        "Fewer duplicate alerts for one flow.",
                        "Same flow can re-alert sooner.",
                    ],
                ],
            ),
            html.P(
                "Only private-source flows to external destinations are analyzed; "
                "known lab destinations (e.g. 8.8.8.8) are excluded.",
                className="text-muted small mb-3",
            ),
            html.H6("Data Exfiltration", className="mt-3"),
            _table(
                ["Field", "What it means", "If you increase", "If you decrease"],
                [
                    [
                        "local_cidr",
                        "CIDR range treated as internal (e.g. 192.168.0.0/16).",
                        "Wider range — more source IPs count as internal.",
                        "Narrower range — traffic outside it may not be evaluated.",
                    ],
                    [
                        "window_seconds",
                        "Rolling window for summing outbound bytes per source.",
                        "Large transfers accumulate over a longer period.",
                        "Only recent outbound bursts count.",
                    ],
                    [
                        "burst_bytes_threshold",
                        "Outbound bytes (internal → external) required to alert.",
                        "Only larger uploads trigger.",
                        "Smaller transfers can alert.",
                    ],
                ],
            ),
            html.H6("ARP Spoofing", className="mt-3"),
            _table(
                ["Field", "What it means", "If you increase", "If you decrease"],
                [
                    [
                        "window_seconds",
                        "How long conflicting MAC claims are remembered; also the alert cooldown.",
                        "Old MAC changes are forgotten; re-alerts are less frequent.",
                        "MAC conflicts must occur closer together to alert.",
                    ],
                ],
            ),
            html.P(
                "Alerts when one IP is seen claiming two or more different MAC addresses within the window.",
                className="text-muted small mb-3",
            ),
            html.Hr(),
            html.H5("Packet Analysis", className="mt-2"),
            html.P("Wide packet table on the left; controls and inspection panel on the right."),
            html.H6("Controls (sidebar)", className="mt-3"),
            _table(
                ["Control", "What it does"],
                [
                    ["PCAP file", "Pick a file from data/. The full path is shown below the dropdown."],
                    ["Detectors", "Enable/disable individual attack detectors (all enabled by default)."],
                    ["Run Analysis", "Replay the PCAP, fill the table, and apply attack row highlights."],
                    ["Alerts", "Toggle the alert picker and summary in the inspection panel."],
                ],
            ),
            html.H6("Stats bar", className="mt-3"),
            html.P("Shows total packets, alerts found, enabled detector count, and highlighted row count."),
            html.H6("Packet table", className="mt-3"),
            html.Ul(
                [
                    html.Li("50 rows per page; sortable and filterable columns including MAC addresses for ARP."),
                    html.Li("Red rows = packets linked to an attack alert."),
                    html.Li("Orange border = packets emphasized when you select an alert or click a linked row."),
                    html.Li("Click a row → inspection panel shows linked alert details for that packet."),
                ]
            ),
            html.H6("Detected Patterns", className="mt-3"),
            html.P(
                "Shown above the packet table after analysis: all attack types on one line; "
                "detected types appear in green."
            ),
            html.H6("Alerts workflow", className="mt-3"),
            html.Ol(
                [
                    html.Li("Run analysis with your chosen detectors."),
                    html.Li("Click Alerts in the sidebar."),
                    html.Li("Use Select alert — the chosen alert highlights its packets and shows structured details."),
                ]
            ),
        ],
        className="tab-content",
    )
