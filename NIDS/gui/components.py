"""Shared Dash layout helpers and DataTable styling."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

import dash_bootstrap_components as dbc
from dash import html


TABLE_COLUMNS = [
    {"name": "#", "id": "index"},
    {"name": "Time", "id": "time"},
    {"name": "Src IP", "id": "ip_src"},
    {"name": "Dst IP", "id": "ip_dst"},
    {"name": "Src MAC", "id": "mac_src"},
    {"name": "Dst MAC", "id": "mac_dst"},
    {"name": "Proto", "id": "protocol"},
    {"name": "Src Port", "id": "src_port"},
    {"name": "Dst Port", "id": "dst_port"},
    {"name": "Flags", "id": "tcp_flags"},
    {"name": "DNS", "id": "dns_qname"},
    {"name": "Payload", "id": "payload_preview"},
    {"name": "Len", "id": "length"},
]

_SEVERITY_COLORS = {
    "high": "danger",
    "medium": "warning",
    "low": "info",
}


def table_style_cell() -> Dict[str, Any]:
    """Default cell styling for the packet table."""
    return {
        "textAlign": "left",
        "fontSize": "12px",
        "padding": "8px",
        "fontFamily": "Consolas, monospace",
        "minWidth": "90px",
        "maxWidth": "280px",
        "overflow": "hidden",
        "textOverflow": "ellipsis",
    }


def table_style_header() -> Dict[str, Any]:
    """Default header styling for the packet table."""
    return {
        "fontWeight": "600",
        "fontSize": "11px",
        "textTransform": "uppercase",
        "letterSpacing": "0.05em",
        "color": "#1e293b",
        "backgroundColor": "#f8fafc",
    }


def _style_for_packet_index(packet_index: int, **style: Any) -> Dict[str, Any]:
    """Build a row style rule keyed on the packet index column."""
    return {
        "if": {"filter_query": f"{{index}} eq {int(packet_index)}"},
        **style,
    }


def build_row_highlight_styles(
    rows: List[Dict[str, Any]],
    emphasis_indices: Optional[Iterable[int]] = None,
) -> List[Dict[str, Any]]:
    """Build per-row styles keyed on packet index (stable under sort/filter)."""
    styles: List[Dict[str, Any]] = [
        {
            "if": {"state": "selected"},
            "backgroundColor": "#fef3c7",
            "border": "1px solid #d97706",
        },
    ]
    emphasis = set(emphasis_indices or [])

    for row in rows:
        packet_index = row.get("index")
        if packet_index is None:
            continue
        kind = row.get("highlight", "")
        if kind == "attack":
            try:
                styles.append(
                    _style_for_packet_index(
                        int(packet_index),
                        backgroundColor="#fee2e2",
                        color="#991b1b",
                    )
                )
            except (TypeError, ValueError):
                continue

    for packet_index in emphasis:
        try:
            styles.append(
                _style_for_packet_index(
                    int(packet_index),
                    border="2px solid #f59e0b",
                    boxShadow="inset 0 0 0 1px #f59e0b",
                )
            )
        except (TypeError, ValueError):
            continue

    return styles


_ACRONYM_WORDS = {
    "ip": "IP",
    "mac": "MAC",
    "dns": "DNS",
    "src": "Src",
    "dst": "Dst",
    "tcp": "TCP",
    "udp": "UDP",
    "syn": "SYN",
    "ack": "ACK",
    "id": "ID",
}


def format_evidence_key(key: str) -> str:
    """Convert snake_case evidence keys to readable labels."""
    parts = key.split("_")
    formatted: List[str] = []
    for part in parts:
        lower = part.lower()
        if lower in _ACRONYM_WORDS:
            formatted.append(_ACRONYM_WORDS[lower])
        else:
            formatted.append(part.capitalize())
    return " ".join(formatted)


def _format_evidence_value(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


ATTACK_PATTERN_LABELS: Dict[str, str] = {
    "port_scan_horizontal": "Port Scan (horizontal)",
    "port_scan_vertical": "Port Scan (vertical)",
    "syn_flood": "SYN Flood",
    "dns_tunneling": "DNS Tunneling",
    "suspicious_payload": "Suspicious Payload",
    "beaconing": "Beaconing",
    "data_exfiltration": "Data Exfiltration",
    "arp_spoofing": "ARP Spoofing",
}

ALL_ATTACK_PATTERNS = list(ATTACK_PATTERN_LABELS.items())


def format_attack_pattern_label(attack_type: str) -> str:
    """Return a human-readable label for an attack type key."""
    return ATTACK_PATTERN_LABELS.get(attack_type, attack_type.replace("_", " ").title())


def render_alert_detail(alert: Dict[str, Any]) -> html.Div:
    """Render a structured alert card for the inspection panel."""
    attack_type = format_attack_pattern_label(alert.get("attack_type", "unknown"))
    severity = str(alert.get("severity", "medium")).lower()
    severity_color = _SEVERITY_COLORS.get(severity, "secondary")
    evidence = alert.get("evidence", {})
    packet_indices = alert.get("packet_indices", [])

    evidence_rows = [
        html.Tr([
            html.Th(format_evidence_key(key), className="cs-evidence-key"),
            html.Td(_format_evidence_value(value), className="cs-evidence-val"),
        ])
        for key, value in evidence.items()
    ]

    return html.Div(
        [
            html.Div(
                [
                    dbc.Badge(attack_type, color="dark", className="me-2"),
                    dbc.Badge(severity.upper(), color=severity_color),
                ],
                className="mb-2",
            ),
            html.P(alert.get("message", ""), className="cs-alert-message mb-2"),
            html.Div("Evidence", className="cs-label", style={"marginTop": 0}),
            dbc.Table(
                [html.Tbody(evidence_rows or [html.Tr(html.Td("(none)", colSpan=2))])],
                bordered=True,
                hover=True,
                size="sm",
                className="cs-evidence-table mb-2",
            ),
            html.Div("Linked packets", className="cs-label", style={"marginTop": 0}),
            html.Div(
                [dbc.Badge(str(idx), color="light", text_color="dark", className="me-1 mb-1") for idx in packet_indices]
                or [html.Span("—", className="text-muted")],
                className="cs-packet-badges",
            ),
            html.Div(
                f"Detector: {alert.get('detector', '')}",
                className="text-muted small mt-2",
            ),
        ],
        className="cs-alert-card mb-2",
    )


def render_packet_inspection(packet_header: str, alerts: List[Dict[str, Any]]) -> html.Div:
    """Render packet row header plus linked alert cards."""
    children: List[Any] = [html.Div(packet_header, className="cs-packet-header mb-1")]
    if not alerts:
        children.append(html.P("No alert linked to this packet.", className="text-muted small"))
    else:
        for alert in alerts:
            children.append(render_alert_detail(alert))
            children.append(html.Hr(className="my-2"))
    return html.Div(children, className="cs-inspection-panel")


def render_detected_patterns(alerts: List[Dict[str, Any]]) -> html.Div:
    """Render all attack patterns on one line; detected types are green."""
    detected: Dict[str, int] = {}
    for alert in alerts:
        attack_type = alert.get("attack_type", "unknown")
        detected[attack_type] = detected.get(attack_type, 0) + 1

    items: List[Any] = []
    for attack_type, label in ALL_ATTACK_PATTERNS:
        count = detected.get(attack_type, 0)
        if count:
            content = dbc.Badge(
                f"{label} ({count})",
                color="success",
                text_color="white",
                className="cs-pattern-badge cs-pattern-detected",
            )
        else:
            content = html.Span(label, className="cs-pattern-badge cs-pattern-muted")
        items.append(html.Div(content, className="cs-pattern-item"))

    return html.Div(items, className="cs-detected-patterns-inline")


def _clean_alert_message(message: str) -> str:
    """Normalize alert message text for compact list display."""
    cleaned = re.sub(r"\s*\(\d+\s+packet\(s\)\)\.?\s*$", "", message.strip())
    if cleaned and not cleaned.endswith("."):
        cleaned += "."
    return cleaned


def render_alerts_overview(alerts: List[Dict[str, Any]]) -> html.Div | html.P:
    """Render alerts list with one alert per line in the GUI."""
    if not alerts:
        return html.P("No alerts detected in this capture.", className="text-muted small mb-0")

    return html.Div(
        [
            html.Div(
                f"[{idx}] {alert.get('attack_type', '').upper()} ({alert.get('severity', '')}) -- "
                f"{_clean_alert_message(alert.get('message', ''))} "
                f"Packets: {len(alert.get('packet_indices', []))}",
                className="cs-alert-list-item",
            )
            for idx, alert in enumerate(alerts, start=1)
        ],
        className="cs-alert-list-lines",
    )
