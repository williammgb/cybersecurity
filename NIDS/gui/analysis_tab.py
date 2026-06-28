"""Dash tab for PCAP replay, detection, and packet table inspection."""

from __future__ import annotations

import glob
import os
from typing import Any, Dict, List, Optional, Set

import dash_bootstrap_components as dbc
from dash import Input, Output, State, dash_table, dcc, html
from dash.exceptions import PreventUpdate

from backend.core.models import DetectorConfig
from backend.services.analysis_service import run_analysis
from gui.components import (
    TABLE_COLUMNS,
    build_row_highlight_styles,
    format_attack_pattern_label,
    render_alert_detail,
    render_alerts_overview,
    render_detected_patterns,
    render_packet_inspection,
    table_style_cell,
    table_style_header,
)
from gui.theme import action_button, labeled_input, stat_card

ATTACK_CHECKBOXES = [
    {"label": "Port Scan (horizontal)", "value": "port_scan_horizontal"},
    {"label": "Port Scan (vertical)", "value": "port_scan_vertical"},
    {"label": "SYN Flood", "value": "syn_flood"},
    {"label": "DNS Tunneling", "value": "dns_tunneling"},
    {"label": "Suspicious Payload", "value": "suspicious_payload"},
    {"label": "Beaconing", "value": "beaconing"},
    {"label": "Data Exfiltration", "value": "data_exfiltration"},
    {"label": "ARP Spoofing", "value": "arp_spoofing"},
]


def _list_pcaps() -> List[Dict[str, str]]:
    """Collect available PCAP files from data/."""
    paths = glob.glob(os.path.join("data", "*.pcap"))
    return [{"label": os.path.basename(path), "value": path} for path in sorted(paths)]


def _alert_dropdown_options(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build select options for the alerts sidebar picker."""
    options: List[Dict[str, Any]] = []
    for alert_index, alert in enumerate(alerts):
        label = f"{alert_index + 1}. {format_attack_pattern_label(alert.get('attack_type', ''))} ({alert.get('severity', '')})"
        options.append({"label": label, "value": alert_index})
    return options


def layout() -> html.Div:
    """Build the analysis tab layout — wide table left, controls sidebar right."""
    return html.Div(
        [
            dbc.Row(
                [
                    stat_card("Packets", "stat-packets"),
                    stat_card("Alerts", "stat-alerts", color="#ef4444"),
                    stat_card("Detectors", "stat-detectors", color="#2563eb"),
                    stat_card("Highlighted", "stat-highlighted", color="#f59e0b"),
                ],
                className="mb-1 g-2",
            ),
            dbc.Row(
                [
                    dbc.Col(
                        [
                            html.Div(
                                id="analysis-detected-patterns",
                                className="cs-detected-patterns-bar cs-card",
                                children=render_detected_patterns([]),
                            ),
                            dbc.Card(
                                [
                                    dbc.CardHeader("Packet Table", className="py-1"),
                                    dbc.CardBody(
                                        dash_table.DataTable(
                                            id="analysis-table",
                                            columns=TABLE_COLUMNS,
                                            data=[],
                                            page_size=50,
                                            row_selectable="single",
                                            sort_action="native",
                                            filter_action="native",
                                            style_table={"overflowX": "auto", "width": "100%", "minWidth": "100%"},
                                            style_cell=table_style_cell(),
                                            style_header=table_style_header(),
                                            style_data_conditional=[],
                                            css=[{"selector": ".dash-spreadsheet", "rule": "width: 100%"}],
                                        ),
                                        className="p-0 cs-packet-table",
                                    ),
                                ],
                                className="cs-card cs-analysis-compact",
                            ),
                        ],
                        lg=9,
                        md=7,
                    ),
                    dbc.Col(
                        html.Div(
                            [
                                dbc.Card(
                                    [
                                        dbc.CardHeader(
                                            html.Div(
                                                [
                                                    html.Span("Controls"),
                                                    dbc.Button(
                                                        "Toggle",
                                                        id="analysis-controls-toggle",
                                                        color="link",
                                                        size="sm",
                                                        className="p-0 cs-collapse-toggle",
                                                    ),
                                                ],
                                                className="d-flex justify-content-between align-items-center",
                                            ),
                                            className="py-1",
                                        ),
                                        dbc.Collapse(
                                            dbc.CardBody(
                                                [
                                                    labeled_input(
                                                        "PCAP file",
                                                        dcc.Dropdown(
                                                            id="analysis-pcap",
                                                            options=_list_pcaps(),
                                                            placeholder="Select a PCAP…",
                                                        ),
                                                    ),
                                                    dbc.Input(
                                                        id="analysis-pcap-path",
                                                        type="text",
                                                        readonly=True,
                                                        placeholder="No PCAP selected",
                                                        className="form-control form-control-sm mt-1",
                                                    ),
                                                    labeled_input(
                                                        "Detectors",
                                                        dcc.Checklist(
                                                            id="analysis-detectors",
                                                            options=ATTACK_CHECKBOXES,
                                                            value=[item["value"] for item in ATTACK_CHECKBOXES],
                                                            labelStyle={"display": "block", "marginBottom": "4px"},
                                                            inputStyle={"marginRight": "8px"},
                                                        ),
                                                    ),
                                                    html.Div(
                                                        [
                                                            action_button("Run Analysis", "analysis-run-btn"),
                                                            action_button("Alerts", "analysis-alerts-btn", outline=True),
                                                        ],
                                                        className="d-flex gap-2 mt-3 flex-wrap",
                                                    ),
                                                ]
                                            ),
                                            id="analysis-controls-collapse",
                                            is_open=True,
                                        ),
                                    ],
                                    className="cs-card cs-analysis-compact mb-2",
                                ),
                                dbc.Card(
                                    [
                                        dbc.CardHeader(id="analysis-panel-title", children="Inspection", className="py-1"),
                                        dbc.CardBody(
                                            [
                                                html.Div(
                                                    id="analysis-detail",
                                                    className="cs-inspection-panel mb-0",
                                                    children=html.P(
                                                        "Run analysis to inspect packets.",
                                                        className="text-muted small mb-0",
                                                    ),
                                                ),
                                                html.Div(
                                                    id="analysis-alerts-panel",
                                                    style={"display": "none"},
                                                    children=[
                                                        labeled_input(
                                                            "Select alert",
                                                            dbc.Select(
                                                                id="analysis-alert-select",
                                                                options=[],
                                                                placeholder="Choose an alert…",
                                                            ),
                                                        ),
                                                        html.Div(id="analysis-alert-summary", className="cs-alert-list mt-2"),
                                                    ],
                                                ),
                                            ]
                                        ),
                                    ],
                                    className="cs-card cs-analysis-compact",
                                ),
                            ],
                            className="cs-sidebar",
                        ),
                        lg=3,
                        md=5,
                    ),
                ],
                className="g-2",
            ),
            dcc.Store(id="analysis-result-store"),
            dcc.Store(id="analysis-selected-alert", data=None),
            dcc.Store(id="analysis-sidebar-view", data="inspect"),
        ],
        className="tab-content cs-analysis-tab",
    )


def register_callbacks(app: Any) -> None:
    """Wire analysis tab controls to the analysis service."""

    @app.callback(
        Output("analysis-controls-collapse", "is_open"),
        Input("analysis-controls-toggle", "n_clicks"),
        State("analysis-controls-collapse", "is_open"),
        prevent_initial_call=True,
    )
    def toggle_analysis_controls(_n_clicks: int, is_open: bool) -> bool:
        return not is_open

    @app.callback(
        Output("analysis-pcap", "options"),
        Output("analysis-pcap", "value"),
        Input("shared-pcap-path", "data"),
    )
    def refresh_pcap_list(shared_path: Optional[str]) -> tuple[List[Dict[str, str]], Optional[str]]:
        options = _list_pcaps()
        value = shared_path if shared_path else (options[-1]["value"] if options else None)
        return options, value

    @app.callback(
        Output("analysis-pcap-path", "value"),
        Input("analysis-pcap", "value"),
        Input("shared-pcap-path", "data"),
    )
    def show_selected_pcap_path(pcap_path: Optional[str], shared_path: Optional[str]) -> str:
        selected = pcap_path or shared_path or ""
        if not selected:
            return ""
        return os.path.abspath(selected)

    @app.callback(
        Output("analysis-table", "data"),
        Output("analysis-table", "style_data_conditional"),
        Output("analysis-result-store", "data"),
        Output("analysis-detail", "children"),
        Output("analysis-detail", "style"),
        Output("analysis-detected-patterns", "children"),
        Output("analysis-alert-select", "options"),
        Output("analysis-alert-select", "value"),
        Output("analysis-alert-summary", "children"),
        Output("analysis-alerts-panel", "style"),
        Output("analysis-panel-title", "children"),
        Output("stat-packets", "children"),
        Output("stat-alerts", "children"),
        Output("stat-detectors", "children"),
        Output("stat-highlighted", "children"),
        Output("analysis-selected-alert", "data"),
        Output("analysis-sidebar-view", "data"),
        Input("analysis-run-btn", "n_clicks"),
        State("analysis-pcap", "value"),
        State("analysis-detectors", "value"),
        State("detector-config-store", "data"),
        prevent_initial_call=True,
    )
    def on_run_analysis(
        _n_clicks: int,
        pcap_path: Optional[str],
        enabled_detectors: List[str],
        detector_config_data: Optional[Dict[str, Any]],
    ) -> tuple:
        hidden = {"display": "none"}
        visible_panel = {"display": "block"}
        empty_stats = ("—", "—", "—", "—")
        empty_patterns = render_detected_patterns([])

        if not pcap_path:
            return (
                [], [], {}, html.P("Select a PCAP file first.", className="text-muted small mb-0"),
                visible_panel, empty_patterns, [], None, "", hidden, "Inspection",
                *empty_stats, None, "inspect",
            )

        try:
            detector_config = DetectorConfig.from_dict(detector_config_data)
            result = run_analysis(
                pcap_path=pcap_path,
                enabled_attacks=enabled_detectors,
                detector_config=detector_config,
            )
            store = {
                "alerts": [alert.to_dict() for alert in result.alerts],
            }
            row_styles = build_row_highlight_styles(result.rows)
            summary = html.Div(
                [
                    html.P(f"Analyzed {len(result.rows)} packets", className="mb-1"),
                    html.P(f"File: {os.path.basename(pcap_path)}", className="mb-1 small text-muted"),
                    html.P(f"Detectors: {len(enabled_detectors or [])}", className="mb-1 small"),
                    html.P(f"Alerts: {len(result.alerts)}", className="mb-1 small"),
                    html.P("Click a table row or open Alerts →", className="mb-0 small text-muted"),
                ]
            )
            alert_options = _alert_dropdown_options(store["alerts"])
            alert_overview = render_alerts_overview(store["alerts"])
            patterns = render_detected_patterns(store["alerts"])
            stats = (
                str(len(result.rows)),
                str(len(result.alerts)),
                str(len(enabled_detectors or [])),
                str(len(result.highlight_map)),
            )
            return (
                result.rows,
                row_styles,
                store,
                summary,
                visible_panel,
                patterns,
                alert_options,
                None,
                alert_overview,
                hidden,
                "Inspection",
                *stats,
                None,
                "inspect",
            )
        except Exception as exc:
            return (
                [], [], {},
                html.P(f"Error: {exc}", className="text-danger small mb-0"),
                visible_panel, empty_patterns, [], None, "", hidden, "Inspection",
                *empty_stats, None, "inspect",
            )

    @app.callback(
        Output("analysis-detail", "children", allow_duplicate=True),
        Output("analysis-detail", "style", allow_duplicate=True),
        Output("analysis-alerts-panel", "style", allow_duplicate=True),
        Output("analysis-panel-title", "children", allow_duplicate=True),
        Output("analysis-sidebar-view", "data", allow_duplicate=True),
        Output("analysis-alert-summary", "children", allow_duplicate=True),
        Input("analysis-alerts-btn", "n_clicks"),
        State("analysis-result-store", "data"),
        prevent_initial_call=True,
    )
    def on_show_alerts(_n_clicks: int, store: Dict[str, Any]) -> tuple:
        alerts = store.get("alerts", []) if store else []
        if not alerts:
            return (
                html.P("No alerts yet. Run analysis first.", className="text-muted small mb-0"),
                {"display": "block"},
                {"display": "none"},
                "Inspection",
                "inspect",
                "",
            )
        return (
            html.P("Pick an alert below to highlight its packets in the table.", className="small mb-0"),
            {"display": "none"},
            {"display": "block"},
            f"Alerts ({len(alerts)})",
            "alerts",
            render_alerts_overview(alerts),
        )

    @app.callback(
        Output("analysis-detail", "children", allow_duplicate=True),
        Output("analysis-detail", "style", allow_duplicate=True),
        Output("analysis-panel-title", "children", allow_duplicate=True),
        Output("analysis-table", "style_data_conditional", allow_duplicate=True),
        Output("analysis-selected-alert", "data", allow_duplicate=True),
        Input("analysis-alert-select", "value"),
        State("analysis-result-store", "data"),
        State("analysis-table", "data"),
        prevent_initial_call=True,
    )
    def on_alert_selected(
        alert_index: Optional[int],
        store: Dict[str, Any],
        table_data: List[Dict[str, Any]],
    ) -> tuple:
        if alert_index is None or not store or not table_data:
            raise PreventUpdate

        alert_index = int(alert_index)
        alerts = store.get("alerts", [])
        if alert_index < 0 or alert_index >= len(alerts):
            raise PreventUpdate

        alert = alerts[alert_index]
        packet_indices = alert.get("packet_indices", [])
        row_styles = build_row_highlight_styles(table_data, emphasis_indices=packet_indices)

        return (
            render_alert_detail(alert),
            {"display": "block"},
            f"Alert: {format_attack_pattern_label(alert.get('attack_type', ''))}",
            row_styles,
            alert_index,
        )

    @app.callback(
        Output("analysis-detail", "children", allow_duplicate=True),
        Output("analysis-detail", "style", allow_duplicate=True),
        Output("analysis-panel-title", "children", allow_duplicate=True),
        Output("analysis-table", "style_data_conditional", allow_duplicate=True),
        Output("analysis-selected-alert", "data", allow_duplicate=True),
        Input("analysis-table", "selected_rows"),
        State("analysis-table", "data"),
        State("analysis-result-store", "data"),
        State("analysis-selected-alert", "data"),
        prevent_initial_call=True,
    )
    def on_row_selected(
        selected_rows: Optional[List[int]],
        table_data: List[Dict[str, Any]],
        store: Dict[str, Any],
        selected_alert: Optional[int],
    ) -> tuple:
        if not selected_rows or not table_data:
            raise PreventUpdate

        row_index = selected_rows[0]
        row = table_data[row_index]
        packet_index = row.get("index", row_index)
        header = (
            f"P #{packet_index} | {row.get('protocol')} | {row.get('ip_src')} → {row.get('ip_dst')}"
        )
        matches = [
            alert for alert in store.get("alerts", [])
            if packet_index in alert.get("packet_indices", [])
        ]
        body = render_packet_inspection(header, matches)

        emphasis: Set[int] = set()
        new_selected_alert = selected_alert
        if selected_alert is not None:
            selected_alert = int(selected_alert)
            alerts = store.get("alerts", [])
            if 0 <= selected_alert < len(alerts):
                alert_packet_indices = set(alerts[selected_alert].get("packet_indices", []))
                if packet_index in alert_packet_indices:
                    emphasis = alert_packet_indices
                else:
                    new_selected_alert = None

        return (
            body,
            {"display": "block"},
            "Inspection",
            build_row_highlight_styles(table_data, emphasis_indices=emphasis or None),
            new_selected_alert,
        )
