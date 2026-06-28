"""Dash tab for configuring detector thresholds."""

from __future__ import annotations

from typing import Any, Dict, List

import dash_bootstrap_components as dbc
from dash import Input, Output, State, html
from dash.exceptions import PreventUpdate

from backend.core.models import DetectorConfig
from gui.theme import labeled_input, page_header

_DEFAULTS = DetectorConfig().to_dict()

_DETECTOR_LABELS = {
    "port_scan_horizontal": "Port Scan (Horizontal)",
    "port_scan_vertical": "Port Scan (Vertical)",
    "syn_flood": "SYN Flood",
    "dns_tunneling": "DNS Tunneling",
    "suspicious_payload": "Suspicious Payload",
    "beaconing": "Beaconing",
    "data_exfiltration": "Data Exfiltration",
    "arp_spoofing": "ARP Spoofing",
}


def _num_input(component_id: str, value: Any, step: str = "1") -> dbc.Input:
    return dbc.Input(id=component_id, type="number", value=value, step=step, size="sm")


def _detector_block(detector_key: str, fields: Dict[str, Any]) -> dbc.Col:
    """Build one detector configuration card for the grid layout."""
    inputs = []
    for field_name, default_value in fields.items():
        input_id = f"detector-{detector_key}-{field_name}"
        if isinstance(default_value, float):
            inputs.append(labeled_input(field_name, _num_input(input_id, default_value, step="0.01")))
        elif isinstance(default_value, int):
            inputs.append(labeled_input(field_name, _num_input(input_id, default_value)))
        else:
            inputs.append(
                labeled_input(
                    field_name,
                    dbc.Input(id=input_id, type="text", value=str(default_value), size="sm"),
                )
            )
    return dbc.Col(
        dbc.Card(
            [
                dbc.CardHeader(_DETECTOR_LABELS.get(detector_key, detector_key), className="py-1"),
                dbc.CardBody(inputs, className="py-2 cs-detector-block-body"),
            ],
            className="cs-card h-100",
        ),
        lg=3,
        md=6,
        sm=12,
        className="mb-2",
    )


def layout() -> html.Div:
    """Build the detector configuration tab layout."""
    blocks = [_detector_block(key, fields) for key, fields in _DEFAULTS.items()]
    return html.Div(
        [
            page_header("Detector Configuration"),
            html.P(
                "Tune detection thresholds before running PCAP analysis. "
                "Click Apply to save settings for the Packet Analysis tab.",
                className="text-muted small mb-2",
            ),
            dbc.Row(blocks, className="g-2"),
            dbc.Button("Apply Settings", id="detector-config-apply", color="primary", size="sm", className="mt-2 mb-2"),
            html.Div(id="detector-config-status", className="cs-summary-box small"),
        ],
        className="tab-content",
    )


def _all_detector_states() -> List[State]:
    """Collect State() for every detector input field."""
    states: List[State] = []
    for detector_key, fields in _DEFAULTS.items():
        for field_name in fields:
            states.append(State(f"detector-{detector_key}-{field_name}", "value"))
    return states


def register_callbacks(app: Any) -> None:
    """Wire detector config form to the shared store."""

    @app.callback(
        Output("detector-config-store", "data"),
        Output("detector-config-status", "children"),
        Input("detector-config-apply", "n_clicks"),
        *_all_detector_states(),
        prevent_initial_call=True,
    )
    def apply_detector_config(n_clicks: int, *field_values: Any) -> tuple[Dict[str, Any], str]:
        if not n_clicks:
            raise PreventUpdate

        data: Dict[str, Dict[str, Any]] = {}
        idx = 0
        for detector_key, fields in _DEFAULTS.items():
            data[detector_key] = {}
            for field_name, default_value in fields.items():
                raw = field_values[idx]
                idx += 1
                if isinstance(default_value, bool):
                    data[detector_key][field_name] = bool(raw)
                elif isinstance(default_value, int):
                    try:
                        data[detector_key][field_name] = int(raw)
                    except (TypeError, ValueError):
                        data[detector_key][field_name] = default_value
                elif isinstance(default_value, float):
                    try:
                        data[detector_key][field_name] = float(raw)
                    except (TypeError, ValueError):
                        data[detector_key][field_name] = default_value
                else:
                    data[detector_key][field_name] = str(raw) if raw is not None else default_value

        return data, "Settings applied. Run analysis on the Packet Analysis tab to use these thresholds."
