"""ScapyNIDS Dash application shell."""

from __future__ import annotations

import logging
import os
import warnings

warnings.filterwarnings("ignore", module="scapy")
logging.getLogger("scapy").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

import dash_bootstrap_components as dbc
from dash import Dash, dcc, html

from backend.core.models import DetectorConfig
from gui import analysis_tab, detector_config_tab, information_tab, traffic_tab
from gui.log_util import log

_NAVBAR = dbc.Navbar(
    dbc.Container(
        dbc.NavbarBrand(
            [
                html.Span("ScapyNIDS", className="cs-brand-title"),
                html.Span("Network Intrusion Detection System", className="cs-brand-sub"),
            ],
            className="d-flex align-items-baseline flex-wrap py-0",
        ),
        fluid=True,
        className="py-1",
    ),
    className="cs-navbar mb-2",
    color="light",
    dark=False,
    sticky="top",
)


def create_app() -> Dash:
    """Create and configure the Dash application."""
    app = Dash(
        __name__,
        external_stylesheets=[dbc.themes.FLATLY, "/assets/custom.css"],
        suppress_callback_exceptions=True,
        title="ScapyNIDS",
    )

    app.layout = dbc.Container(
        [
            _NAVBAR,
            dcc.Store(id="shared-pcap-path"),
            dcc.Store(id="traffic-request"),
            dcc.Store(id="detector-config-store", data=DetectorConfig().to_dict()),
            dcc.Tabs(
                id="main-tabs",
                value="traffic-tab",
                children=[
                    dcc.Tab(label="Traffic Generation", value="traffic-tab", children=traffic_tab.layout()),
                    dcc.Tab(
                        label="Detector Configuration",
                        value="detector-config-tab",
                        children=detector_config_tab.layout(),
                    ),
                    dcc.Tab(label="Packet Analysis", value="analysis-tab", children=analysis_tab.layout()),
                    dcc.Tab(label="Information", value="information-tab", children=information_tab.layout()),
                ],
                className="mb-2",
            ),
        ],
        fluid=True,
        className="px-3 pb-2",
        style={"maxWidth": "100%"},
    )

    traffic_tab.register_callbacks(app)
    detector_config_tab.register_callbacks(app)
    analysis_tab.register_callbacks(app)
    log("Callbacks registered (traffic + detector config + analysis)")
    return app


def main() -> None:
    """Start the Dash development server."""
    os.makedirs("data", exist_ok=True)
    app = create_app()
    log("Starting Dash server at http://127.0.0.1:8050/")
    app.run(debug=True, port=8050, use_reloader=True)


if __name__ == "__main__":
    main()
