from __future__ import annotations

import hashlib
from typing import Any

import dash
import dash_cytoscape as cyto
import networkx as nx
import numpy as np
from dash import Input, Output, State, callback, ctx, dcc, html, no_update

from simulation import CyberNetworkSimulation, MessageLogEntry, SimulationConfig

_layout_pos: dict[str, np.ndarray] = {}
_sim: CyberNetworkSimulation | None = None


def _get_sim() -> CyberNetworkSimulation:
    global _sim
    if _sim is None:
        _sim = CyberNetworkSimulation(
            network_name="LiveNet",
            config=SimulationConfig(
                initial_nodes=12,
                initial_edges=16,
                suspicious_threshold=3,
                prob_add_node=0.20,
                prob_add_edge=0.35,
                prob_send_message=0.4,
                malicious_node_fraction=0.25,
                malicious_send_suspicious_prob=0.35,
            ),
        )
    return _sim


def _reset_sim() -> CyberNetworkSimulation:
    global _sim, _layout_pos
    _layout_pos = {}
    _sim = CyberNetworkSimulation(
        network_name="LiveNet",
        config=SimulationConfig(
            initial_nodes=12,
            initial_edges=16,
            suspicious_threshold=3,
            prob_add_node=0.20,
            prob_add_edge=0.35,
            prob_send_message=0.4,
            malicious_node_fraction=0.12,
            malicious_send_suspicious_prob=0.35,
        ),
    )
    return _sim


def _stable_seed(name: str) -> int:
    return int(hashlib.md5(name.encode(), usedforsecurity=False).hexdigest()[:8], 16) % (2**31)


def _compute_positions(sim: CyberNetworkSimulation) -> dict[str, dict[str, float]]:
    """NetworkX  layout, scales iteration count for large graphs."""
    global _layout_pos
    G = nx.Graph()
    for name in sim.network.nodes:
        G.add_node(name)
    for a, b, _d in sim.edges_for_graph():
        G.add_edge(a, b)
    if len(G.nodes) == 0:
        return {}
    n = len(G.nodes)
    k = 2.5 / max(1, n**0.5)
    for node in G.nodes:
        if node not in _layout_pos:
            rng = np.random.RandomState(_stable_seed(node))
            _layout_pos[node] = rng.rand(2) * 2.0 - 1.0
    it = 50 if n < 100 else (35 if n < 300 else 28)
    pos = nx.spring_layout(G, pos=_layout_pos, k=k, iterations=it, seed=42)
    for node in pos:
        _layout_pos[node] = pos[node]
    scale_x, scale_y = 720.0, 520.0
    return {
        name: {"x": float(pos[name][0] * scale_x), "y": float(pos[name][1] * scale_y)}
        for name in pos
    }


def _build_elements(sim: CyberNetworkSimulation, positions: dict[str, dict[str, float]]) -> list[dict[str, Any]]:
    elements: list[dict[str, Any]] = []
    for name in sim.network.nodes:
        pos = positions.get(name, {"x": 0, "y": 0})
        short = name if len(name) <= 10 else name[:9] + "…"
        cls = "criminal" if sim.is_flagged_criminal(name) else "clean"
        elements.append(
            {
                "data": {"id": name, "label": short},
                "classes": cls,
                "position": pos,
            }
        )
    seen: set[tuple[str, str]] = set()
    for a, b, dist in sim.edges_for_graph():
        key = (a, b) if a < b else (b, a)
        if key in seen:
            continue
        seen.add(key)
        eid = f"{a}|{b}"
        elements.append(
            {
                "data": {
                    "id": eid,
                    "source": a,
                    "target": b,
                    "weight": dist,
                }
            }
        )
    return elements


def _format_message_card(m: MessageLogEntry) -> html.Div:
    is_sus = m.suspicious
    border = "3px solid #f59e0b" if is_sus else "1px solid #334155"
    bg = "rgba(245, 158, 11, 0.08)" if is_sus else "rgba(15, 23, 42, 0.6)"
    badge = html.Span(
        "SUSPICIOUS",
        className="msg-badge",
        style={
            "background": "#b45309",
            "color": "#fffbeb",
            "fontSize": "10px",
            "padding": "2px 6px",
            "borderRadius": "4px",
            "marginLeft": "8px",
        },
    )
    triggers = (
        html.Div(
            "Triggers: " + ", ".join(m.matched_triggers),
            style={"fontSize": "11px", "color": "#fcd34d", "marginTop": "6px"},
        )
        if m.matched_triggers
        else None
    )
    return html.Div(
        [
            html.Div(
                [
                    html.Span(f"tick {m.tick}", style={"color": "#64748b", "fontFamily": "JetBrains Mono, monospace"}),
                    badge if is_sus else None,
                ],
                style={"display": "flex", "alignItems": "center", "marginBottom": "6px"},
            ),
            html.Div(
                f"{m.origin_name}  ->  {m.destination_name}",
                style={"color": "#94a3b8", "fontSize": "13px", "fontWeight": "600"},
            ),
            html.P(
                m.content_preview,
                style={
                    "margin": "8px 0 0 0",
                    "color": "#e2e8f0",
                    "fontSize": "13px",
                    "lineHeight": "1.45",
                },
            ),
            triggers,
        ],
        style={
            "borderLeft": border,
            "background": bg,
            "padding": "12px 14px",
            "marginBottom": "10px",
            "borderRadius": "0 8px 8px 0",
        },
    )


CY_STYLE: list[dict[str, Any]] = [
    {
        "selector": "node",
        "style": {
            "label": "data(label)",
            "width": 36,
            "height": 36,
            "font-size": "11px",
            "color": "#f1f5f9",
            "text-valign": "center",
            "text-halign": "center",
            "border-width": 2,
            "border-color": "#0f172a",
        },
    },
    {"selector": "node.clean", "style": {"background-color": "#16a34a"}},
    {"selector": "node.criminal", "style": {"background-color": "#dc2626"}},
    {"selector": "node:selected", "style": {"border-width": 4, "border-color": "#38bdf8"}},
    {
        "selector": "edge",
        "style": {
            "width": 2,
            "line-color": "#475569",
            "curve-style": "bezier",
            "opacity": 0.85,
            "target-arrow-shape": "none",
        },
    },
]

app = dash.Dash(__name__)
app.title = "CyberNetwork — Live simulation"

app.index_string = """
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,600;0,9..40,700;1,9..40,400&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
        <style>
            body { margin: 0; font-family: 'DM Sans', system-ui, sans-serif; background: #020617; }
            .msg-badge { font-family: 'JetBrains Mono', monospace; letter-spacing: 0.04em; }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
"""

app.layout = html.Div(
    className="app-root",
    style={
        "display": "flex",
        "flexDirection": "column",
        "height": "100vh",
        "background": "linear-gradient(165deg, #020617 0%, #0f172a 45%, #020617 100%)",
        "color": "#e2e8f0",
        "overflow": "hidden",
    },
    children=[
        html.Header(
            style={
                "display": "flex",
                "alignItems": "center",
                "justifyContent": "space-between",
                "padding": "12px 20px",
                "borderBottom": "1px solid #1e293b",
                "background": "rgba(15, 23, 42, 0.85)",
                "backdropFilter": "blur(8px)",
            },
            children=[
                html.Div(
                    [
                        html.H1(
                            "CyberNetwork",
                            style={
                                "margin": 0,
                                "fontSize": "1.35rem",
                                "fontWeight": "700",
                                "letterSpacing": "-0.02em",
                            },
                        ),
                        html.P(
                            "Live traffic · flagged nodes in red",
                            style={"margin": "4px 0 0 0", "color": "#64748b", "fontSize": "13px"},
                        ),
                    ]
                ),
                html.Div(
                    style={"display": "flex", "gap": "12px", "alignItems": "center"},
                    children=[
                        html.Button(
                            "Pause",
                            id="btn-pause",
                            n_clicks=0,
                            style={
                                "padding": "8px 16px",
                                "borderRadius": "8px",
                                "border": "1px solid #334155",
                                "background": "#1e293b",
                                "color": "#e2e8f0",
                                "cursor": "pointer",
                                "fontWeight": "600",
                            },
                        ),
                        html.Button(
                            "Reset network",
                            id="btn-reset",
                            n_clicks=0,
                            style={
                                "padding": "8px 16px",
                                "borderRadius": "8px",
                                "border": "1px solid #7f1d1d",
                                "background": "#450a0a",
                                "color": "#fecaca",
                                "cursor": "pointer",
                                "fontWeight": "600",
                            },
                        ),
                        dcc.Dropdown(
                            id="speed",
                            options=[
                                {"label": "Slow", "value": 1200},
                                {"label": "Normal", "value": 700},
                                {"label": "Fast", "value": 350},
                            ],
                            value=700,
                            clearable=False,
                            style={"width": "130px", "color": "#0f172a"},
                        ),
                    ],
                ),
            ],
        ),
        html.Div(
            style={"display": "flex", "flex": "1", "minHeight": 0},
            children=[
                html.Div(
                    style={
                        "flex": "1",
                        "position": "relative",
                        "minWidth": 0,
                        "borderRight": "1px solid #1e293b",
                    },
                    children=[
                        html.Div(
                            id="stats-bar",
                            style={
                                "position": "absolute",
                                "top": "12px",
                                "left": "12px",
                                "zIndex": 2,
                                "padding": "8px 14px",
                                "background": "rgba(15, 23, 42, 0.92)",
                                "borderRadius": "8px",
                                "border": "1px solid #334155",
                                "fontSize": "12px",
                                "fontFamily": "JetBrains Mono, monospace",
                                "color": "#94a3b8",
                            },
                            children="tick 0 · nodes 0 · edges 0 · flagged 0",
                        ),
                        cyto.Cytoscape(
                            id="cyto",
                            elements=[],
                            stylesheet=CY_STYLE,
                            layout={"name": "preset"},
                            style={"width": "100%", "height": "100%", "minHeight": "480px"},
                            zoomingEnabled=True,
                            panningEnabled=True,
                            userZoomingEnabled=True,
                            userPanningEnabled=True,
                            boxSelectionEnabled=False,
                            autoungrabify=False,
                            autounselectify=False,
                            minZoom=0.2,
                            maxZoom=2.5,
                        ),
                    ],
                ),
                html.Div(
                    style={
                        "width": "380px",
                        "minWidth": "300px",
                        "display": "flex",
                        "flexDirection": "column",
                        "background": "rgba(2, 6, 23, 0.5)",
                    },
                    children=[
                        html.Div(
                            style={
                                "padding": "14px 16px",
                                "borderBottom": "1px solid #1e293b",
                            },
                            children=[
                                html.H2(
                                    "Message stream",
                                    style={"margin": 0, "fontSize": "1rem", "fontWeight": "700"},
                                ),
                                html.P(
                                    "Newest at the top · suspicious traffic highlighted",
                                    style={"margin": "6px 0 0 0", "fontSize": "12px", "color": "#64748b"},
                                ),
                            ],
                        ),
                        html.Div(
                            id="node-panel",
                            style={
                                "padding": "12px 16px",
                                "borderBottom": "1px solid #1e293b",
                                "maxHeight": "220px",
                                "overflowY": "auto",
                                "background": "rgba(15, 23, 42, 0.4)",
                            },
                            children=html.P(
                                "Click a node to see role, traffic, and neighbor analysis.",
                                style={"margin": 0, "color": "#64748b", "fontSize": "13px", "lineHeight": "1.5"},
                            ),
                        ),
                        html.Div(
                            id="msg-stream",
                            style={
                                "flex": "1",
                                "overflowY": "auto",
                                "padding": "14px 16px 24px",
                            },
                            children=[],
                        ),
                    ],
                ),
            ],
        ),
        dcc.Interval(id="timer", interval=700, n_intervals=0, disabled=False),
        dcc.Store(id="paused", data=False),
    ],
)


@callback(
    Output("paused", "data"),
    Output("btn-pause", "children"),
    Output("timer", "disabled"),
    Input("btn-pause", "n_clicks"),
    State("paused", "data"),
    prevent_initial_call=True,
)
def toggle_pause(_n, paused):
    new = not bool(paused)
    # Stop the interval while paused so the sim cannot advance (State alone can race with the timer).
    return new, "Resume" if new else "Pause", new


@callback(
    Output("timer", "interval"),
    Input("speed", "value"),
)
def set_interval(ms):
    return ms if ms else 700


@callback(
    Output("cyto", "elements"),
    Output("stats-bar", "children"),
    Output("msg-stream", "children"),
    Input("timer", "n_intervals"),
    Input("btn-reset", "n_clicks"),
    Input("paused", "data"),
    prevent_initial_call=False,
)
def tick_graph(n_intervals, reset_clicks, paused):
    if ctx.triggered_id == "btn-reset":
        sim = _reset_sim()
    elif ctx.triggered_id == "paused":
        sim = _get_sim()
    else:
        sim = _get_sim()
        if not paused:
            sim.step()

    positions = _compute_positions(sim)
    elements = _build_elements(sim, positions)
    flagged_n = len(sim.flagged_criminal_names())
    stats = (
        f"tick {sim.tick_index} · nodes {len(sim.network.nodes)} · "
        f"edges {len(sim.edges_for_graph())} · flagged {flagged_n}"
        + (" · PAUSED" if paused else "")
    )
    msgs = list(reversed(sim.recent_messages(120)))
    stream = [_format_message_card(m) for m in msgs]
    if not stream:
        stream = [
            html.P(
                "No messages yet. The simulation will generate traffic automatically.",
                style={"color": "#64748b", "fontSize": "13px"},
            )
        ]
    return elements, stats, stream


@callback(
    Output("node-panel", "children"),
    Input("cyto", "tapNodeData"),
    prevent_initial_call=True,
)
def show_node(data):
    if not data:
        return no_update
    nid = data.get("id")
    if not nid:
        return no_update
    sim = _get_sim()
    intel = sim.neighbor_intel(nid)
    if not intel:
        return html.P("Unknown node.", style={"color": "#94a3b8"})
    role = "Flagged (possible criminal)" if intel.is_criminal else "Not flagged"
    role_color = "#f87171" if intel.is_criminal else "#4ade80"
    friends = intel.closest_friends[:6]
    friends_el = (
        html.Ul(
            [html.Li(f"{n} — edge weight {d}", style={"margin": "4px 0"}) for n, d in friends],
            style={"margin": "8px 0 0 0", "paddingLeft": "18px", "color": "#cbd5e1", "fontSize": "13px"},
        )
        if friends
        else html.P("No neighbors yet.", style={"color": "#64748b", "fontSize": "13px"})
    )
    sus_nb = intel.neighbors_with_suspicious_activity[:8]
    sus_el = (
        html.Div(
            [
                html.Div("Neighbors with suspicious sends", style={"fontSize": "11px", "color": "#94a3b8", "marginTop": "12px"}),
                html.Ul(
                    [html.Li(f"{n} ({c} suspicious)", style={"margin": "4px 0"}) for n, c in sus_nb],
                    style={"margin": "6px 0 0 0", "paddingLeft": "18px", "color": "#fcd34d", "fontSize": "12px"},
                ),
            ]
        )
        if sus_nb
        else None
    )
    flagged_nb = intel.neighbors_flagged
    fn_el = (
        html.Div(
            [
                html.Div("Flagged neighbors", style={"fontSize": "11px", "color": "#94a3b8", "marginTop": "8px"}),
                html.P(", ".join(flagged_nb), style={"color": "#f87171", "fontSize": "13px", "margin": "6px 0 0 0"}),
            ]
        )
        if flagged_nb
        else None
    )
    return html.Div(
        [
            html.Div(
                intel.node_name,
                style={"fontFamily": "JetBrains Mono, monospace", "fontWeight": "700", "fontSize": "15px", "color": "#f8fafc"},
            ),
            html.Div(role, style={"color": role_color, "fontWeight": "600", "marginTop": "6px", "fontSize": "13px"}),
            html.Div(
                f"Suspicious messages sent: {intel.suspicious_count} · Total sent: {intel.total_messages_sent}",
                style={"fontSize": "12px", "color": "#94a3b8", "marginTop": "8px"},
            ),
            html.Div("Closest ties (by edge distance)", style={"fontSize": "11px", "color": "#64748b", "marginTop": "12px"}),
            friends_el,
            fn_el,
            sus_el,
        ]
    )


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=8050)
