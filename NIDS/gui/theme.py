"""Shared layout primitives for the Dash GUI."""

from __future__ import annotations

from typing import Any

import dash_bootstrap_components as dbc
from dash import html


def page_header(title: str, subtitle: str = "") -> html.Div:
    """Render a compact section header."""
    children = [html.Div(title, className="cs-page-title")]
    if subtitle:
        children.append(html.Div(subtitle, className="cs-page-sub"))
    return html.Div(children, className="mb-1")


def labeled_input(label: str, component: Any) -> html.Div:
    """Wrap a form control with a styled label."""
    return html.Div([html.Div(label, className="cs-label"), component])


def action_button(text: str, button_id: str, color: str = "primary", outline: bool = False) -> html.Button:
    """Compact Bootstrap button with explicit type=button for reliable Dash callbacks."""
    css = f"btn btn-{'outline-' if outline else ''}{color} btn-sm"
    return html.Button(text, id=button_id, n_clicks=0, type="button", className=css)


def stat_card(label: str, value_id: str, color: str = "#2563eb") -> dbc.Col:
    """Build a compact inline KPI stat card for the analysis dashboard."""
    return dbc.Col(
        dbc.Card(
            dbc.CardBody(
                html.Div(
                    [
                        html.Span(label, className="cs-stat-label-inline"),
                        html.Span(id=value_id, children="—", className="cs-stat-value-inline", style={"color": color}),
                    ],
                    className="d-flex justify-content-between align-items-center",
                ),
                className="py-1 px-2",
            ),
            className="cs-card cs-stat-inline",
        ),
        md=3,
        sm=6,
        className="mb-1",
    )
