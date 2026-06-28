"""Simple console logging for GUI and backend actions."""

from __future__ import annotations

from datetime import datetime


def log(message: str) -> None:
    """Print a timestamped log line to the terminal."""
    stamp = datetime.now().strftime("%H:%M:%S")
    print(f"[ScapyNIDS {stamp}] {message}", flush=True)
