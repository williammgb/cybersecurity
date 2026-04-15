import hashlib
import logging
import os
from datetime import datetime, timezone

import requests

# configurate logging: add format and output direction
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    handlers=[
        logging.FileHandler("/app/logs/local_access.log"), # write log to this file
        logging.StreamHandler() # print log to terminal
    ]
)
app_logger = logging.getLogger("APP")

DETECTOR_URL = os.environ.get("DETECTOR_URL")

# Simulated geo/ISP pools (deterministic per client IP for demo consistency).
_SIM_LOCATIONS: list[tuple[str, str, str]] = [
    ("United States", "New York", "Comcast Cable"),
    ("United States", "Seattle", "Ziply Fiber"),
    ("Netherlands", "Amsterdam", "KPN B.V."),
    ("Germany", "Frankfurt", "Deutsche Telekom AG"),
    ("United Kingdom", "London", "BT Group plc"),
    ("Japan", "Tokyo", "NTT Communications"),
    ("Australia", "Sydney", "Telstra Corporation"),
    ("Canada", "Toronto", "Rogers Communications"),
    ("Brazil", "São Paulo", "Vivo"),
    ("India", "Mumbai", "Reliance Jio"),
    ("France", "Paris", "Orange S.A."),
    ("South Korea", "Seoul", "SK Broadband"),
]


def _device_type_from_user_agent(user_agent: str) -> str:
    ua = (user_agent or "").lower()
    if "tablet" in ua or "ipad" in ua:
        return "tablet"
    if any(
        x in ua
        for x in (
            "mobile",
            "iphone",
            "android",
            "mobilesafari",
            "cfnetwork",
        )
    ):
        return "mobile"
    if any(x in ua for x in ("python-requests", "curl/", "wget/", "sqlmap", "headlesschrome", "attackbot", "reconcrawler", "maliciousbot")):
        return "automation"
    return "desktop"


def simulated_session_metadata(client_ip: str, user_agent: str) -> dict[str, str]:
    """Deterministic fake country, city, ISP from IP; device_type from User-Agent."""
    h = int(hashlib.md5(client_ip.encode(), usedforsecurity=False).hexdigest(), 16)
    country, city, isp = _SIM_LOCATIONS[h % len(_SIM_LOCATIONS)]
    return {
        "country": country,
        "city": city,
        "isp": isp,
        "device_type": _device_type_from_user_agent(user_agent),
    }


def log_event(
    client_ip: str,
    method: str,
    endpoint: str,
    status_code: int,
    payload: str,
    user_agent: str,
    actor_type: str = "unknown",
):
    # 1. Gather data from event
    meta = simulated_session_metadata(client_ip, user_agent)
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": client_ip,
        "actor_type": actor_type,
        "method": method,
        "endpoint": endpoint,
        "status_code": status_code,
        "payload": payload,
        "payload_size": len(payload),
        "path_depth": endpoint.count('/'),
        "is_bot_ua": int("bot" in user_agent.lower()),
        "country": meta["country"],
        "city": meta["city"],
        "isp": meta["isp"],
        "device_type": meta["device_type"],
    }
    # 2. Send event to detector
    try:
        requests.post(DETECTOR_URL, json=event, timeout=0.5)
    except requests.exceptions.RequestException as e:
        app_logger.error(f"Failed to log event to SIEM: {e}")
    # 3. Log event to file and terminal
    app_logger.info("Event: %s (%s) -> %s (%s)", client_ip, actor_type, endpoint, status_code)