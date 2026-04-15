import json
import os
import random
import threading
import time

import requests

TARGET_URL = os.environ.get("TARGET_SERVER", "http://10.5.0.20:8000")
LOCAL_IP = os.environ.get("CLIENT_IP", "10.5.0.25")
PACE_FILE = os.environ.get("TRAFFIC_PACE_PATH", "/app/logs/traffic_pace.json")

# Fallback when file is missing (e.g. local run without volume).
DEFAULT_PACE = os.environ.get("TRAFFIC_PACE", "normal")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
    "MobileSafari/604.1 CFNetwork/1240.7 Darwin/20.5.0",
]

NORMAL_DATA_POOL = [
    "normal_activity",
    "login_username=john_doe",
    "search_query=best+python+libraries",
    "view_item_id=9821",
    "add_to_cart_item=SKU_2049",
    "remove_from_cart_item=SKU_1033",
    "checkout_step=shipping_address",
    "shipping_country=US",
    "payment_method=credit_card",
    "feedback=Great service and fast delivery",
    "settings_change=notifications_enabled",
    "settings_change=dark_mode_enabled",
    "profile_visibility=public",
    "page_scroll_depth=620",
    "page_time_spent_seconds=145",
    "newsletter_signup=email",
    "contact_form_message=Please call me back",
    "support_ticket_category=billing",
    "support_ticket_priority=low",
    "rating=5",
    "search_filter=price_low_to_high",
    "language_preference=en",
    "timezone=UTC",
    "logout=true"
]

def read_pace() -> str:
    try:
        with open(PACE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        p = str(data.get("pace", DEFAULT_PACE)).lower()
        if p in ("slow", "normal", "fast"):
            return p
    except (OSError, json.JSONDecodeError, TypeError):
        pass
    return DEFAULT_PACE if DEFAULT_PACE in ("slow", "normal", "fast") else "normal"


def sleep_range_for_pace(pace: str) -> tuple[float, float]:
    """
    Sleep between requests per simulated user thread. With 3 client containers × 3 threads
    (9 loops), mean interval ≈ 540 / target_events_per_minute across all benign clients.
    Targets: slow ~8/min, normal ~15/min, fast ~25/min (attackers add more on top).
    """
    if pace == "slow":
        return (62.0, 73.0)
    if pace == "fast":
        return (19.0, 24.0)
    return (32.0, 40.0)


def simulate_user(user_id: int) -> None:
    actions = ["/process", "/invalid_page"]
    headers_base = {"User-Agent": random.choice(USER_AGENTS), "X-Actor-Type": "normal_client"}
    while True:
        try:
            path = random.choices(actions, weights=[90, 10])[0]
            url = f"{TARGET_URL}{path}"
            headers = {**headers_base, "User-Agent": random.choice(USER_AGENTS)}
            payload = {
                "user_id": user_id,
                "session": random.randint(1000, 9999),
                "data": random.choice(NORMAL_DATA_POOL),
                "request_id": random.randint(100000, 999999),
            }
            response = requests.post(url, json=payload, headers=headers, timeout=2)
            print(f"[User {user_id}] Status: {response.status_code}")
        except Exception as e:
            print(f"[User {user_id}] Error: {e}")

        pace = read_pace()
        lo, hi = sleep_range_for_pace(pace)
        time.sleep(random.uniform(lo, hi))


if __name__ == "__main__":
    print(f"Starting client simulation from {LOCAL_IP} (pace file: {PACE_FILE})")
    # Start 3 background threads (deamon=True), simulating 3 users in parallel
    for i in range(3):
        t = threading.Thread(target=simulate_user, args=(i,))
        t.daemon = True
        t.start()
    # Keep the main thread alive so the threads continue working
    while True:
        time.sleep(1)
