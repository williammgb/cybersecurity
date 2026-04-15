import json
import os
import random
import time

import requests
import yaml

TARGET_SERVER = os.environ.get("TARGET_SERVER", "http://10.5.0.20:8000")
PROFILE_NAME = os.environ.get("ATTACK_PROFILE", "")
PROFILES_PATH = os.environ.get("ATTACK_PROFILES", "/app/profiles.yaml")
PACE_FILE = os.environ.get("TRAFFIC_PACE_PATH", "/app/logs/traffic_pace.json")
DEFAULT_PACE = os.environ.get("TRAFFIC_PACE", "normal")
DETECTOR_STATUS_URL = os.environ.get("DETECTOR_STATUS_URL", "http://10.5.0.30:8000/api/model/status")
ATTACKER_START_TIMEOUT_SECONDS = int(os.environ.get("ATTACKER_START_TIMEOUT_SECONDS", "240"))
ATTACKER_START_OFFSET_SECONDS = float(os.environ.get("ATTACKER_START_OFFSET_SECONDS", "0"))


def load_profiles() -> list[dict]:
    """Open the profiles.yaml file and load the profiles with attacker-specific parameters."""
    with open(PROFILES_PATH, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    return data.get("profiles", [])


def read_pace() -> str:
    """Same global pace as benign clients (detector dashboard writes traffic_pace.json)."""
    try:
        with open(PACE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        p = str(data.get("pace", DEFAULT_PACE)).lower()
        if p in ("slow", "normal", "fast"):
            return p
    except (OSError, json.JSONDecodeError, TypeError):
        pass
    return DEFAULT_PACE if DEFAULT_PACE in ("slow", "normal", "fast") else "normal"


def pace_scales(pace: str) -> tuple[float, float, float]:
    """
    Return (idle_between_bursts_scale, in_burst_interval_ms_scale, startup_delay_scale).
    Slow = fewer attacker events; fast = more — aligned with client_server pace intent.
    """
    if pace == "slow":
        return (2.15, 1.85, 1.7)
    if pace == "fast":
        return (0.52, 0.62, 0.55)
    return (1.0, 1.0, 1.0)


def pick_profile(profiles: list[dict]) -> dict:
    if PROFILE_NAME:
        for profile in profiles:
            if profile.get("name") == PROFILE_NAME:
                return profile
    weights = [int(p.get("weight", 1)) for p in profiles]
    return random.choices(profiles, weights=weights, k=1)[0]


def run_profile_attack(profile: dict) -> None:
    """Run the selected attack profile. Each attacker runs a different attack method."""
    url = f"{TARGET_SERVER}/process"
    print(f"[!] Running profile: {profile['name']} (pace from {PACE_FILE})")
    solo_chance = float(profile.get("solo_burst_chance", 0.25))

    wait_for_model_training()
    apply_start_offset(profile)
    pace = read_pace()
    idle_scale, interval_scale, startup_scale = pace_scales(pace)
    time.sleep(random.uniform(6.0, 14.0) * startup_scale)

    while True:
        pace = read_pace()
        idle_scale, interval_scale, _ = pace_scales(pace)

        idle_min = float(profile.get("idle_between_bursts_min", 4.0)) * idle_scale
        idle_max = float(profile.get("idle_between_bursts_max", 18.0)) * idle_scale
        sleep_s = random.uniform(idle_min, idle_max)
        print(f"[!] Pace={pace} sleeping {sleep_s:.1f}s before next burst")
        time.sleep(sleep_s)

        burst_min = int(profile["burst_size_min"])
        burst_max = int(profile["burst_size_max"])
        if random.random() < solo_chance:
            burst_size = 1
        else:
            burst_size = random.randint(burst_min, burst_max)

        for _ in range(burst_size):
            payload_text = random.choice(profile["payloads"])
            headers = {
                "User-Agent": random.choice(profile["user_agents"]),
                "X-Actor-Type": profile.get("actor_type", "attacker"),
            }
            payload = {
                "session": random.randint(1000, 9999),
                "data": payload_text,
                "request_id": random.randint(100000, 999999),
                "profile": profile["name"],
            }
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=2)
                print(f"[{profile['name']}] status={response.status_code} payload={payload_text[:35]}")
                if response.status_code == 403:
                    print(f"[{profile['name']}] blocked by SOAR.")
                    return
            except Exception as exc:
                print(f"[{profile['name']}] connection error: {exc}")
                return

            lo = int(profile["min_interval_ms"]) * interval_scale
            hi = int(profile["max_interval_ms"]) * interval_scale
            lo = max(30, int(lo))
            hi = max(lo + 1, int(hi))
            sleep_ms = random.randint(lo, hi)
            time.sleep(sleep_ms / 1000.0)

        time.sleep(random.uniform(0.3, 1.8) * idle_scale)


def wait_for_model_training() -> None:
    """Delay attacker activity until detector baseline model is trained."""
    waited = 0.0
    poll_interval = 5.0
    while waited < ATTACKER_START_TIMEOUT_SECONDS:
        try:
            response = requests.get(DETECTOR_STATUS_URL, timeout=2)
            if response.ok:
                data = response.json()
                if bool(data.get("trained")):
                    print("[!] Detector model is trained. Starting attacker traffic.")
                    return
                collected = int(data.get("baseline_collected", 0))
                required = int(data.get("baseline_required", 0))
                print(f"[!] Waiting for detector training {collected}/{required}...")
        except Exception as exc:
            print(f"[!] Waiting for detector status endpoint: {exc}")
        time.sleep(poll_interval)
        waited += poll_interval
    print("[!] Training wait timeout reached. Starting attacker traffic anyway.")


def apply_start_offset(profile: dict) -> None:
    """Stagger attacker services after model training to keep scenarios readable."""
    profile_offsets = {
        "sql_injection_bursty": 0.0,
        "low_and_slow_recon": 20.0,
        "credential_stuffing_fast": 40.0,
        "cmd_injection_opportunistic": 60.0,
    }
    base_offset = float(profile_offsets.get(str(profile.get("name", "")), 15.0))
    delay = max(0.0, ATTACKER_START_OFFSET_SECONDS + base_offset + random.uniform(0.0, 6.0))
    if delay > 0:
        print(f"[!] Applying ordered startup delay: {delay:.1f}s")
        time.sleep(delay)


if __name__ == "__main__":
    profiles = load_profiles()
    if not profiles:
        raise RuntimeError("No attacker profiles found.")
    selected_profile = pick_profile(profiles)
    run_profile_attack(selected_profile)
