import asyncio
import json
import logging
import os
import re
import sqlite3
import tempfile
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import numpy as np
import pandas as pd
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sklearn.ensemble import IsolationForest


def _detector_log_file() -> str:
    path = os.environ.get("DETECTOR_LOG_FILE", "/app/logs/local_access.log")
    parent = os.path.dirname(path)
    if parent and os.path.isdir(parent):
        return path
    return os.path.join(tempfile.gettempdir(), "detector_local_access.log")


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[
        logging.FileHandler(_detector_log_file()),
        logging.StreamHandler(),
    ],
)
detector_logger = logging.getLogger("DETECTOR")


_ATTACKER_PHRASES = frozenset(
    {
        "or 1=1",
        "' union",
        "union select",
        "information_schema",
        "xp_cmdshell",
        "benchmark(",
        "sleep(",
        "/etc/passwd",
        "/proc/self",
        "/var/www",
        "/root",
        "c:\\windows\\system32",
        "..\\",
        "../",
        "wget http",
        "curl http",
        "bash -i",
        "$(whoami)",
        "bash -c",
        "sh -c",
        "cmd /c",
        "powershell",
        "*/",
        "/*",
    }
)
# detect strings like union select, select * from, insert into, drop table, delete from, update set
_SQL_FRAGMENT_RE = re.compile(
    r"\b(union\s+select|select\s+[\w\*]+\s+from|insert\s+into|drop\s+table|delete\s+from|update\s+\w+\s+set)\b",
    re.IGNORECASE,
)
# detect shell commands like whoami, uname, wget, curl, bash
_SHELL_TOKEN_RE = re.compile(
    r"\b(whoami|uname|wget|curl|bash)\b",
    re.IGNORECASE,
)
# detect standalone shell 'id' / 'nc' (not inside other string like user_id)
_SHELL_ID_OR_NC_RE = re.compile(r"(?:^|[;&|`\n\r])\s*\b(id|nc)\b\s*(?:[;&|`]|$|[|]\s|\s+\|)", re.IGNORECASE)
_CREDENTIAL_STUFFING_RE = re.compile(
    r"(username|user|email)\s*=\s*[^&\s]+.*(password|pass|pwd)\s*=\s*[^&\s]+",
    re.IGNORECASE,
)
_COMMON_CRED_VALUE_RE = re.compile(
    r"(admin|root|guest|test|toor|welcome1)",
    re.IGNORECASE,
)


def payload_has_attack_keyword(text: str) -> bool:
    """Return True if payload text matches attack patterns."""
    low = (text or "").lower()
    if any(p in low for p in _ATTACKER_PHRASES):
        return True
    if "'--" in low or '"--' in low:
        return True
    if "`" in low or "$(" in low:
        return True
    if _SQL_FRAGMENT_RE.search(low):
        return True
    if _SHELL_TOKEN_RE.search(low):
        return True
    if _SHELL_ID_OR_NC_RE.search(low):
        return True
    return False


class EventStore:
    """Store events, detections and blocks in a SQLite database."""
    def __init__(self, db_path: str) -> None:
        """Initialize the event store with the database path."""
        self.db_path = db_path
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        """Create a connection to the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row # allows accessing rows like dictionaries
        return conn

    def _init_db(self) -> None:
        """Initialize the database tables."""
        with self._conn() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, timestamp TEXT, source_ip TEXT, actor_type TEXT, method TEXT, endpoint TEXT, status_code INTEGER, payload TEXT, signal_type TEXT, risk_delta INTEGER, risk_total INTEGER, decision TEXT, reason TEXT, country TEXT, city TEXT, isp TEXT, device_type TEXT)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS detections (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT, signal_type TEXT, value REAL, note TEXT, related_event_id TEXT, related_event_snapshot TEXT)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT, action TEXT, reason TEXT)"
            )

    def insert_event(self, record: dict[str, Any]) -> None:
        """Insert an event into the database."""
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO events (event_id, timestamp, source_ip, actor_type, method, endpoint, status_code, payload, signal_type, risk_delta, risk_total, decision, reason, country, city, isp, device_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record["event_id"],
                    record["timestamp"],
                    record["source_ip"],
                    record["actor_type"],
                    record["method"],
                    record["endpoint"],
                    record["status_code"],
                    record["payload"],
                    record["signal_type"],
                    record["risk_delta"],
                    record["risk_total"],
                    record["decision"],
                    record["reason"],
                    record.get("country", ""),
                    record.get("city", ""),
                    record.get("isp", ""),
                    record.get("device_type", ""),
                ),
            )

    def insert_detection(
        self,
        timestamp: str,
        ip: str,
        signal_type: str,
        value: float,
        note: str,
        related_event_id: str = "",
        related_event_snapshot: str = "",
    ) -> None:
        """Insert a detection into the database."""
        with self._conn() as conn:
            try:
                conn.execute(
                    "INSERT INTO detections (timestamp, source_ip, signal_type, value, note, related_event_id, related_event_snapshot) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (timestamp, ip, signal_type, value, note, related_event_id, related_event_snapshot),
                )
            except sqlite3.OperationalError:
                # Backward compatibility when an old detections table exists.
                conn.execute(
                    "INSERT INTO detections (timestamp, source_ip, signal_type, value, note) VALUES (?, ?, ?, ?, ?)",
                    (timestamp, ip, signal_type, value, note),
                )

    def list_events(self, limit: int = 200) -> list[dict[str, Any]]:
        """List events from the database."""
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def list_detections(self, limit: int = 200) -> list[dict[str, Any]]:
        """List detections from the database."""
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM detections ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def next_event_sequence(self) -> int:
        """Get the next event sequence number."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT MAX(CAST(event_id AS INTEGER)) AS max_event_id FROM events WHERE event_id GLOB '[0-9]*'"
            ).fetchone()
        try:
            max_seq = int(row["max_event_id"] or 0)
        except (TypeError, ValueError):
            max_seq = 0
        return max_seq + 1

    def get_event_by_id(self, event_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return dict(row) if row else None

    def get_related_event_for_detection(self, detection_id: int) -> dict[str, Any] | None:
        with self._conn() as conn:
            detection_row = conn.execute("SELECT * FROM detections WHERE id = ?", (detection_id,)).fetchone()
            if not detection_row:
                return None
            detection = dict(detection_row)
            related_event_id = str(detection.get("related_event_id") or "").strip()
            if related_event_id:
                event_row = conn.execute("SELECT * FROM events WHERE event_id = ?", (related_event_id,)).fetchone()
                if event_row:
                    return dict(event_row)

            source_ip = str(detection.get("source_ip") or "").strip()
            timestamp = str(detection.get("timestamp") or "").strip()
            if source_ip and timestamp:
                event_row = conn.execute(
                    """
                    SELECT *
                    FROM events
                    WHERE source_ip = ?
                    ORDER BY ABS(julianday(timestamp) - julianday(?)) ASC
                    LIMIT 1
                    """,
                    (source_ip, timestamp),
                ).fetchone()
                if event_row:
                    return dict(event_row)

            if timestamp:
                event_row = conn.execute(
                    """
                    SELECT *
                    FROM events
                    ORDER BY ABS(julianday(timestamp) - julianday(?)) ASC
                    LIMIT 1
                    """,
                    (timestamp,),
                ).fetchone()
                if event_row:
                    return dict(event_row)

            return None

    def list_blocks(self, limit: int = 200) -> list[dict[str, Any]]:
        """List blocks from the database."""
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM blocks ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def summary(self) -> dict[str, Any]:
        """Get a summary of the database."""
        with self._conn() as conn:
            event_count = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
            active_blocks = conn.execute(
                "SELECT COUNT(*) AS c FROM (SELECT source_ip, MAX(id) AS max_id FROM blocks GROUP BY source_ip) latest JOIN blocks b ON b.id = latest.max_id WHERE b.action = 'block'"
            ).fetchone()["c"]
            detections = conn.execute("SELECT COUNT(*) AS c FROM detections").fetchone()["c"]
            blocked_events = conn.execute("SELECT COUNT(*) AS c FROM events WHERE decision = 'blocked'").fetchone()["c"]
        return {"total_events": event_count, "total_detections": detections, "active_blocks": active_blocks, "blocked_events": blocked_events}

    def clear_all_tables(self) -> None:
        """Remove all events, detections, and blocks."""
        with self._conn() as conn:
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM detections")
            conn.execute("DELETE FROM blocks")


class ConnectionHub:
    """Keeps track of all connected WebSocket clients."""
    def __init__(self) -> None:
        """Initialize the connection hub."""
        self.clients: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        """Accept a new WebSocket connection."""
        await ws.accept()
        self.clients.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        """Disconnect a WebSocket client."""
        if ws in self.clients:
            self.clients.remove(ws)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        """
        Broadcast a message to all connected WebSocket clients.
        Used to send real-time events to the dashboard.
        """
        stale: list[WebSocket] = []
        for client in self.clients:
            try:
                await client.send_text(json.dumps(payload))
            except Exception:
                stale.append(client)
        for client in stale:
            self.disconnect(client)


class AnomalyDetector:
    """Detects anomalies and blocks malicious IPs."""
    def __init__(self, store: EventStore, training_threshold: int = 50, max_logs: int = 2000):
        self.store = store
        self.training_threshold = int(os.getenv("TRAINING_THRESHOLD", str(training_threshold)))
        self.log_history = deque(maxlen=max_logs)
        self.block_url = os.environ.get("BLOCK_URL")
        self.model = None
        self.is_trained = False
        self.rate_limit_hits: dict[str, int] = {}
        self.ml_anomaly_hits: dict[str, int] = {}
        self.blocked_ips: set[str] = set()
        self.risk_state: dict[str, dict[str, Any]] = {}
        self.risk_cooldown_minutes = int(os.getenv("RISK_COOLDOWN_MINUTES", "5"))
        self.risk_block_threshold = int(os.getenv("RISK_BLOCK_THRESHOLD", "5"))
        self.rate_limit_hits_to_block = int(os.getenv("RATE_LIMIT_HITS_TO_BLOCK", "3"))
        self.ml_anomaly_hits_to_block = int(os.getenv("ML_ANOMALY_HITS_TO_BLOCK", "2"))
        self.rate_limit_window = int(os.getenv("RATE_LIMIT_WINDOW", "10"))
        self.rate_limit_min_avg_delta = float(os.getenv("RATE_LIMIT_MIN_AVG_DELTA", "0.2"))
        trusted = os.getenv("ALLOWLIST", "10.5.0.20")
        self.allowlist = {item.strip() for item in trusted.split(",") if item.strip()}
        self.keyword_hits: dict[str, int] = {}
        self.keyword_hits_to_block = int(os.getenv("KEYWORD_HITS_TO_BLOCK", "3"))
        self.credential_hits: dict[str, int] = {}
        self.credential_hits_to_block = int(os.getenv("CREDENTIAL_STUFFING_HITS_TO_BLOCK", "2"))
        self.event_sequence = store.next_event_sequence()
        self._block_lock = asyncio.Lock()

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate the entropy of a text string by measuring randomness of characters, as hackers often use random strings."""
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        return -sum((count / length) * np.log2(count / length) for count in counts.values())

    def _get_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract features from a DataFrame of events."""
        df["contains_attacker_kw"] = df["payload"].fillna("").astype(str).apply(payload_has_attack_keyword)
        df["contains_credential_pattern"] = df["payload"].fillna("").astype(str).apply(self.contains_credential_stuffing)
        df["entropy"] = df["payload"].fillna("").astype(str).apply(self._calculate_entropy)
        df["is_error"] = (df["status_code"] >= 400).astype(int)
        df["is_post"] = (df["method"] == "POST").astype(int)
        return df[
            [
                "payload_size",
                "entropy",
                "contains_attacker_kw",
                "contains_credential_pattern",
                "path_depth",
                "is_bot_ua",
                "is_error",
                "is_post",
            ]
        ]

    def train_model(self) -> bool:
        """Train the machine learning model on the event history."""
        if len(self.log_history) < self.training_threshold:
            return False
        df = pd.DataFrame(list(self.log_history))
        if df.empty:
            return False
        X = self._get_features(df)
        self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=1234)
        self.model.fit(X)
        self.is_trained = True
        detector_logger.info("Model trained on baseline data. Detection ACTIVE.")
        return True

    def _touch_risk_state(self, ip: str) -> dict[str, Any]:
        """Update (or initialize) the risk state for an IP address."""
        now = datetime.now(timezone.utc)
        state = self.risk_state.get(ip)
        if not state:
            state = {"risk": 0, "updated_at": now}
            self.risk_state[ip] = state
            return state
        if now - state["updated_at"] > timedelta(minutes=self.risk_cooldown_minutes):
            state["risk"] = 0
            self.rate_limit_hits[ip] = 0
            self.ml_anomaly_hits[ip] = 0
            self.keyword_hits[ip] = 0
        state["updated_at"] = now
        return state

    def check_rate_limit(self, ip: str) -> tuple[bool, float]:
        """Check if the IP has exceeded the rate limit."""
        recent_logs = [log for log in self.log_history if log["ip"] == ip]
        if len(recent_logs) < self.rate_limit_window:
            return False, 0.0
        window = recent_logs[-self.rate_limit_window :]
        times = pd.to_datetime([item["timestamp"] for item in window], utc=True, errors="coerce")
        valid_times = sorted([ts for ts in times if ts is not pd.NaT])
        if len(valid_times) < 2:
            return False, 0.0
        deltas = []
        for i in range(1, len(valid_times)):
            delta = (valid_times[i] - valid_times[i - 1]).total_seconds()
            if delta > 0:
                deltas.append(delta)
        if not deltas:
            return False, 0.0
        avg_delta = float(sum(deltas) / len(deltas))
        return avg_delta < self.rate_limit_min_avg_delta, avg_delta

    def contains_attack_keyword(self, payload: str) -> bool:
        """Check if the payload contains any attacker keywords."""
        return payload_has_attack_keyword(payload)

    def contains_credential_stuffing(self, payload: str) -> bool:
        low = (payload or "").lower()
        if not _CREDENTIAL_STUFFING_RE.search(low):
            return False
        return bool(_COMMON_CRED_VALUE_RE.search(low))

    def add_signal(self, ip: str, signal: str, delta: int) -> int:
        """Add a signal to the risk state for an IP address."""
        state = self._touch_risk_state(ip)
        state["risk"] += delta
        if signal == "rate_limit":
            self.rate_limit_hits[ip] = self.rate_limit_hits.get(ip, 0) + 1
        elif signal == "ml_anomaly":
            self.ml_anomaly_hits[ip] = self.ml_anomaly_hits.get(ip, 0) + 1
        elif signal == "keyword":
            self.keyword_hits[ip] = self.keyword_hits.get(ip, 0) + 1
        elif signal == "credential_stuffing":
            self.credential_hits[ip] = self.credential_hits.get(ip, 0) + 1
        return int(state["risk"])

    def should_block(self, ip: str, signal: str) -> bool:
        """Check if the IP should be blocked based on the risk state and signal."""
        if ip in self.blocked_ips:
            return False
        state = self.risk_state.get(ip, {"risk": 0})
        if state["risk"] >= self.risk_block_threshold:
            return True
        if signal == "rate_limit" and self.rate_limit_hits.get(ip, 0) >= self.rate_limit_hits_to_block:
            return True
        if signal == "ml_anomaly" and self.ml_anomaly_hits.get(ip, 0) >= self.ml_anomaly_hits_to_block:
            return True
        if signal == "keyword" and self.keyword_hits.get(ip, 0) >= self.keyword_hits_to_block:
            return True
        if signal == "credential_stuffing" and self.credential_hits.get(ip, 0) >= self.credential_hits_to_block:
            return True
        return False

    async def trigger_block(self, ip: str, reason: str) -> bool:
        """Trigger a block for an IP address (idempotent; serialized per process)."""
        if not self.block_url:
            return False
        async with self._block_lock:
            if ip in self.blocked_ips:
                return True
            self.blocked_ips.add(ip)
            try:
                async with httpx.AsyncClient(timeout=2) as client:
                    response = await client.post(self.block_url, json={"block_ip": ip, "reason": reason}, timeout=2)
                if response.status_code >= 400:
                    self.blocked_ips.discard(ip)
                    return False
                return True
            except Exception as exc:
                self.blocked_ips.discard(ip)
                detector_logger.info("Failed to send block command for %s: %s", ip, exc)
                return False

    async def run_ml_detection(self, event: dict[str, Any]) -> tuple[bool, bool, str, int]:
        """Run the ML anomaly detection on an event."""
        if not self.is_trained:
            if not self.train_model():
                detector_logger.info("Collecting baseline data... (%s/%s)", len(self.log_history), self.training_threshold)
            return False, False, "baseline_collection", 0
        df_event = pd.DataFrame([event])
        X_event = self._get_features(df_event)
        score = self.model.predict(X_event)[0]
        if score != -1:
            return False, False, "normal_ml", 0
        ip = event["ip"]
        risk_total = self.add_signal(ip, "ml_anomaly", 2)
        if self.should_block(ip, "ml_anomaly"):
            blocked = await self.trigger_block(ip, "ml_anomaly_threshold_met")
            if blocked:
                return True, True, "blocked_ml_anomaly", risk_total
        return False, True, "ml_anomaly_detected", risk_total

    def next_event_id(self) -> str:
        value = str(self.event_sequence)
        self.event_sequence += 1
        return value

    def reset_ip_state(self, ip: str) -> None:
        self.blocked_ips.discard(ip)
        self.risk_state.pop(ip, None)
        self.rate_limit_hits.pop(ip, None)
        self.ml_anomaly_hits.pop(ip, None)
        self.keyword_hits.pop(ip, None)
        self.credential_hits.pop(ip, None)

    def reset_runtime_state(self) -> None:
        """Clear in-memory detection state after a dashboard reset."""
        self.log_history.clear()
        self.blocked_ips.clear()
        self.risk_state.clear()
        self.rate_limit_hits.clear()
        self.ml_anomaly_hits.clear()
        self.keyword_hits.clear()
        self.credential_hits.clear()
        self.model = None
        self.is_trained = False
        self.event_sequence = self.store.next_event_sequence()


app = FastAPI(title="Detector Service")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
store = EventStore(os.getenv("SIEM_DB_PATH", "/app/logs/siem.db"))
hub = ConnectionHub()
detector = AnomalyDetector(store=store)
main_server_url = os.getenv("MAIN_SERVER_URL", "http://10.5.0.20:8000")


def traffic_pace_file_path() -> str:
    base = os.getenv("SIEM_DB_PATH", "/app/logs/siem.db")
    return os.getenv("TRAFFIC_PACE_PATH", os.path.join(os.path.dirname(base), "traffic_pace.json"))


def read_traffic_pace() -> dict[str, Any]:
    path = traffic_pace_file_path()
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        pace = str(data.get("pace", "normal")).lower()
        if pace not in ("slow", "normal", "fast"):
            pace = "normal"
        return {"pace": pace}
    except FileNotFoundError:
        return {"pace": "normal"}
    except Exception:
        return {"pace": "normal"}


def write_traffic_pace(pace: str) -> None:
    p = str(pace).lower()
    if p not in ("slow", "normal", "fast"):
        p = "normal"
    path = traffic_pace_file_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"pace": p}, f)


@app.post("/log")
async def receive_log(request: Request) -> dict[str, Any]:
    """
    Main endpoint that receives events from the main server and processes them.
    Here the rate-limit and ML anomaly detection are run, and the decision is made to block or not.
    """
    # 1. Extract the event from the request and set default values.
    event = await request.json()
    event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    event.setdefault("ip", "unknown")
    event.setdefault("method", "POST")
    event.setdefault("endpoint", "/process")
    event.setdefault("status_code", 200)
    event.setdefault("payload", "")
    event.setdefault("payload_size", len(str(event.get("payload", ""))))
    event.setdefault("path_depth", str(event.get("endpoint", "/")).count("/"))
    event.setdefault("is_bot_ua", 0)
    event.setdefault("country", "")
    event.setdefault("city", "")
    event.setdefault("isp", "")
    event.setdefault("device_type", "")

    ip = event["ip"]
    event_id = detector.next_event_id()
    decision = "processed"
    reason = "no_signal"
    signal_type = "none"
    risk_delta = 0
    risk_total = detector.risk_state.get(ip, {}).get("risk", 0)
    pending_detections: list[tuple[str, float, str]] = []

    # 2. Check if the IP is in the allowlist, then it does not have to be checked.
    if ip in detector.allowlist:
        decision = "allowed_ip"
        reason = "allowlist"
    else:
        # 3. Check if the IP has exceeded the rate limit.
        triggered, avg_delta = detector.check_rate_limit(ip)
        if triggered:
            signal_type = "rate_limit"
            risk_delta = 2
            risk_total = detector.add_signal(ip, "rate_limit", risk_delta)
            pending_detections.append(("rate_limit", avg_delta, f"Average request delta {avg_delta:.3f}s"))
            if detector.should_block(ip, "rate_limit") and await detector.trigger_block(ip, "rate_limit_threshold_met"):
                decision = "blocked"
                reason = "rate_limit_threshold_met"
            else:
                decision = "suspicious"
                reason = "rate_limit_detected"

        # 4. Check if the payload contains any attacker keywords.
        if signal_type == "none" and detector.contains_credential_stuffing(str(event.get("payload", ""))):
            signal_type = "credential_stuffing"
            risk_delta = 2
            risk_total = detector.add_signal(ip, "credential_stuffing", risk_delta)
            pending_detections.append(("credential_stuffing", 1.0, "Credential stuffing pattern detected"))
            if detector.should_block(ip, "credential_stuffing") and await detector.trigger_block(ip, "credential_stuffing_threshold_met"):
                decision = "blocked"
                reason = "credential_stuffing_threshold_met"
            else:
                decision = "suspicious"
                reason = "credential_stuffing_detected"

        if signal_type == "none" and detector.contains_attack_keyword(str(event.get("payload", ""))):
            signal_type = "keyword"
            risk_delta = 1
            risk_total = detector.add_signal(ip, "keyword", risk_delta)
            pending_detections.append(("keyword", 1.0, "Known attacker keyword found"))
            if detector.should_block(ip, "keyword") and await detector.trigger_block(ip, "keyword_threshold_met"):
                decision = "blocked"
                reason = "keyword_threshold_met"
            else:
                decision = "suspicious"
                reason = "keyword_detected"

        # 5. Run the ML anomaly detection.
        if signal_type == "none":
            blocked, detected, ml_reason, ml_risk = await detector.run_ml_detection(event)
            if detected:
                signal_type = "ml_anomaly"
                risk_total = ml_risk
                pending_detections.append(("ml_anomaly", -1.0, "IsolationForest flagged anomaly"))
                if blocked:
                    decision = "blocked"
                    reason = "ml_anomaly_threshold_met"
                elif ml_reason == "ml_anomaly_detected":
                    decision = "suspicious"
                    reason = "ml_anomaly_detected"

    # 6. Add the event to the log history and insert it into the database.
    detector.log_history.append(event)
    event_record = {
        "event_id": event_id,
        "timestamp": event["timestamp"],
        "source_ip": ip,
        "actor_type": event.get("actor_type", "unknown"),
        "method": event["method"],
        "endpoint": event["endpoint"],
        "status_code": int(event["status_code"]),
        "payload": str(event.get("payload", "")),
        "signal_type": signal_type,
        "risk_delta": int(risk_delta),
        "risk_total": int(risk_total),
        "decision": decision,
        "reason": reason,
        "country": str(event.get("country", "")),
        "city": str(event.get("city", "")),
        "isp": str(event.get("isp", "")),
        "device_type": str(event.get("device_type", "")),
    }
    inserted = False
    for _ in range(5):
        try:
            store.insert_event(event_record)
            inserted = True
            break
        except sqlite3.IntegrityError:
            event_id = detector.next_event_id()
            event_record["event_id"] = event_id
    if not inserted:
        raise RuntimeError("Unable to persist event after event_id collision retries")
    related_snapshot = json.dumps(event_record, ensure_ascii=False)
    for signal_name, value, note in pending_detections:
        store.insert_detection(
            event["timestamp"],
            ip,
            signal_name,
            float(value),
            note,
            related_event_id=event_id,
            related_event_snapshot=related_snapshot,
        )
    await hub.broadcast({"type": "event", "data": event_record})
    return {"status": decision, "reason": reason, "risk_total": risk_total}

# Below are API endpoints for the dashboard to fetch events, detections, blocks and summary.
@app.get("/api/events")
async def api_events(limit: int = 200) -> dict[str, Any]:
    return {"items": store.list_events(limit=limit)}


@app.get("/api/detections")
async def api_detections(limit: int = 200) -> dict[str, Any]:
    return {"items": store.list_detections(limit=limit)}


@app.get("/api/blocks")
async def api_blocks(limit: int = 200) -> dict[str, Any]:
    return {"items": store.list_blocks(limit=limit)}


@app.get("/api/metrics/summary")
async def api_summary() -> dict[str, Any]:
    return store.summary()


@app.get("/api/model/status")
async def api_model_status() -> dict[str, Any]:
    return {
        "trained": detector.is_trained,
        "baseline_collected": len(detector.log_history),
        "baseline_required": detector.training_threshold,
    }


@app.get("/api/simulation/traffic-pace")
async def api_traffic_pace_get() -> dict[str, Any]:
    return read_traffic_pace()


@app.post("/api/simulation/traffic-pace")
async def api_traffic_pace_post(request: Request) -> dict[str, Any]:
    body = await request.json()
    pace = body.get("pace", "normal") if isinstance(body, dict) else "normal"
    write_traffic_pace(str(pace))
    return read_traffic_pace()


@app.post("/api/reset")
async def api_reset() -> dict[str, Any]:
    """Clear shared DB tables and detector state; sync main server block cache."""
    store.clear_all_tables()
    detector.reset_runtime_state()
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(f"{main_server_url}/control/reset-cache")
        if response.status_code >= 400:
            return {"status": "partial", "detail": response.text}
    except Exception as exc:
        return {"status": "partial", "detail": str(exc)}
    return {"status": "ok"}


@app.post("/api/control/pause")
async def api_control_pause() -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(f"{main_server_url}/control/pause")
        if response.status_code >= 400:
            return {"status": "error", "detail": response.text}
        return {"status": "ok", **response.json()}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


@app.post("/api/control/resume")
async def api_control_resume() -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(f"{main_server_url}/control/resume")
        if response.status_code >= 400:
            return {"status": "error", "detail": response.text}
        return {"status": "ok", **response.json()}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


@app.get("/api/control/status")
async def api_control_status() -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{main_server_url}/control/status")
        if response.status_code >= 400:
            return {"paused": False, "status": "error", "detail": response.text}
        data = response.json()
        return {"status": "ok", "paused": bool(data.get("paused"))}
    except Exception as exc:
        return {"paused": False, "status": "error", "detail": str(exc)}


@app.post("/api/blocks/{ip}/unblock")
async def api_unblock(ip: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            response = await client.post(f"{main_server_url}/unblock", json={"ip": ip, "reason": "dashboard_unblock"})
        if response.status_code >= 400:
            return {"status": "error", "detail": response.text}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}
    detector.reset_ip_state(ip)
    return {"status": "ok", "ip": ip}


@app.get("/api/events/{event_id}")
async def api_event_by_id(event_id: str) -> dict[str, Any]:
    row = store.get_event_by_id(event_id)
    if not row:
        return {"item": None}
    return {"item": row}


@app.get("/api/detections/{detection_id}/related")
async def api_related_event_by_detection(detection_id: int) -> dict[str, Any]:
    row = store.get_related_event_for_detection(detection_id)
    return {"item": row}


@app.websocket("/api/stream/events")
async def websocket_events(ws: WebSocket) -> None:
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        hub.disconnect(ws)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)