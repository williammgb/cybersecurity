import os
import tempfile
from datetime import datetime, timedelta, timezone

from detector import AnomalyDetector, EventStore, payload_has_attack_keyword


def make_detector() -> AnomalyDetector:
    fd, db_path = tempfile.mkstemp(prefix="cybersiem_test_", suffix=".db")
    os.close(fd)
    store = EventStore(db_path)
    detector = AnomalyDetector(store=store, training_threshold=9999)
    detector.rate_limit_window = 5
    detector.rate_limit_min_avg_delta = 0.2
    return detector


def test_rate_limit_no_negative_delta():
    detector = make_detector()
    ip = "10.5.0.90"
    base = datetime.now(timezone.utc)
    offsets = [4, 2, 1, 3, 5]  # out of order
    for seconds in offsets:
        detector.log_history.append(
            {
                "ip": ip,
                "timestamp": (base + timedelta(seconds=seconds)).isoformat(),
            }
        )
    triggered, avg = detector.check_rate_limit(ip)
    assert triggered is False
    assert avg > 0


def test_block_requires_multiple_hits():
    detector = make_detector()
    ip = "10.5.0.91"
    detector.rate_limit_hits_to_block = 3
    detector.add_signal(ip, "rate_limit", 2)
    assert detector.should_block(ip, "rate_limit") is False
    detector.add_signal(ip, "rate_limit", 2)
    assert detector.should_block(ip, "rate_limit") is False
    detector.add_signal(ip, "rate_limit", 2)
    assert detector.should_block(ip, "rate_limit") is True


def test_keyword_hits_trigger_block():
    detector = make_detector()
    ip = "10.5.0.92"
    detector.keyword_hits_to_block = 3
    detector.add_signal(ip, "keyword", 1)
    assert detector.should_block(ip, "keyword") is False
    detector.add_signal(ip, "keyword", 1)
    assert detector.should_block(ip, "keyword") is False
    detector.add_signal(ip, "keyword", 1)
    assert detector.should_block(ip, "keyword") is True


def test_payload_keyword_benign_json_no_false_positive():
    benign = '{"user_id": 0, "session": 1234, "data": "Normal activity", "request_id": 456789}'
    assert payload_has_attack_keyword(benign) is False


def test_payload_keyword_detects_sqli():
    assert payload_has_attack_keyword("admin' OR 1=1 --") is True
    assert payload_has_attack_keyword("foo' UNION SELECT password FROM users --") is True


def test_payload_keyword_detects_path_traversal():
    assert payload_has_attack_keyword("../../etc/passwd") is True
