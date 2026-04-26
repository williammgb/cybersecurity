from collections import deque
from datetime import datetime, timezone
from threading import Thread
import time

from flask import Flask, jsonify
from scapy.all import IP, Raw, TCP, sniff

app = Flask(__name__)

# Keep only the latest 50 events to limit processing and keep the UI fast.
events = deque(maxlen=50)

# When we detect the HTTP demo POST, capture the full TCP flow
# (handshake + request + response) for a short time window.
HTTP_FLOW_WINDOW_SECONDS = 4.0
active_http_flow = None  # dict with keys: client_ip, client_port, server_ip, expires_at


def safe_decode(payload_bytes: bytes) -> str:
    """Decode raw bytes into a string."""
    return payload_bytes.decode("utf-8", errors="replace")


def format_payload_preview(decoded: str) -> str:
    """Make HTTP payload previews clearer at packet granularity."""
    if not decoded:
        return "<empty payload>"

    if decoded.startswith(("POST ", "GET ", "HTTP/1.1")):
        if "\r\n\r\n" in decoded:
            headers, body = decoded.split("\r\n\r\n", 1)
            if body.strip():
                combined = f"{headers}\n\n--- body ---\n{body}"
                return combined[:400]
            return (
                f"{headers}\n\n<no HTTP body bytes in this packet, may be in a following TCP segment>"
            )[:400]

        return (
            f"{decoded}\n\n<incomplete HTTP payload in this packet, may be in a following TCP segment>"
        )[:400]

    return decoded[:400]


def detect_protocol(src_port: int, dst_port: int) -> str:
    """Detect protocol by checking either endpoint's service port."""
    if 8080 in {src_port, dst_port}:
        return "HTTP"
    if 8443 in {src_port, dst_port}:
        return "HTTPS/TLS"
    return "UNKNOWN"


def _flow_matches_http_demo(packet, flow: dict) -> bool:
    """
    Check if a packet belongs to the HTTP demo flow (the same TCP connection). 
    Filters out non-HTTP packets and packets to other ports.
    """
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return False

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    client_ip = flow["client_ip"]
    client_port = flow["client_port"]
    server_ip = flow["server_ip"]

    # Match both directions for the same 4-tuple (client ephemeral <-> server:8080).
    return (
        (src_ip == client_ip and src_port == client_port and dst_ip == server_ip and dst_port == 8080)
        or (src_ip == server_ip and src_port == 8080 and dst_ip == client_ip and dst_port == client_port)
    )


def _maybe_refresh_http_flow(packet, raw_bytes: bytes | None) -> None:
    """If this packet is the demo HTTP POST, start/refresh the capture window."""
    global active_http_flow
    if raw_bytes is None:
        return
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return

    # Detect the user-triggered demo request (starts with POST /message to port 8080).
    if packet[TCP].dport == 8080 and b"POST /message" in raw_bytes:
        active_http_flow = {
            "client_ip": packet[IP].src,
            "client_port": packet[TCP].sport,
            "server_ip": packet[IP].dst,
            "expires_at": time.time() + HTTP_FLOW_WINDOW_SECONDS,
        }


def should_capture_demo_packet(packet, raw_bytes: bytes | None) -> bool:
    """Keep only packets that represent the demo message flow (but capture full HTTP flow once detected)."""
    global active_http_flow
    now = time.time()

    # Stops capturing after the flow window expires.
    if active_http_flow and now >= active_http_flow["expires_at"]:
        active_http_flow = None

    # If we have an active HTTP flow window, capture ALL packets for that flow,
    if active_http_flow and _flow_matches_http_demo(packet, active_http_flow):
        return True

    # Otherwise, try to detect a new demo HTTP flow.
    _maybe_refresh_http_flow(packet, raw_bytes)
    if active_http_flow and _flow_matches_http_demo(packet, active_http_flow):
        return True

    # Always capture client-to-receiver HTTPS payload packets (port 8443).
    if packet.haslayer(TCP) and packet[TCP].dport == 8443 and raw_bytes is not None:
        return True

    return False


def handle_packet(packet):
    """Store information about a packet."""
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    raw_bytes = bytes(packet[Raw].load) if packet.haslayer(Raw) else None
    if not should_capture_demo_packet(packet, raw_bytes):
        return

    payload_preview = "<no raw payload>"
    if raw_bytes is not None:
        decoded = safe_decode(raw_bytes)
        payload_preview = format_payload_preview(decoded)

    events.append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol_guess": detect_protocol(src_port, dst_port),
            "tcp_flags": str(packet[TCP].flags),
            "payload_len": len(raw_bytes) if raw_bytes is not None else 0,
            "payload_preview": payload_preview,
        }
    )


def packet_sniffer_loop():
    """
    Capture packets on the container interface.
    eth0 is the default network interface (traffic goes through this interface) for the receiver container.
    """
    # Capture both request and response directions for demo ports.
    bpf_filter = "tcp and (port 8080 or port 8443)"

    try:
        sniff(
            iface="eth0",
            filter=bpf_filter,
            prn=handle_packet,
            store=False,
        )
    except Exception as exc:
        # If iface/filter selection fails (common on some Docker setups),
        # fall back to sniffing without explicit iface/filter so we still capture.
        sniff(
            prn=handle_packet,
            store=False,
        )


@app.get("/events")
def get_events():
    return jsonify({"ok": True, "events": list(events)})


if __name__ == "__main__":
    # Run sniffer in background while Flask serves event API.
    Thread(target=packet_sniffer_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5001, debug=False)
