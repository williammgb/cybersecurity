from flask import Flask, jsonify, render_template, request
import requests

app = Flask(__name__)

# Container names are DNS names inside the docker bridge network.
RECEIVER_HTTP_URL = "http://receiver:8080/message"
RECEIVER_HTTPS_URL = "https://receiver:8443/message"
# Sniffer uses network_mode: service:receiver, so it shares receiver's IP and DNS name (no separate "sniffer" hostname).
SNIFFER_EVENTS_URL = "http://receiver:5001/events"
RECEIVER_LAST_MESSAGE_URL = "http://receiver:8080/last-message"


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/send")
def send_message():
    """
    Send a message from container A (this service) to container B (receiver),
    using HTTP or HTTPS based on the user's choice.
    """
    payload = request.get_json(silent=True) or {}
    protocol = (payload.get("protocol") or "").upper()
    message = (payload.get("message") or "").strip()

    if protocol not in {"HTTP", "HTTPS"}:
        return jsonify({"ok": False, "error": "Protocol must be HTTP or HTTPS"}), 400
    if not message:
        return jsonify({"ok": False, "error": "Message is required"}), 400

    receiver_url = RECEIVER_HTTP_URL if protocol == "HTTP" else RECEIVER_HTTPS_URL

    try:
        # verify=False is used here only because receiver uses a self-signed certificate. It skips certificate verification.
        response = requests.post(
            receiver_url,
            json={
                "message": message,
                "source": "sender-ui",
                "protocol": protocol,
            },
            timeout=5,
            verify=False if protocol == "HTTPS" else True,
        )
        response.raise_for_status() # raise an exception for HTTP errors (400, 500, etc.)
        return jsonify({"ok": True, "receiver_response": response.json()})
    except requests.RequestException as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502


@app.get("/api/sniffer-events")
def get_sniffer_events():
    """
    Proxy to the sniffer container so browser can easily fetch events from one place.
    Update the UI (sniffer section) with the latest sniffer events.
    """
    try:
        response = requests.get(SNIFFER_EVENTS_URL, timeout=5)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.RequestException as exc:
        return jsonify({"ok": False, "error": str(exc), "events": []}), 502


@app.get("/api/receiver-last-message")
def receiver_last_message():
    """
    Fetch what container B last received so UI (receiver section) can show message content.
    """
    try:
        response = requests.get(RECEIVER_LAST_MESSAGE_URL, timeout=5)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.RequestException as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502


if __name__ == "__main__":
    # host=0.0.0.0 makes the Flask app reachable from Docker port mapping.
    app.run(host="0.0.0.0", port=5000, debug=False)
