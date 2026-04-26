from datetime import datetime, timezone
from threading import Thread
from collections import deque

from flask import Flask, jsonify, request
from werkzeug.serving import make_server

app = Flask(__name__)

# Keep the 5 most recent received messages for UI display.
messages = deque(maxlen=5)


@app.post("/message")
def message():
    """Store the latest received message in a small history."""
    data = request.get_json(silent=True) or {}

    new_message = {
        "message": data.get("message", ""),
        "source": data.get("source", "unknown"),
        "protocol": data.get("protocol", "unknown"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    messages.appendleft(new_message)

    return jsonify({"ok": True, "stored": new_message})


@app.get("/last-message")
def get_last_message():
    """Return the last message received and the 4 older messages."""
    last_message = messages[0] if messages else None
    older_messages = list(messages)[1:5]
    return jsonify({"ok": True, "last_message": last_message, "older_messages": older_messages})


def run_https_server():
    """
    Flask is plain HTTP by default. This runs a second instance with TLS on port 8443.
    It receives HTTPS requests, decrypts them, and forwards the plain HTTP request to the Flask app.
    Acts as a reverse proxy for HTTPS requests.
    """
    https_server = make_server(
        host="0.0.0.0",
        port=8443,
        app=app,
        ssl_context=("/app/certs/server.crt", "/app/certs/server.key"),
    )
    https_server.serve_forever()


if __name__ == "__main__":
    # Start HTTPS server in background thread (daemon=True).
    Thread(target=run_https_server, daemon=True).start()

    # Main thread serves plain HTTP on 8080.
    app.run(host="0.0.0.0", port=8080, debug=False)
