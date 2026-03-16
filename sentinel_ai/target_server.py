"""
target_server.py — The "victim" web server that the attack simulator targets.

All routes log every request as a NetworkEvent so detectors can analyse them.
The server deliberately stays up even under attack — detectors decide the response.
"""

import logging
import time

from flask import Flask, request, Response

from shared_state import state, NetworkEvent

# Silence Flask's default access log — our middleware handles it
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

app = Flask(__name__)


# ── Request middleware ────────────────────────────────────────────────────────

@app.before_request
def _intercept():
    """Log every request; return 403 immediately if IP is blocked."""
    ip = request.remote_addr or "0.0.0.0"

    if state.is_blocked(ip):
        with state.lock:
            state.stats["blocked_requests"] += 1
        return Response("Forbidden — blocked by SentinelAI", status=403)

    evt = NetworkEvent(
        timestamp      = time.time(),
        src_ip         = ip,
        event_type     = "http_request",
        port           = state.config.get("server_port", 5000),
        method         = request.method,
        path           = request.path,
        content_length = request.content_length or 0,
        content_type   = request.content_type or "",
        user_agent     = request.user_agent.string or "",
        status_code    = 200,  # updated in after_request
    )
    state.add_event(evt)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def index():
    return Response("SentinelAI Target Server — Online", status=200)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Brute-force target — always rejects credentials."""
    return Response("Unauthorized", status=401)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """Data-exfiltration target — accepts the body, discards it."""
    _ = request.get_data(cache=False)   # drain body
    return Response("OK", status=200)


@app.route("/beacon", methods=["GET", "POST"])
def beacon():
    """C2 beaconing target."""
    _ = request.get_data(cache=False)
    return Response("{\"cmd\":\"sleep\"}", status=200, content_type="application/json")


@app.route("/data", methods=["GET", "POST"])
def data():
    """Generic data endpoint (exfil fallback)."""
    _ = request.get_data(cache=False)
    return Response("OK", status=200)


# ── Launcher ──────────────────────────────────────────────────────────────────

def start_server(host: str = "0.0.0.0", port: int = 5000) -> None:
    """Start Flask in a background thread (blocking call)."""
    app.run(host=host, port=port, threaded=True, use_reloader=False)
