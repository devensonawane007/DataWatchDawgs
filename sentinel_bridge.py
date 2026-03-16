"""
sentinel_bridge.py — Connects SentinelAI to DataWatchDawgs SocketIO.

Runs as a background thread inside app.py.
Polls sentinel_ai/shared_state every 0.5 s.
Any new Alert or NetworkEvent gets emitted as a SocketIO event so every
connected browser (main dashboard, judges view, attacker console) sees
SentinelAI detections in real time.

SocketIO events emitted
-----------------------
  sentinel_alert   — { timestamp, severity, attack_type, src_ip,
                       description, auto_blocked }
  sentinel_stats   — { total_requests, blocked_requests, total_alerts,
                       alerts_by_type, blocked_ips, uptime }
  sentinel_event   — { timestamp, src_ip, event_type, port,
                       method, path, content_length } (HTTP/honeypot hits)

Nothing in sentinel_ai/ is modified.
"""

import sys
import os
import time
import threading
import logging

logger = logging.getLogger("dwd.sentinel_bridge")

# Make sentinel_ai importable
_HERE = os.path.dirname(os.path.abspath(__file__))
_SENTINEL_DIR = os.path.join(_HERE, "sentinel_ai")
if _SENTINEL_DIR not in sys.path:
    sys.path.insert(0, _SENTINEL_DIR)


def start_sentinel(socketio, host: str = "0.0.0.0", port: int = 6100,
                   autoblock: bool = True) -> bool:
    """
    Import and start SentinelAI, then start the bridge thread.
    Returns True if sentinel started OK, False if import failed.

    port=6100 — SentinelAI's target/honeypot server runs here so it
    doesn't clash with DWD on 5000.
    """
    try:
        from shared_state import state
        from target_server import start_server
        from honeypot import start_honeypot
        from detection_engine import start_detection

        # Configure sentinel
        state.config["autoblock"]   = autoblock
        state.config["server_port"] = port
        state.config["server_host"] = host

        # Start sentinel's Flask target server (victim server attackers hit)
        threading.Thread(
            target=start_server, args=(host, port),
            daemon=True, name="sentinel-target"
        ).start()

        # Start honeypot (28 TCP ports)
        threading.Thread(
            target=start_honeypot,
            daemon=True, name="sentinel-honeypot"
        ).start()

        # Start all 5 detectors
        threading.Thread(
            target=start_detection,
            daemon=True, name="sentinel-detectors"
        ).start()

        logger.info(
            "SentinelAI started — target server on :%d | honeypot on 28 ports | "
            "5 detectors active", port
        )

        # Start the bridge that forwards alerts to SocketIO
        threading.Thread(
            target=_bridge_loop, args=(socketio, state),
            daemon=True, name="sentinel-bridge"
        ).start()

        return True

    except Exception as e:
        logger.warning("SentinelAI could not start: %s", e)
        return False


def _bridge_loop(socketio, state) -> None:
    """
    Tail the alerts deque and forward every new entry to SocketIO.
    Also emits a stats snapshot every 2 s.
    """
    last_alert_ts   = 0.0
    last_stats_emit = 0.0

    while True:
        try:
            now = time.time()

            # ── Forward new alerts ────────────────────────────────────────
            with state.lock:
                recent = list(state.alerts)

            for alert in recent:
                if alert.timestamp > last_alert_ts:
                    last_alert_ts = alert.timestamp
                    socketio.emit("sentinel_alert", {
                        "timestamp":    alert.timestamp,
                        "severity":     alert.severity,
                        "attack_type":  alert.attack_type,
                        "src_ip":       alert.src_ip,
                        "description":  alert.description,
                        "auto_blocked": alert.auto_blocked,
                    })
                    logger.info(
                        "[SENTINEL] %s from %s — %s",
                        alert.attack_type, alert.src_ip, alert.severity
                    )

            # ── Stats snapshot every 2 s ──────────────────────────────────
            if now - last_stats_emit >= 2.0:
                last_stats_emit = now
                snap = state.snapshot_stats()
                socketio.emit("sentinel_stats", {
                    "total_requests":   snap["total_requests"],
                    "blocked_requests": snap["blocked_requests"],
                    "total_alerts":     snap["total_alerts"],
                    "alerts_by_type":   snap["alerts_by_type"],
                    "blocked_ips":      list(state.blocked_ips),
                    "uptime":           now - snap["start_time"],
                })

        except Exception as e:
            logger.debug("Bridge loop error: %s", e)

        time.sleep(0.5)
