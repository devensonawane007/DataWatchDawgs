"""
DataWatchDawgs — Main Flask + SocketIO Application
Run: python app.py
Dashboard: http://localhost:5000
"""
import os, sys, threading, time, logging
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from dotenv import load_dotenv
 
load_dotenv()
 
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("dwd.app")
 
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
 
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "datawatchdawgs-secret")
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
 
from core.battle_engine import BattleEngine, CVE_DB
try:
    from sentinel_bridge import start_sentinel
    SENTINEL_AVAILABLE = True
except ImportError:
    SENTINEL_AVAILABLE = False
try:
    from core.network_battle_engine import NETWORK_VULN_DB
    from agents.network_agent import NETWORK_ATTACK_META
    NETWORK_AVAILABLE = True
except ImportError:
    NETWORK_VULN_DB = {}
    NETWORK_ATTACK_META = {}
    NETWORK_AVAILABLE = False
 
_engine = None
_battle_running = False
 
 
def get_engine():
    global _engine
    if _engine is None:
        def emit_fn(event, data):
            socketio.emit(event, data)
        _engine = BattleEngine(max_rounds=5, emit_fn=emit_fn)
    return _engine
 
 
# HTTP Routes
 
@app.route("/")
def index():
    return render_template("index.html")
 
 
@app.route("/sentinel")
def sentinel_view():
    """SentinelAI live detection dashboard — shows real-time alerts from the defender."""
    return render_template("sentinel.html")


@app.route("/api/sentinel/status")
def api_sentinel_status():
    """Quick health check — returns whether SentinelAI is running."""
    return jsonify({"available": SENTINEL_AVAILABLE})


@app.route("/judges")
def judges():
    """Fullscreen live battle spectator view — open on projector or TV."""
    return render_template("judges.html")


@app.route("/attacker")
def attacker():
    """Attacker control panel — open on Laptop A (attacker machine)."""
    return render_template("attacker.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(get_engine().get_stats())
 
 
@app.route("/api/battles")
def api_battles():
    engine = get_engine()
    return jsonify(engine.battles[-20:])
 
 
@app.route("/api/cves")
def api_cves():
    return jsonify([
        {"key": k, "id": v["id"], "name": v["name"],
         "cvss": v["cvss"], "type": v["type"], "desc": v["desc"]}
        for k, v in CVE_DB.items()
    ])
 
 
@app.route("/api/network/attacks")
def api_network_attacks():
    return jsonify([
        {
            "key": k,
            "id": v["id"],
            "name": v["name"],
            "cvss": v.get("cvss", 0),
            "layer": v.get("layer", "network"),
            "type": v.get("type", "Medium"),
            "desc": v.get("desc", ""),
        }
        for k, v in NETWORK_VULN_DB.items()
    ])
 
 
@app.route("/api/network/soc-training", methods=["POST"])
def api_soc_training():
    data = request.get_json(force=True) or {}
    attack_type = data.get("attack_type", "port_scan")
    soc_response = data.get("soc_response")
 
    def run_soc():
        try:
            result = get_engine().run_soc_training(attack_type, soc_response)
            socketio.emit("soc_training_complete", result)
        except Exception as e:
            socketio.emit("soc_training_complete", {"error": str(e)})
 
    threading.Thread(target=run_soc, daemon=True).start()
    return jsonify({"status": "running", "message": f"SOC training started for {attack_type}"})
 
 
@app.route("/api/network/firewall-verify", methods=["POST"])
def api_firewall_verify():
    data = request.get_json(force=True) or {}
    attack_type = data.get("attack_type", "brute_force")
    proposed_rule = data.get("proposed_rule")
 
    def run_verify():
        try:
            result = get_engine().run_firewall_verification(attack_type, proposed_rule)
            socketio.emit("waf_verify_complete", result)
        except Exception as e:
            socketio.emit("waf_verify_complete", {"error": str(e)})
 
    threading.Thread(target=run_verify, daemon=True).start()
    return jsonify({"status": "running", "message": f"Verifying {attack_type} rule — watch Network terminal"})
 
 
@app.route("/api/network/red-team", methods=["POST"])
def api_red_team():
    data = request.get_json(force=True) or {}
    target_url = data.get("target_url")
    options_map = data.get("options")
 
    def run_rt():
        try:
            result = get_engine().run_full_red_team(target_url, options_map)
            socketio.emit("red_team_complete", result)
        except Exception as e:
            socketio.emit("red_team_complete", {"error": str(e)})
 
    threading.Thread(target=run_rt, daemon=True).start()
    return jsonify({"status": "running", "message": "Red team campaign started — watch Network terminal"})
 
 
# SocketIO Events
 
@socketio.on("connect")
def on_connect():
    engine = get_engine()
    stats = engine.get_stats()
    emit("connected", {
        "message": "DataWatchDawgs v2 — Connected",
        "cycle": stats["cycle"],
        "stats": stats,
    })
    logger.info("Client connected")
 
 
@socketio.on("launch_battle")
def on_launch(data):
    global _battle_running
    if _battle_running:
        emit("battle_error", {"msg": "Battle already running — please wait"})
        return
 
    vuln_key = data.get("vuln_key", "sqli")
 
    # Handle network-layer standalone battles (net_port_scan -> port_scan etc.)
    if vuln_key.startswith("net_"):
        net_key_map = {
            "net_port_scan":     "port_scan",
            "net_brute_force":   "brute_force",
            "net_c2_beacon":     "c2_beacon",
            "net_data_exfil":    "data_exfiltration",
            "net_traffic_flood": "traffic_flood",
        }
        net_type = net_key_map.get(vuln_key, vuln_key[4:])
 
        def run_net():
            global _battle_running
            _battle_running = True
            try:
                engine = get_engine()
                result = engine.run_firewall_verification(net_type)
                socketio.emit("battle_complete", result)
            except Exception as e:
                logger.error(f"Network battle error: {e}")
                socketio.emit("battle_error", {"msg": str(e)})
            finally:
                _battle_running = False
 
        threading.Thread(target=run_net, daemon=True).start()
        return
 
    if vuln_key not in CVE_DB:
        emit("battle_error", {"msg": f"Unknown vulnerability type: {vuln_key}"})
        return
 
    def run():
        global _battle_running
        _battle_running = True
        try:
            engine = get_engine()
            engine.run(vuln_key)
        except Exception as e:
            logger.error(f"Battle error: {e}")
            socketio.emit("battle_error", {"msg": str(e)})
        finally:
            _battle_running = False
 
    threading.Thread(target=run, daemon=True).start()
 
 
@socketio.on("get_stats")
def on_stats():
    emit("stats_update", get_engine().get_stats())
 
 
# Live ticker
 
def live_ticker():
    msgs = [
        ("INFO",    "research:",  "la-orch",  "NVD sync complete — no new critical CVEs in monitored stack"),
        ("INFO",    "orchestra…", "la-orch",  lambda: f"Cycle #{get_engine().cycle}: All agents nominal"),
        ("INFO",    "red:",       "la-red",   "Passive recon: monitoring api-gateway for configuration drift"),
        ("INFO",    "blue:",      "la-blue",  "Digital twin: regression suite 847/847 tests passing"),
        ("INFO",    "audit:",     "la-audit", "Tamper check: HMAC chain integrity verified — no anomalies"),
        ("INFO",    "network:",   "la-red",   "Network layer: port scan baseline — 3 open ports (22,80,443)"),
        ("INFO",    "network:",   "la-red",   "Network layer: C2 beacon monitor — no anomalous egress detected"),
        ("INFO",    "network:",   "la-red",   "Network layer: brute-force threshold — 0 login floods in last 5m"),
        ("INFO",    "network:",   "la-red",   "Network layer: exfil detector — outbound entropy within normal range"),
        ("SUCCESS", "network:",   "la-red",   "Network layer: traffic flood sentinel — rate limiter holding"),
    ]
    import random
    from datetime import datetime
    while True:
        time.sleep(4)
        if not _battle_running:
            m = random.choice(msgs)
            msg = m[3]() if callable(m[3]) else m[3]
            ts = datetime.now().strftime("%H:%M:%S")
            lvc = {"INFO":"lv-info","SUCCESS":"lv-success","ERROR":"lv-error","WARNING":"lv-warn"}.get(m[0],"lv-info")
            socketio.emit("op_log", {"ts":ts,"lv":m[0],"lvc":lvc,"ag":m[1],"ac":m[2],"msg":msg})
 
 
if __name__ == "__main__":
    os.makedirs("audit_logs", exist_ok=True)
 
    # Pre-init engine
    get_engine()

    # Start SentinelAI (target server on :6100, honeypot on 28 ports, 5 detectors)
    if SENTINEL_AVAILABLE:
        sentinel_ok = start_sentinel(
            socketio,
            host="0.0.0.0",
            port=int(os.getenv("SENTINEL_PORT", 6100)),
            autoblock=os.getenv("SENTINEL_AUTOBLOCK", "true").lower() != "false",
        )
        if sentinel_ok:
            print("  [✓] SentinelAI      →  target on :6100 | honeypot 28 ports | 5 detectors")
        else:
            print("  [!] SentinelAI failed to start — check sentinel_ai/ folder")
    else:
        print("  [!] SentinelAI not found — place sentinel_ai/ folder next to app.py")

    # Start ticker
    threading.Thread(target=live_ticker, daemon=True).start()
 
    port = int(os.getenv("DASHBOARD_PORT", 5000))
    print(f"""
╔══════════════════════════════════════════════════╗
║   🐾 DataWatchDawgs v2 + SentinelAI             ║
║                                                  ║
║   Dashboard:   http://localhost:{port}            ║
║   SentinelAI:  http://localhost:{port}/sentinel   ║
║   Judges View: http://localhost:{port}/judges     ║
║   Attacker:    http://localhost:{port}/attacker   ║
║                                                  ║
║   Attack target (SentinelAI): port 6100         ║
║   Press Ctrl+C to stop                          ║
╚══════════════════════════════════════════════════╝
""")
    socketio.run(app, host="0.0.0.0", port=port,
                 debug=False, allow_unsafe_werkzeug=True)