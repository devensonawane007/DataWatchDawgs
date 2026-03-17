#!/usr/bin/env python3
"""
attack_simulator.py — CLI Controller for the Cyber Attack Simulation Toolkit

This is the main entry-point.  It uses ``argparse`` to let users pick an
attack mode and configure module-specific options from the command line.

Usage examples
--------------
  python attack_simulator.py --mode portscan --target 192.168.1.10
  python attack_simulator.py --mode brute   --target http://192.168.1.10/login
  python attack_simulator.py --mode flood   --target http://192.168.1.10 --duration 10
  python attack_simulator.py --mode exfil   --target 192.168.1.10 --port 8080
  python attack_simulator.py --mode c2      --target http://192.168.1.10:4444
  python attack_simulator.py --mode normal  --duration 30

Press Ctrl+C at any time to stop a running simulation gracefully.
"""

import argparse
import sys
import os

# Ensure project root is on sys.path so modules resolve correctly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    DEFAULT_TARGET,
    DEFAULT_PORT,
    DEFAULT_DURATION,
    DEFAULT_PORT_RANGE,
    DEFAULT_RPS,
    FLOOD_THREADS,
    DEFAULT_CHUNK_SIZE,
    DEFAULT_CHUNK_COUNT,
    DEFAULT_BEACON_INTERVAL,
    DEFAULT_USERNAME,
    DEFAULT_WORDLIST,
    BRUTE_FORCE_DELAY,
)
from logger import get_logger

# ── Module registry ───────────────────────────────────────────────────────────
# Lazy mapping: mode-name → (import path, class name)
MODULE_MAP = {
    "portscan": ("modules.port_scan",        "PortScanSimulator"),
    "brute":    ("modules.brute_force",       "BruteForceSimulator"),
    "flood":    ("modules.traffic_flood",     "TrafficFloodSimulator"),
    "exfil":    ("modules.data_exfiltration", "DataExfiltrationSimulator"),
    "c2":       ("modules.c2_beacon",         "C2BeaconSimulator"),
    "normal":   ("modules.normal_traffic",    "NormalTrafficGenerator"),
}

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║       ⚡  CYBER ATTACK SIMULATION TOOLKIT  ⚡               ║
║       Safe lab-only network attack simulator               ║
║       For IDS / DPI / AI detection testing                 ║
╚══════════════════════════════════════════════════════════════╝
"""


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Cyber Attack Simulation Toolkit — safe, modular network attack simulator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available modes:
  portscan   Scan a range of TCP ports on the target
  brute      Brute-force login attempts against an HTTP endpoint
  flood      High-frequency HTTP / TCP traffic flood
  exfil      Data exfiltration (random data to a remote server)
  c2         C2 beaconing (periodic HTTP check-ins)
  normal     Normal web-browsing traffic (baseline)

Examples:
  python attack_simulator.py --mode portscan --target 192.168.1.10
  python attack_simulator.py --mode brute --target http://192.168.1.10/login --username admin
  python attack_simulator.py --mode flood --target http://192.168.1.10 --duration 10 --rps 200
  python attack_simulator.py --mode exfil --target 192.168.1.10 --port 8080 --protocol tcp
  python attack_simulator.py --mode c2 --target http://192.168.1.10:4444 --interval 3
  python attack_simulator.py --mode normal --duration 30
""",
    )

    # ── Required ──────────────────────────────────────────────────────────
    parser.add_argument(
        "--mode", "-m",
        required=True,
        choices=MODULE_MAP.keys(),
        help="Attack simulation mode to run.",
    )

    # ── Common options ────────────────────────────────────────────────────
    parser.add_argument("--target", "-t", default=DEFAULT_TARGET,
                        help=f"Target host or URL (default: {DEFAULT_TARGET}).")
    parser.add_argument("--port", "-p", type=int, default=DEFAULT_PORT,
                        help=f"Target port (default: {DEFAULT_PORT}).")
    parser.add_argument("--duration", "-d", type=int, default=DEFAULT_DURATION,
                        help=f"Max duration in seconds (default: {DEFAULT_DURATION}).")

    # ── Port-scan options ─────────────────────────────────────────────────
    ps = parser.add_argument_group("Port Scan options")
    ps.add_argument("--ports", default=DEFAULT_PORT_RANGE,
                    help=f"Ports to scan, e.g. '22,80,443' or '1-1024' (default: {DEFAULT_PORT_RANGE}).")
    ps.add_argument("--speed", choices=["fast", "stealth"], default="fast",
                    help="Scan speed: 'fast' or 'stealth' (default: fast).")

    # ── Brute-force options ───────────────────────────────────────────────
    bf = parser.add_argument_group("Brute Force options")
    bf.add_argument("--username", default=DEFAULT_USERNAME,
                    help=f"Username to brute-force (default: {DEFAULT_USERNAME}).")
    bf.add_argument("--wordlist", default=DEFAULT_WORDLIST,
                    help="Path to password wordlist file.")
    bf.add_argument("--delay", type=float, default=BRUTE_FORCE_DELAY,
                    help=f"Delay between attempts in seconds (default: {BRUTE_FORCE_DELAY}).")

    # ── Flood options ─────────────────────────────────────────────────────
    fl = parser.add_argument_group("Traffic Flood options")
    fl.add_argument("--rps", type=int, default=DEFAULT_RPS,
                    help=f"Target requests per second (default: {DEFAULT_RPS}).")
    fl.add_argument("--threads", type=int, default=FLOOD_THREADS,
                    help=f"Number of concurrent threads (default: {FLOOD_THREADS}).")

    # ── Exfiltration options ──────────────────────────────────────────────
    ex = parser.add_argument_group("Data Exfiltration options")
    ex.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE,
                    help=f"Bytes per data chunk (default: {DEFAULT_CHUNK_SIZE}).")
    ex.add_argument("--chunk-count", type=int, default=DEFAULT_CHUNK_COUNT,
                    help=f"Number of chunks to send (default: {DEFAULT_CHUNK_COUNT}).")
    ex.add_argument("--protocol", choices=["http", "tcp"], default="http",
                    help="Transport protocol (default: http).")

    # ── C2 options ────────────────────────────────────────────────────────
    c2 = parser.add_argument_group("C2 Beaconing options")
    c2.add_argument("--interval", type=float, default=DEFAULT_BEACON_INTERVAL,
                    help=f"Beacon interval in seconds (default: {DEFAULT_BEACON_INTERVAL}).")

    return parser


def resolve_module(mode: str):
    """Dynamically import and return the module class for *mode*."""
    mod_path, cls_name = MODULE_MAP[mode]
    import importlib
    mod = importlib.import_module(mod_path)
    return getattr(mod, cls_name)


def main() -> None:
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()
    logger = get_logger("controller")

    logger.info("Mode: %s  |  Target: %s:%d  |  Duration: %ds",
                args.mode, args.target, args.port, args.duration)

    # Build kwargs dict with module-specific options
    kwargs = {}
    if args.mode == "portscan":
        kwargs = {"ports": args.ports, "speed": args.speed}
    elif args.mode == "brute":
        kwargs = {"username": args.username, "wordlist": args.wordlist, "delay": args.delay}
    elif args.mode == "flood":
        kwargs = {"rps": args.rps, "threads": args.threads}
    elif args.mode == "exfil":
        kwargs = {
            "chunk_size": args.chunk_size,
            "chunk_count": args.chunk_count,
            "protocol": args.protocol,
        }
    elif args.mode == "c2":
        kwargs = {"interval": args.interval}

    # Instantiate the chosen module
    ModuleClass = resolve_module(args.mode)
    module = ModuleClass(
        target=args.target,
        port=args.port,
        duration=args.duration,
        **kwargs,
    )

    # Run with graceful Ctrl+C handling
    try:
        module.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user — stopping simulation …")
        module.stop()
        module.print_summary()

    logger.info("Simulation finished.  Logs saved to logs/attack_simulation.log")


if __name__ == "__main__":
    main()
