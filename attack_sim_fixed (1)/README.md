# 🛡️ Cyber Attack Simulation Toolkit

A **modular, Python-based** network attack simulator designed for testing AI-powered Intrusion Detection Systems (IDS) and Deep Packet Inspection (DPI) engines. Safe to run inside a local lab network — no Kali Linux or external penetration tools required.

---

## 📁 Project Structure

```
attack_sim/
├── attack_simulator.py          # CLI controller (main entry-point)
├── config.py                    # Shared defaults & constants
├── logger.py                    # Centralised logging (console + file)
├── modules/
│   ├── __init__.py
│   ├── base.py                  # Abstract base class for all modules
│   ├── port_scan.py             # Port Scan Simulator
│   ├── brute_force.py           # Brute Force Login Simulator
│   ├── traffic_flood.py         # Traffic Flood / Mini DDoS
│   ├── data_exfiltration.py     # Data Exfiltration Simulator
│   ├── c2_beacon.py             # Command & Control Beaconing
│   └── normal_traffic.py        # Normal Traffic Generator (baseline)
├── wordlists/
│   └── passwords.txt            # Sample password wordlist (~50 entries)
├── logs/                        # Runtime logs (auto-created)
└── README.md                    # This file
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+** (uses only the standard library — no `pip install` needed)

### Run a simulation

```bash
python attack_simulator.py --mode <MODE> [options]
```

### Available Modes

| Mode       | Description                                      |
| ---------- | ------------------------------------------------ |
| `portscan` | TCP port scan (fast or stealth)                  |
| `brute`    | Brute-force login attempts against HTTP endpoint |
| `flood`    | High-frequency HTTP / TCP traffic flood          |
| `exfil`    | Data exfiltration (random data to remote server) |
| `c2`       | C2 beaconing (periodic HTTP check-ins)           |
| `normal`   | Normal web browsing traffic (baseline)           |

---

## 📖 Usage Examples

### 1️⃣ Port Scan

```bash
# Fast scan of ports 1-1024 on a target
python attack_simulator.py --mode portscan --target 192.168.1.10

# Stealth scan of specific ports
python attack_simulator.py --mode portscan --target 192.168.1.10 --ports 22,80,443,3306,8080 --speed stealth
```

### 2️⃣ Brute Force Login

```bash
# Default: tries passwords from wordlists/passwords.txt against /login
python attack_simulator.py --mode brute --target http://192.168.1.10/login

# Custom username and wordlist
python attack_simulator.py --mode brute --target http://192.168.1.10/login --username root --wordlist /path/to/wordlist.txt --delay 0.2
```

### 3️⃣ Traffic Flood / Mini DDoS

```bash
# 10-second flood at 200 RPS with 10 threads
python attack_simulator.py --mode flood --target http://192.168.1.10 --duration 10 --rps 200

# Higher intensity
python attack_simulator.py --mode flood --target http://192.168.1.10 --duration 30 --rps 500 --threads 20
```

### 4️⃣ Data Exfiltration

```bash
# HTTP-based exfiltration (50 chunks × 1 KB)
python attack_simulator.py --mode exfil --target http://192.168.1.10:8080

# Raw TCP exfiltration with larger chunks
python attack_simulator.py --mode exfil --target 192.168.1.10 --port 9999 --protocol tcp --chunk-size 4096 --chunk-count 100
```

### 5️⃣ C2 Beaconing

```bash
# Beacon every 5 seconds for 60 seconds
python attack_simulator.py --mode c2 --target http://192.168.1.10:4444 --duration 60

# Faster beaconing (every 2 seconds)
python attack_simulator.py --mode c2 --target http://192.168.1.10:4444 --interval 2 --duration 120
```

### 6️⃣ Normal Traffic (Baseline)

```bash
# Generate normal browsing traffic for 60 seconds
python attack_simulator.py --mode normal --duration 60
```

---

## 🔧 Common CLI Flags

| Flag             | Default       | Description                              |
| ---------------- | ------------- | ---------------------------------------- |
| `--mode`, `-m`   | *(required)*  | Simulation mode (see table above)        |
| `--target`, `-t` | `127.0.0.1`   | Target host or URL                       |
| `--port`, `-p`   | `80`          | Target port                              |
| `--duration`, `-d` | `30`        | Max runtime in seconds                   |

Run `python attack_simulator.py --help` for the full list of module-specific flags.

---

## 📝 Logging

All simulations produce structured logs in two places:

1. **Console** — real-time, human-readable output.
2. **`logs/attack_simulation.log`** — persistent file with rotating backups (5 MB × 3).

Log format:

```
TIMESTAMP | LEVEL    | MODULE               | MESSAGE
2026-03-14 20:30:15 | INFO     | PortScan             | Port    80 — OPEN
2026-03-14 20:30:15 | INFO     | PortScan             | Port   443 — OPEN
```

---

## 🔌 Integration with IDS / AI Detection Systems

This toolkit is designed to be **easy to integrate** with detection systems:

### Network-Level Integration
- Point your IDS sensor at the same network segment and run simulations — the toolkit generates real TCP / HTTP traffic that any packet capture tool (Wireshark, tcpdump, Zeek) can observe.

### Log-Based Integration
- Parse `logs/attack_simulation.log` and feed structured entries into your ML pipeline as labelled attack data.

### Programmatic Integration
- Import modules directly in your own Python code:

```python
from modules.port_scan import PortScanSimulator

scanner = PortScanSimulator(target="192.168.1.10", ports="22,80,443", speed="stealth")
stats = scanner.run()
print(stats)
```

### Mixed Traffic Testing
Run normal + attack traffic simultaneously to test anomaly detection:

```bash
# Terminal 1 — baseline
python attack_simulator.py --mode normal --duration 120

# Terminal 2 — attack
python attack_simulator.py --mode flood --target http://192.168.1.10 --duration 30
```

---

## ⚠️ Safety & Legal Notice

> **This toolkit is intended ONLY for authorised security testing in controlled lab environments.**

- Run only against systems you own or have explicit permission to test.
- Do **not** use against production networks or third-party services.
- The toolkit uses only Python's standard library and generates traffic from your machine — it does not exploit real vulnerabilities.

---

## 🏗️ Architecture

```
┌───────────────────────────────────────────────┐
│            attack_simulator.py                │
│         (CLI controller / argparse)           │
└──────────────────┬────────────────────────────┘
                   │  selects mode
                   ▼
┌──────────────────────────────────────────────┐
│              AttackModule (base.py)           │
│  • logger   • stats   • stop() / run()       │
└──────┬───────┬───────┬───────┬───────┬───────┘
       │       │       │       │       │
  PortScan  Brute  Flood  Exfil   C2   Normal
```

Each module inherits from `AttackModule` and implements a `run()` method that returns a `stats` dictionary. The base class provides shared logging, graceful shutdown via threading events, and a summary printer.

---

## 📄 License

For educational and research purposes only.
