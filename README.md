# 🕵️‍♂️ Network Phantom Tool

> "Know the network. Hide in the noise. Strike precisely."

A professional-grade, stealth-first network scanner built with asynchronous Python.

## 🎯 Why This Tool?

Traditional network scanners are fast but loud — they trigger IDS/IPS systems, firewalls, and logging traps. This tool is built for those who need to scan without being seen.

Whether you're a Red Teamer, Pentester, or Threat Emulation Specialist, this tool offers:

- 🔒 **Stealth**: Minimize detection with advanced evasion techniques
- ⚡ **Speed**: Leverage asynchronous Python for rapid scanning
- 📊 **Precision**: Accurate service detection and detailed reporting
- 💡 **Flexibility**: Highly customizable for diverse use cases

## 🚀 Core Features

| Feature | Description |
|---------|-------------|
| ⚙️ **Async TCP SYN Scanner** | High-speed, non-blocking scanning using asyncio |
| 🕵️‍♂️ **Stealth Techniques** | Random delays, IP shuffling, non-linear port logic |
| 📡 **Service Detection** | Lightweight fingerprinting (HTTP, SSH, RDP, etc.) |
| 🧱 **Firewall Evasion** (Planned) | FIN/NULL/Xmas scans for advanced bypassing |
| 🧢 **MAC Spoofing** (Planned) | Change MAC address before each probe group |
| 🕸 **Decoy IPs** (Planned) | Inject fake source IPs to obscure origin |
| 🧃 **Fake HTTP Headers** | Simulate real browsers on web ports for authenticity |
| 🌪 **Traffic Noise** | Random harmless TCP/UDP packets as cover |
| 📁 **Detailed Logs** | JSON and .log files with precise timestamps |

## 🧪 Example Usage

```bash
# 📍 Basic subnet scan
python3 network_diagnostic.py 192.168.1.0/24

# 🚀 High concurrency, targeted ports
python3 network_diagnostic.py 10.0.0.0/24 --ports 22,80,443 --max-concurrent 100

# 🕵️‍♂️ Low-stealth scan with random delays
python3 network_diagnostic.py 172.16.0.0/16 --delay-min 1.0 --delay-max 5.0
```

## ⚙️ CLI Options

| Flag | Description |
|------|-------------|
| `subnet` | Target subnet (e.g., 192.168.1.0/24) |
| `--ports` | Comma-separated ports (default: 1-1024) |
| `--max-concurrent` | Number of concurrent tasks (default: 50) |
| `--delay-min` / `--delay-max` | Range of delay between scans (in seconds) |
| `--output` | Output file prefix |
| `--no-stealth` | Disable all stealth behaviors |

## 🧾 Output Sample (JSON)

```json
{
  "ip_address": "192.168.1.10",
  "port": 443,
  "status": "open",
  "service": "HTTPS",
  "response_time": 11.53
}
```

## 📁 Output Files

- `scan_results.json`: Structured scan output
- `scan.log`: Timestamped plain log file

## 🛠️ Upcoming Features

- Decoy IP support for enhanced obfuscation
- TCP FIN/NULL/Xmas flag support for firewall evasion
- MAC address randomization for local network stealth
- HTTP browser header spoofing for realistic probes
- Web interface for visualization and analysis

## 🧠 Behind the Tool

This tool was built with a simple goal: **Deliver powerful scanning capabilities to ethical hackers, without compromising stealth.**

Built entirely in Python 3, leveraging:
- `asyncio` for high-performance parallelism
- `random` for entropy in stealth techniques
- `scapy` for low-level packet control (planned)
- `logging` and `JSON` for clean, structured output

## ⚠️ Legal Disclaimer

**This tool is intended for educational use and authorized penetration testing only.**

Do not use it on networks you don't own or have explicit permission to test. Unauthorized use may violate laws and regulations.

## ✨ Final Thought

> "Being seen is a risk."

If you need reconnaissance without detection, this tool is your silent ally.

---

**Contributing**: Pull requests are welcome. For major changes, please open an issue first.

**License**: MIT License - see LICENSE file for details.