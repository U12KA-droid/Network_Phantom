# 🕵️ Network_Phantom
### *The Silent Hunter for Red Team Operations*

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-Educational-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Cross--Platform-lightgrey.svg)](README.md)

> *"In the shadows of the network, where packets whisper secrets and ports tell stories, this tool becomes your invisible companion."*

**Why settle for basic port scanners when you can have a ghost?** This isn't just another network reconnaissance tool—it's a sophisticated penetration testing companion designed for red teamers who understand that **stealth is strategy**.

---

## 🎯 Why Red Teamers Choose This Tool

**Traditional scanners get caught. Smart operators stay invisible.**

In today's SOC-monitored environments, your scanning technique can make or break an engagement. This tool was born from real-world red team operations where detection meant mission failure. Every feature has been battle-tested in environments where blue teams actually know what they're doing.

### The Red Team Advantage
- **🚫 Zero Full TCP Handshakes** - SYN-only scanning leaves minimal forensic traces
- **🎭 Decoy Army** - Launch from multiple fake IPs simultaneously to confuse attribution
- **⏰ Human-Like Timing** - Randomized delays that mimic organic network behavior  
- **🔀 Anti-Pattern Design** - Shuffled IPs and ports break sequential detection rules
- **👻 Multiple Evasion Vectors** - Combine techniques that individually bypass different security controls

---

## ⚡ Core Features

| Feature | Description | Red Team Benefit |
|---------|-------------|------------------|
| **🔄 Async SYN Scanning** | Non-blocking TCP SYN checks without full connections | Faster scans with lower detection probability |
| **🎭 Decoy IP Generation** | Parallel scans from fake source IPs in target subnet | Attribution confusion and IDS noise |
| **🏴 Custom TCP Flags** | SYN/FIN/NULL/XMAS scan types | Different evasion profiles for various firewalls |
| **🔀 MAC Randomization** | Automatic MAC address changes during scan | Layer 2 attribution avoidance |
| **🌊 Noise Traffic** | Random TCP/UDP packets to multiple ports | Legitimate scan traffic obfuscation |
| **🌐 HTTP Header Spoofing** | Realistic browser User-Agent and headers | Web service enumeration without fingerprinting |
| **⏱️ Intelligent Timing** | Configurable jittered delays between operations | Organic traffic pattern simulation |
| **📊 Multi-Format Logging** | JSON, detailed logs, and stealth operation tracking | Complete operation documentation |

---

## 🚀 Installation

```bash
# Clone the repo
git clone https://github.com/your-repo/network-diagnostic-tool.git
cd network-diagnostic-tool

# Install dependencies
pip install aiohttp

# For MAC randomization (Linux/macOS)
sudo python network_diagnostic.py --help
```

---

## 💻 Example Usage

### 🎯 Stealth Reconnaissance
```bash
# Ghost mode - Maximum evasion for high-security targets
python network_diagnostic.py 10.0.0.0/24 \
  --use-decoys --decoy-count 15 \
  --tcp-flags SYN,FIN,NULL \
  --change-mac --mac-interval 25 \
  --noise-traffic \
  --delay-min 3.0 --delay-max 12.0 \
  --max-concurrent 20
```

### 🌐 Web Application Discovery
```bash
# Web-focused scan with realistic browser behavior
python network_diagnostic.py 192.168.1.0/24 \
  --ports 80,443,8080,8443,3000,5000,8000,9000 \
  --fake-http-headers \
  --tcp-flags SYN,FIN \
  --delay-min 1.0 --delay-max 4.0
```

### ⚡ High-Speed Internal Network Mapping
```bash
# Fast internal network discovery (trusted environment)
python network_diagnostic.py 172.16.0.0/16 \
  --max-concurrent 200 \
  --use-decoys --decoy-count 5 \
  --delay-min 0.1 --delay-max 0.5
```

### 🎭 Advanced Evasion Techniques
```bash
# Multi-vector evasion for mature security environments
python network_diagnostic.py 203.0.113.0/24 \
  --tcp-flags FIN,NULL,XMAS \
  --change-mac --mac-interval 10 \
  --noise-traffic \
  --fake-http-headers \
  --delay-min 5.0 --delay-max 20.0 \
  --output stealth_scan_$(date +%Y%m%d)
```

---

## 📋 Sample Output

### JSON Results Format
```json
{
  "scan_metadata": {
    "start_time": "2025-06-15T14:30:25Z",
    "target_range": "192.168.1.0/24",
    "scan_techniques": ["SYN", "FIN", "decoys"],
    "total_hosts": 254,
    "scan_duration": "00:12:34"
  },
  "results": [
    {
      "ip": "192.168.1.100",
      "hostname": "web-server-01.local",
      "open_ports": [
        {
          "port": 80,
          "service": "http",
          "response_time": 0.045,
          "headers": {
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/7.4.3"
          }
        },
        {
          "port": 22,
          "service": "ssh",
          "response_time": 0.023,
          "banner": "SSH-2.0-OpenSSH_8.2p1"
        }
      ],
      "decoy_results": {
        "successful_decoys": 8,
        "failed_decoys": 2,
        "attribution_confusion": "high"
      }
    }
  ],
  "stealth_metrics": {
    "mac_changes": 45,
    "noise_packets_sent": 1247,
    "timing_variance": 0.85,
    "detection_probability": "very_low"
  }
}
```

### Console Output Preview
```
[14:30:25] 🎭 Initializing decoy IPs: 192.168.1.201, 192.168.1.202, 192.168.1.203...
[14:30:26] 🔀 MAC address changed to: aa:bb:cc:dd:ee:ff
[14:30:27] 🌊 Noise traffic injection started (background)
[14:30:28] 🎯 Scanning 192.168.1.100 - Ports: 22✓ 80✓ 443✗
[14:30:31] 📊 Host 192.168.1.100: 2 open ports, 3 decoy confirmations
[14:30:45] 🔀 MAC address rotated (scan #25)
[14:32:15] ✅ Scan complete: 45 hosts up, 127 services discovered
[14:32:15] 👻 Stealth score: 9.2/10 (excellent evasion)
```

---

## ⚙️ How It Works

### The Stealth Engine
This tool operates on the principle of **distributed deception**. Instead of scanning from a single source with predictable patterns, it orchestrates a symphony of evasion techniques:

1. **🎭 Decoy Orchestration**: Generates legitimate-looking source IPs within the target subnet and launches parallel scans, making it nearly impossible to identify the real attacker
2. **🧬 Protocol Mutation**: Alternates between different TCP flag combinations (SYN, FIN, NULL, XMAS) to evade signature-based detection
3. **⏰ Temporal Obfuscation**: Uses machine learning-inspired timing algorithms that mimic human browsing patterns
4. **🔀 Layer 2 Ghosting**: Periodically changes MAC addresses to break hardware-based tracking
5. **🌊 Traffic Camouflage**: Injects realistic noise traffic to hide legitimate reconnaissance packets

### Architecture Overview
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Async Engine  │────│  Stealth Layer   │────│   Target Range  │
│   (AsyncIO)     │    │  (Evasion)       │    │   (Scanning)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Timing Control  │    │ Decoy Generator  │    │  Port Probing   │
│ MAC Rotation    │    │ Noise Injection  │    │  Service ID     │
│ Result Logging  │    │ Header Spoofing  │    │  Banner Grab    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

---

## 🛡 Legal Disclaimer

⚠️ **AUTHORIZED USE ONLY** ⚠️

This tool is designed for **authorized security testing, penetration testing, and network administration** purposes only. Users must:

- ✅ Obtain explicit written permission before scanning any network
- ✅ Comply with all applicable laws and regulations  
- ✅ Use only on networks you own or have contractual authorization to test
- ✅ Respect scope limitations and rules of engagement
- ❌ Never use for unauthorized access or malicious purposes

**The developers assume no responsibility for misuse of this tool. Professional red teamers understand that with great power comes great responsibility.**

---

## 🚀 Upcoming Features

### 🔮 Roadmap v2.0
- [ ] **AI-Powered Timing** - Machine learning models for even more realistic traffic patterns
- [ ] **Protocol Tunneling** - Embed scans within legitimate protocols (DNS, ICMP, etc.)
- [ ] **Cloud Integration** - Distributed scanning from multiple cloud providers
- [ ] **Custom Payloads** - Scriptable probe packets for specific service enumeration
- [ ] **Threat Intel Integration** - Real-time IOC avoidance during reconnaissance
- [ ] **Mobile Device Simulation** - Mimic smartphone/tablet network behavior

### 🎯 Enterprise Features (v2.5)
- [ ] **Team Collaboration** - Multi-operator scan coordination
- [ ] **Report Generation** - Executive and technical reporting templates  
- [ ] **CI/CD Integration** - Automated security pipeline integration
- [ ] **Custom Dashboards** - Real-time scan visualization and metrics

---

## 📞 Professional Support

Built by red teamers, for red teamers. If you're conducting authorized security assessments and need advanced capabilities, this tool speaks your language.

### Community
- 🐛 **Issues**: Report bugs or request features via GitHub Issues
- 💬 **Discussions**: Share techniques and configurations  
- 📖 **Wiki**: Advanced usage patterns and case studies

---

## 🎖️ Battle-Tested Promise

*"Every great red team operation begins with reconnaissance that goes unnoticed. This tool doesn't just scan networks—it ghosts through them, leaving defenders wondering if they ever saw anything at all. In a world where attribution is everything, invisibility is your greatest asset."*

**Ready to elevate your reconnaissance game? Your next target is waiting, and it won't even know you were there.**

---

### 🔥 Start Your Ghost Hunt Today
```bash
git clone https://github.com/your-repo/network-diagnostic-tool.git
cd network-diagnostic-tool
python network_diagnostic.py --help
```

*The network remembers everything. Make sure it never remembers you.*