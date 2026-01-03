---

# 🛡️ ARGUS v0: Offline AI Threat Detection for NGOs

**Privacy-first, AI-powered network security for organizations that can't afford enterprise tools.**

## What is ARGUS?

ARGUS is an offline cybersecurity system that protects your network from ransomware, data theft, and botnet attacks. It runs on a $60 Raspberry Pi, learns your network behavior, and automatically detects threats—all without sending data to the cloud.

**No subscriptions. No cloud dependency. No data exfiltration.**

## Why ARGUS?

| Problem | ARGUS Solution |
|---------|---|
| Darktrace costs $50k+/year | ARGUS is free for NGOs |
| Requires cloud access | Runs completely offline |
| Complex to deploy | 5-minute installation |
| Privacy concerns | All data stays on your network |
| Not designed for low bandwidth | Works on any network |

## Quick Start (5 Minutes)

### Requirements
- Raspberry Pi 4 (8GB RAM)
- Ethernet cable + internet connection
- microSD card (32GB+)
- Firebase account (free)

### Installation

```bash
# 1. Download and run installer
curl -fsSL https://github.com/Ojas-bb/Argus_V/releases/download/v0.1.0/install.sh | bash

# 2. Answer setup questions (Firebase credentials, network interface)
# 3. Done! Services start automatically
# 4. Verify: systemctl status argus-retina argus-mnemosyne argus-shield
```

## How It Works

**3 components working together:**

1. **Retina** 👁️ - Captures network packets
   - Watches all traffic flowing through your network
   - Extracts key patterns (packet sizes, timing, volume)
   - Stores in local CSV files

2. **Mnemosyne** 🧠 - AI Brain
   - Learns what "normal" traffic looks like for YOUR network
   - Uses Isolation Forest (AI algorithm) to spot anomalies
   - Retrains weekly to stay current

3. **Aegis** 🛡️ - Protection Engine
   - Runs real-time detection (every 5 seconds)
   - Compares live traffic against learned baseline
   - Blocks malicious IPs automatically (after 7-day safety period)

## Detailed Installation

### Step 1: Prepare Hardware

```bash
# Flash Raspberry Pi OS Lite to microSD card
# Use Raspberry Pi Imager (https://www.raspberrypi.com/software/)
# Boot Pi with internet connection
```

### Step 2: Set Up Firebase

```
1. Go to https://console.firebase.google.com
2. Create project "argus-v0"
3. Create Realtime Database (Asia-Southeast1)
4. Create Cloud Storage bucket
5. Generate service account JSON key
6. Keep JSON key safe (you'll need it during install)
```

### Step 3: Run Installer

```bash
# SSH into Pi
ssh pi@[pi-ip]

# Download and run installer
curl -fsSL https://raw.githubusercontent.com/Ojas-bb/Argus_V/main/install.sh | bash

# Follow interactive prompts:
# - Paste Firebase service account JSON
# - Select network interface (usually eth0)
# - Confirm dry-run mode (mandatory for 7 days)
```

### Step 4: Verify Installation

```bash
# Check all services running
systemctl status argus-retina argus-mnemosyne argus-shield

# View logs
tail -f /var/log/argus/retina.log
tail -f /var/log/argus/mnemosyne.log
tail -f /var/log/argus/aegis.log
```

## Configuration

Edit `/etc/argus/config.yaml`:

```yaml
retina:
  interface: eth0           # Network interface to monitor
  window_size: 5           # Flow window (seconds)
  
mnemosyne:
  contamination: 0.05      # % of traffic expected to be anomalies
  retraining_day: "Sunday" # Weekly retraining
  
aegis:
  dry_run_days: 7          # Days before actual blocking starts
  enable_blocking: false   # Set to true after dry-run
```

## Features

✅ **Offline-First** - No cloud, no data exfiltration  
✅ **Privacy-First** - Data deleted after 24 hours  
✅ **AI-Powered** - Learns your specific network  
✅ **Automatic** - No manual configuration needed  
✅ **Safe** - 7-day dry-run before blocking  
✅ **Smart Updates** - Weekly model retraining  
✅ **Zero Downtime** - Automatic updates without restarting  

## Deployment Options

### Option A: Inline (Recommended)

```
[Router] --ethernet--> [Pi Running ARGUS] --ethernet--> [NGO Network]
```

Pi acts as gateway, sees all traffic. Best detection accuracy.

**Setup:**
1. Connect Pi between router and network
2. Configure router's default gateway to Pi
3. Done!

### Option B: Port Mirroring (Advanced)

```
[Managed Switch] --SPAN port to Pi--> [Pi Running ARGUS]
```

Requires managed switch with SPAN/mirroring capability.

See NETWORKING.md for detailed diagrams.

## Usage

### Check Status

```bash
systemctl status argus-shield
journalctl -u argus-shield -f
```

### View Blocked IPs

```bash
tail -20 /var/log/argus/aegis.log | grep "BLOCKED"
```

### Manual Retraining

```bash
systemctl start argus-mnemosyne-train
```

### Disable Blocking (Emergency)

```bash
systemctl stop argus-shield
# Or edit config.yaml: enable_blocking: false
```

### Check Model Performance

```bash
cat /var/log/argus/mnemosyne.log | tail -30
```

## Troubleshooting

### "Pi can't reach Firebase"

```bash
# Test connectivity
ping 8.8.8.8
curl https://www.google.com

# Check Firebase credentials
cat /opt/argus/firebase-config.json | head -3

# Verify service account has Realtime DB access
```

### "Model fails to load"

```bash
# Check disk space
df -h /opt/argus

# Verify model file exists
ls -lh /opt/argus/models/

# Check permissions
sudo chown -R argus:argus /opt/argus
```

### "No packets captured"

```bash
# Verify interface is correct
ip link show

# Check if interface is up
sudo ip link set eth0 up

# Test packet capture
sudo tcpdump -i eth0 -c 10
```

### "False positives (high blocking rate)"

```bash
# You're still in dry-run mode - this is expected
# After 7 days, model will be more accurate

# Or: Adjust contamination in config.yaml
mnemosyne:
  contamination: 0.1  # Increase if too sensitive
```

## Security & Privacy

🔒 **Data Retention:** 24 hours only (then deleted)  
🔐 **Anonymization:** IP hashing, timestamp rounding  
🔒 **Encryption:** TLS for all Firebase communication  
🔐 **No Cloud:** 100% runs locally  
🔒 **No Tracking:** No telemetry or analytics  
🔐 **Code Access:** Tied to active contract (revoked on termination)  

## Support

📧 **Email:** karman.labs.contact@gmail.com  
📖 **Docs:** See `/docs/` folder  
🔍 **Logs:** `/var/log/argus/`  
📋 **Debug:** See SUPPORT.md for log collection  

## Roadmap

| Version | Feature | Status |
|---------|---------|--------|
| v0 (Now) | Network threat detection | ✅ Done |
| v1.5 | Device vulnerability scanning + auto-patching | 🔄 In Progress |
| v2.0 | DPI (encrypted threat detection) | 📅 Q2 2025 |
| v3.0+ | Threat intelligence API | 📅 Q3 2025+ |

## License & Pricing

**Free Tier (NGO Pilots)**
- Full ARGUS detection
- Data collection for model improvement (anonymized)
- Email support

**Paid Tier ($2-5k/year)**
- Zero data collection (all local)
- Daily model updates
- Priority support

**Enterprise**
- Custom threat intelligence
- On-call support
- Dedicated account manager

## Legal

- Closed source (proprietary)
- Source code access tied to active contract
- Non-redistribution clause
- See LICENSE file for full terms

## Technology Stack

- **Language:** Python 3.8+
- **ML:** scikit-learn (Isolation Forest)
- **Networking:** scapy, pcap
- **Infrastructure:** Firebase, GitHub Actions
- **OS:** Raspberry Pi OS (Debian-based)

## Architecture

```
┌─────────────────────────────────────┐
│     NGO Network Traffic             │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│  Retina: Packet Capture             │
│  (5-second windows, 4 features)     │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│  Mnemosyne: AI Training (Weekly)    │
│  (Learn normal baseline)             │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│  Aegis: Real-Time Detection         │
│  (Compare → Score → Block)           │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│  Blocked Traffic (iptables DROP)    │
└─────────────────────────────────────┘
```

## Contributing

Not open source. Research partnerships: Contact us.

## Credits

Built by [Your Name] at MIT for [Organization Name].

Inspired by privacy-first design (Tor, Signal) and academic anomaly detection research.

---

**Ready to protect your network? Start the 5-minute install above.** 🚀
