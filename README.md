# Linux Security Monitoring and Hardening
**A hands-on project where I built a multi-layered security system on Ubuntu Server, started from scratch and progressively added intrusion detection, automated prevention, and comprehensive security hardening.**

---
## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Lab Environment](#lab-environment)
- [Phase 1: Initial Setup and Baseline](#phase-1-initial-setup-and-baseline)
- [Phase 2: Intrusion Detection with Snort](#phase-2-intrusion-detection-with-snort)
- [Phase 3: Security Hardening](#phase-3-security-hardening)
- [Phase 4: Intrusion Prevention with Fail2Ban](#phase-4-intrusion-prevention-with-fail2ban)
- [Phase 5: Testing Everything Together](#phase-5-testing-everything-together)
- [What I Learned](#what-i-learned)
- [Production vs Lab](#production-vs-lab)
- [References](#references)

---

## Project Overview

### What I Built

This project demonstrates securing an Ubuntu Server from the ground up. I started with a fresh minimal installation and progressively added security layers:

1. **Establish secure remote access** and document baseline security posture
2. **Network intrusion detection** - Custom Snort rules to detect attacks
3. **System hardening** - SSH, firewall, services, file permissions
4. **File integrity monitoring** (auditd)
5. **Password policy enforcement** (PAM)
6. **Rootkit detection** (rkhunter)
7. **Automated prevention** - Fail2Ban integrated with firewall to automatically block attackers
8. **Integration testing** - Simulated real attacks to validate the OS hardening

The goal was to build a defense-in-depth system where multiple security controls work together, so even if one layer fails, another would catch the threat.

### Skills I Demonstrated

**Linux System Administration:**
- Service management and minimization
- File permissions and ownership
- Network configuration
- Package management
- Log analysis and correlation

**Security Implementation:**
- Intrusion detection system configuration
- Intrusion prevention automation
- Firewall management (UFW)
- SSH hardening
- Access control and authentication
- File integrity monitoring
- Security auditing

**Security Operations:**
- Baseline documentation
- Rule creation and tuning
- Attack simulation and validation
- Incident detection and response
- Log correlation across multiple systems

---


## Lab Environment

### Architecture

I used VirtualBox to create two VMs on the same NAT network, this setup mimics a realistic scenario where an attacker had gained access to the same network as the target server.

**Ubuntu Server 24.04 LTS** - The system I'm securing
- 2GB RAM, 25GB disk
- IP: 10.0.2.8
- Minimal installation (fewer services = smaller attack surface)

**Kali Linux 2024** - For attack testing
- 4GB RAM, 80GB disk  
- IP: 10.0.2.15
- Comes with penetration testing tools pre-installed

**Network diagram:**
```
┌─────────────────────────────────────────────┐
│         VirtualBox NAT Network              │
│              (10.0.2.0/24)                  │
│                                             │
│  ┌─────────────────┐   ┌─────────────────┐│
│  │   Kali Linux    │   │  Ubuntu Server  ││
│  │   (Attacker)    │──▶│ (Target/Defend) ││
│  │   10.0.2.15     │   │   10.0.2.8      ││
│  │                 │   │                 ││
│  │  Tools:         │   │  Security:      ││
│  │  • nmap         │   │  • Snort IDS    ││
│  │  • ping flood   │   │  • Fail2Ban IPS ││
│  │  • SSH brute    │   │  • UFW Firewall ││
│  └─────────────────┘   └─────────────────┘│
└─────────────────────────────────────────────┘
```
### Why NAT Network?

I used NAT instead of bridged networking because:
- Complete isolation from my home network (safe to run attacks)
- VMs can still communicate with each other
- Simulates an attacker who's already inside the network (realistic scenario)
- Safety: I could run aggressive attacks without worrying about triggering my home router's security features or ffecting other devices on my network

**Production difference:** In a real enterprise environment, I'd have proper network segmentation with VLANs, DMZs, and multiple firewall layers. This lab simulates a flat internal network where both systems can communicate directly.

---

## Phase 1: Initial Access and Baseline Configuration

### 1.1 Ubuntu Server Initial Login

After installing Ubuntu Server 24.04 LTS (minimized), I logged in directly through the VirtualBox console to begin the security configuration process.

![Initial UFW and SSH Status](screenshots/02-initial-ufw-ssh-status.png)

**Checking network configuration:**
```bash
# Verify IP address
ip addr show

# Output:
# enp0s3: inet 10.0.2.8/24
```

My Ubuntu Server received IP address **10.0.2.8** from the VirtualBox NAT network DHCP server.

**Checking SSH Status**

Before establishing remote access, I verified that SSH was installed and running on the Ubuntu server.

*SSH service status:*
```bash
sudo systemctl status sshd
```
*Key observations:*
- ✅ SSH service is **active (running)**
- ✅ SSH is **enabled** (starts automatically on boot)
- ✅ Listening on **port 22** (default)
- ✅ Listening on all interfaces (0.0.0.0 and ::)

This confirms SSH is ready for remote connections.

**Checking UFW Firewall Status**

Next, I checked the firewall status to understand the baseline security posture.

*UFW status:*
```bash
sudo ufw status verbose
```

*Output:*
```
Status: inactive
```
**Important finding:** UFW firewall was **inactive** by default on Ubuntu Server minimized installation. This means:
- All incoming connections are allowed
- No firewall protection
- SSH is exposed without filtering
- Logging is set to low

This is a security risk that needs to be addressed immediately.

**Enabling UFW and Allowing SSH**

Before enabling the firewall, I needed to allow SSH connections to avoid locking myself out.

*Allowing SSH through firewall:*
```bash
# Allow SSH from anywhere (initial setup)
sudo ufw allow 22/tcp comment 'Allow SSH'

# Enable UFW
sudo ufw enable
```
**Verifying UFW status after enabling:**
```bash
sudo ufw status numbered
```
**Security posture after enabling UFW:**
- ✅ Firewall is now **active**
- ✅ SSH access is **allowed** (port 22)
- ✅ All other incoming connections are **denied** (default policy)
- ✅ Firewall starts automatically on boot

---

### 1.2 Initial Setup and Baseline

With SSH enabled and the firewall configured, I tested remote access from the Kali VM.

**From Kali Linux terminal:**
```bash
# Test SSH connection to Ubuntu Server
ssh ubuntu@10.0.2.8
```
**✅ SSH connection successful!**

Now I could manage the Ubuntu server remotely from Kali Linux, which is more convenient than using the VirtualBox console.

### Why Document Baseline First?

Before making any security changes, I documented the system's initial state. You can't measure improvement if you don't know where you started. This also demonstrates a methodical approach - production environment also requires documenting the current state before modifications.

**Checking running services and network exposure:**
```bash
sudo systemctl list-units --type=service --state=running | tee pre_hardening.txt
sudo ss -tuln | tee pre_network.txt
```
![SSH Connection from Kali](screenshots/03-ssh-connection-success.png)

**Result:**
- *14 loaded units*
- *Port 22 (TCP):* SSH listening on all interfaces (0.0.0.0 and ::)
- *Port 53 (TCP/UDP):* systemd-resolved on localhost only (127.0.0.53)
- *Port 68 (UDP):* DHCP client (getting IP from VirtualBox)

I saved this output to a file so I could compare before/after states later. The service count was low because I chose the minimized installation during setup. Only SSH was exposed to the network; one attack vector from external access.

**Checking SSH configuration and Sensitive files permissions**
I checked the initial sshd configuration, created a back up file before configuration in order to have something to fall back on if it fails. I also checked for file permissions of sensitive files
```bash
sudo grep "^Port\|^PermitRootLogin\|^PasswordAuthentication\|^MaxAuthTries\|ClientAliveInterval\|ClientAliveCountMax" /etc/ssh/sshd_config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
sudo ls -l /etc/passwd /etc/shadow /etc/ssh/sshd_config 
```
![SSH Connection from Kali](screenshots/03-ssh-connection-success.png)

**Initial findings:**
- Port 22: Standard port, heavily targeted by bots
- Root login: Allowed with keys (better than password, but still risky)
- Password authentication: Enabled (brute force attack vector)
- MaxAuthTries: 6 attempts (gives attackers too many tries)

### Baseline Security Posture

Before any hardening:

| Component | Status | Security Level | Notes |
|-----------|--------|----------------|-------|
| Services Running | 14 | Good | Minimal installation, lean system |
| Network Exposure | 1 service (SSH) | Medium | Only SSH externally accessible |
| Firewall | Active (basic) | Basic | Single allow rule for SSH |
| SSH Configuration | Default | Poor | Default port, password auth, 6 tries allowed |
| Root Access | SSH keys only | Medium | Better than password, but direct root access still possible |
| Intrusion Detection | None | Poor | No visibility into attacks |
| Intrusion Prevention | None | Poor | No automated response |
| File Integrity | None | Poor | No monitoring of critical files |
| Password Policy | Default | Poor | Weak password requirements |
| Security Updates | Manual | Poor | No automatic patching |

The system was functional but not hardened. Time to build the security layers.

---

## Phase 2: Intrusion Detection System (Snort)

### Why Start with Detection?

I implemented detection before prevention because I need visibility before I can respond. Deploying prevention first (like Fail2Ban) without detection means you're blocking attacks blind - you know something got banned, but you don't see the full attack pattern or context.

With Snort running first, I could:
- See exactly what attacks looked like at the packet level
- Understand attack patterns and timing
- Tune thresholds based on real traffic
- Validate that prevention systems were responding to actual threats

### Installing Snort

```bash
sudo apt update
sudo apt install snort -y
```
During installation, I set the Interface which Snort should listen on as enp0s3 which is my network interface. Snort will capture all traffic on this interface.

### Configuring and Verifying HOME_NET IP

![SSH Connection from Kali](screenshots/03-ssh-connection-success.png)

```bash
# Check Snort version
snort --version
# Output: Snort 2.9.20

# Configuring and Verifying HOME_NET configuration
sudo nano /etc/snort/snort_config
sudo grep "ipvar HOME_NET" /etc/snort/snort.conf
# Output: ipvar HOME_NET 10.0.2.0/24 ✓
```
This defines my "protected" network. Snort uses this to understand directionality:
- Traffic from 10.0.2.0/24 → external = outbound
- Traffic from external → 10.0.2.0/24 = inbound (potential attack)

**Why this matters:** Many Snort rules are directional. For example, "alert tcp any any -> $HOME_NET 22" means "alert on traffic FROM anywhere TO my network on port 22." Getting HOME_NET right is critical for accurate detection.

```bash
# Test configuration for syntax errors
sudo snort -T -c /etc/snort/snort.conf
```
The validation test loads all rules, initializes preprocessors, and checks for configuration errors. Seeing "Snort successfully validated the configuration!" means everything is syntactically correct and Snort can start.

### Creating Custom Detection Rules

Snort comes with thousands of community rules, but I created a custom rules to showcase an understanding of intrusion detection, rule writing and fine tuning. I focused on four common attack types I planned to test.

```bash
sudo nano /etc/snort/rules/local.rules
```
**My four custom rules:**
```bash
# Rule 1: TCP SYN Scan Detection (nmap and port scanners)
alert tcp any any -> $HOME_NET any (msg:"Possible NMAP scan detected"; flags:S; threshold: type threshold, track by_src, count 10, seconds 5; sid:1000001; rev:1;)

# Rule 2: ICMP Flood Detection (ping floods)
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Flood Detected"; itype:8; threshold: type threshold, track by_src, count 50, seconds 5; sid:1000002; rev:1;)

# Rule 3: SSH Brute Force Detection
alert tcp any any -> $HOME_NET 22 (msg:"Possible SSH Brute Force Attempt"; flags:S; threshold: type threshold, track by_src, count 5, seconds 60; sid:1000003; rev:1;)

# Rule 4: UDP Port Scan Detection
alert udp any any -> $HOME_NET any (msg:"Possible UDP Port Scan Detected"; threshold: type threshold, track by_src, count 10, seconds 5; sid:1000004; rev:1;)
```
![SSH Connection from Kali](screenshots/03-ssh-connection-success.png)

### Understanding Rule Syntax
```bash
alert tcp any any -> $HOME_NET any (msg:"Possible NMAP scan detected"; flags:S; threshold: type threshold, track by_src, count 10, seconds 5; sid:1000001; rev:1;)
```
**Rule components:**

- **`alert`** - Action to take (generate alert, don't just log)
- **`tcp`** - Protocol to monitor
- **`any any`** - From any source IP and any source port
- **`-> $HOME_NET any`** - Directed toward my network (10.0.2.0/24), any destination port
- **`msg:"Possible NMAP scan detected"`** - Human-readable alert message
- **`flags:S`** - Match only TCP packets with SYN flag set
  - SYN is used to initiate connections
  - Port scanners send SYN to many ports rapidly
- **`threshold: type threshold, track by_src, count 10, seconds 5`** - Threshold logic:
  - `type threshold` - Alert only when threshold is met
  - `track by_src` - Track per source IP address
  - `count 10, seconds 5` - Trigger when 10+ matching packets seen in 5 seconds from same source
- **`sid:1000001`** - Signature ID (unique identifier, custom rules use 1000000+)
- **`rev:1`** - Revision number (version 1 of this rule)

**Why the threshold is critical:**

Without the threshold, this rule would trigger on every single TCP SYN packet including normal web browsing (browsers open 6-8 simultaneous connections), SSH sessions, database connections, etc. The system would be flooded with false positives.

With the threshold:
- Normal user: Opens 1-5 connections to a server (no alert)
- Web browser: 6-8 connections (no alert)
- Port scanner: 100-1000 connections in seconds (ALERT!)

### Rule Tuning Process

I actually tested three different threshold variations for the port scan rule to find the optimal setting:

**Baseline (what I chose):**
```bash
count 10, seconds 5
```
![SSH Connection from Kali](screenshots/03-ssh-connection-success.png)

**Sensitive variant (catches more, but potentially noisier):**
```bash
count 5, seconds 10
```
![SSH Connection from Kali](screenshots/03-ssh-connection-success.png)

**Conservative variant (fewer false positives, might miss slow scans):**
```bash
count 20, seconds 5
```
![SSH Connection from Kali](screenshots/03-ssh-connection-success.png)

I tested all three against different scan speeds:

| Rule Version | Normal Traffic | Standard Scan | Slow Scan (-T2) | Fast Scan (-T4) |
|--------------|----------------|---------------|-----------------|-----------------|
| Baseline | No alerts ✓ | Detected | Missed | Detected |
| Sensitive | No alerts ✓ | Detected | Detected ✓ | Detected |
| Conservative | No alerts ✓ | Detected | Missed | Detected |

**My decision:** Stuck with baseline.

**Why:** The sensitive version caught slow scans, which is good, but I'd need to test it with actual production traffic to see if it generates too many alerts. The conservative version was too lenient - missed attacks I wanted to catch. Baseline provided the best balance for this lab environment.

**Production tuning would involve:**
1. Deploy all three variations simultaneously (different SIDs)
2. Run for 2-4 weeks collecting data
3. Analyze false positive rates
4. Measure detection coverage
5. Choose optimal threshold based on real traffic patterns
6. Continuously adjust as traffic patterns change

You can't properly tune IDS rules without understanding your environment's normal behavior.

### Testing Detection

Time to validate the rules actually work. I started Snort in console mode so I could watch alerts in real-time:
```bash
sudo snort -A console -c /etc/snort/snort.conf -i enp0s3
```
Now from Kali, I launched attacks to test each rule:

![SSH Connection from Kali](screenshots/03-ssh-connection-success.png)

**Test 1: TCP Port Scan (Rule 1000001)**
```bash
# From Kali
nmap -sS 10.0.2.8
```

**What nmap does:**
- `-sS` = TCP SYN scan (stealth scan)
- Sends SYN packets to top 1000 most common ports
- Analyzes responses to determine port state

**Analyzing results:**
```bash
# Count NMAP detections
sudo grep "\[1:1000001:" /var/log/snort/alert | wc -l
```
![SSH Connection from Kali](screenshots/03-ssh-connection-success.png)

**Result** Snort detected 200 port scan attempts from nmap. The threshold-based detection successfully identified scanning behavior while avoiding false positives from normal network traffic.*

200 alerts from a single nmap scan. This makes sense - nmap probed 1000 ports, generating well over the threshold of 10 SYNs in 5 seconds. Snort correctly identified this as a port scan.

**Test 2: UDP Port Scan (Rule 1000004)**
```bash
# From Kali
nmap -sU --top-ports 100 10.0.2.8
```

UDP scans are slower than TCP because:
- TCP: Send SYN, get SYN-ACK (open) or RST (closed) - definitive answer
- UDP: Send packet, wait for response or ICMP unreachable - often ambiguous
- UDP scanning requires timeouts for each port

I used `--top-ports 100` to speed it up (only scan 100 most common UDP ports instead of all 65535).

![SSH Connection from Kali](screenshots/03-ssh-connection-success.png)

**Results:** 208 detections (shown in Screenshot 15)

The UDP rule successfully caught the scanning pattern.

**Test 3: SSH Brute Force (Rule 1000003)**

For SSH testing, I simulated rapid connection attempts:
```bash
# From Kali
for i in {1..10}; do ssh -p 22 -o ConnectTimeout=2 wronguser@10.0.2.8 2>/dev/null & done
```

This tries to connect 10 times rapidly with a fake username. All attempts fail, but Snort sees the rapid SYN packets to port 22.

**Checking results:**
```bash
sudo grep "\[1:1000003:" /var/log/snort/alert | wc -l
```
![SSH Connection from Kali](screenshots/03-ssh-connection-success.png)

1 SSH brute force attempt was detected (sid:1000003) and 208 UDP scan attempts detected (sid:1000004). The SSH rule triggered when rapid connection attempts to port 22 exceeded the threshold of 5 attempts in 60 seconds.*

The rule caught the rapid connection pattern. However, there's an important limitation here:

**Rule limitation:** This rule detects rapid TCP SYN packets to port 22, but it can't distinguish between:
- Multiple connections with wrong passwords (attack)
- Multiple connections with correct passwords (unusual but legitimate)

It's detecting the connection pattern, not the authentication failure. That's okay for network-based IDS - Snort operates at the packet level and doesn't see application-layer authentication results.

This is why I need both Snort (network detection) and Fail2Ban (application detection) - they complement each other:
- **Snort:** Sees connection attempts at network level
- **Fail2Ban:** Parses auth.log and sees actual authentication failures

**Test 4: ICMP Flood (Rule 1000002)**
```bash
# From Kali
sudo ping -f 10.0.2.8
```

The `-f` flag means "flood" - send pings as fast as possible with no delay. I let it run for about 5 seconds then hit Ctrl+C.
```
--- 10.0.2.8 ping statistics ---
532 packets transmitted, 532 received, 0% packet loss, time 4998ms
```

That's 106 packets per second - way above my threshold of 50 in 5 seconds. Snort should have caught this easily.

**Checking results:**
```bash
sudo grep "\[1:1000002:" /var/log/snort/alert | wc -l
```
![SSH Connection from Kali](screenshots/03-ssh-connection-success.png)

*Caption: Snort detected 99 ICMP flood attempts. Custom rule (sid:1000002) successfully identified ping flood when threshold of 50 ICMP Echo Requests in 5 seconds was exceeded. Normal pings (1 per second) do not trigger this rule.*

99 detections - the rule triggered multiple times as the flood continued. Perfect.

### What Production Deployment Looks Like

**Lab vs Production differences:**

| Aspect | My Lab | Production Standard |
|--------|--------|---------------------|
| **Rules** | 4 custom rules | 10,000+ rules (ET Open/Pro, Snort VRT, custom) |
| **Rule sources** | Local file only | Subscriptions to threat intelligence feeds |
| **Updates** | Manual | Automated daily updates |
| **Deployment** | Single sensor | Distributed sensors across network segments |
| **Mode** | IDS (alert only) | IPS (inline, can block) |
| **Logging** | Local files | Centralized SIEM (Splunk, ELK) |
| **Monitoring** | Manual review | 24/7 SOC with automated correlation |
| **Tuning** | 3 days testing | 4-6 weeks with production traffic |
| **Performance** | 95%+ packet analysis | 99.9%+ required (can't drop packets) |
| **High availability** | Single instance | Redundant sensors with failover |

**Production implementation would include:**
```bash
# Subscribe to Snort Subscriber Rules (paid) or ET Open (free)
cd /etc/snort/rules
wget https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz
tar -xzvf emerging.rules.tar.gz

# Update snort.conf to include new rule categories
include $RULE_PATH/emerging-exploit.rules
include $RULE_PATH/emerging-malware.rules
include $RULE_PATH/emerging-scan.rules
include $RULE_PATH/emerging-attack_response.rules
# ... 50+ categories

# Deploy as inline IPS (can drop packets, not just alert)
snort -Q --daq afpacket -i eth0:eth1 -c /etc/snort/snort.conf

# Forward all alerts to SIEM
# Configure Filebeat/Logstash to ship logs to Elasticsearch
```

**Why I didn't do this in the lab:**
- **Demonstration:** 4 custom rules effectively demonstrate IDS concepts

**What I learned:** The principles are the same whether you have 4 rules or 10,000. Understanding how to:
- Write effective detection logic
- Tune thresholds
- Analyze false positives
- Validate rule effectiveness

...applies to any IDS deployment.

---
## Phase 3: Core Security Hardening

With detection in place, I could now harden the system knowing I'd see any attacks that occurred during or after the hardening process.

### SSH Hardening

SSH was my primary attack surface - the only service exposed to the network. Hardening SSH would have the biggest security impact.

**Backing up original configuration:**
```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
```

Always back up before modifying critical configs. If I broke something, I could easily revert.

**Editing configuration:**
```bash
sudo nano /etc/ssh/sshd_config
```
**Changes I made:**
```bash
# Change from default port (security through obscurity + practicality)
Port 2222

# Disable direct root login
PermitRootLogin no

# Limit authentication attempts
MaxAuthTries 3

# Disable password authentication (force keys only)
PasswordAuthentication no

# Ensure public key authentication is enabled
PubkeyAuthentication yes

# Session timeout settings
ClientAliveInterval 300
ClientAliveCountMax 3

# Restrict to specific users
AllowUsers ubuntu

# Disable potentially dangerous features
HostbasedAuthentication no
IgnoreRhosts yes
X11Forwarding no
AllowTcpForwarding no

# Reduce login grace time
LoginGraceTime 30
```
![SSH Connection from Kali](screenshots/03-ssh-connection-success.png)

**Why each change matters:**

**Port 2222 (vs default 22):**
- **Problem:** Port 22 is the first thing automated bots attack
- **Solution:** Non-standard port eliminates ~99% of automated bot attacks
- **Reality check:** Skilled attackers can still find it with nmap
- **Value:** Reduces noise and automated attack attempts dramatically

This is "security through obscurity" but it's practical obscurity.

**PermitRootLogin no:**
- **Problem:** Direct root login means attacker with root password has full system access immediately
- **Solution:** Even if attacker gets root password, they can't login directly
- **How it works:** Users must login as regular user, then use `sudo` to get root privileges
- **Benefits:**
  - Forces two-factor authentication (user password + sudo password)
  - Logs all privilege escalation in sudo logs
  - Limits blast radius of compromised credentials
  - Account compromise ≠ automatic root access

**MaxAuthTries 3 (vs 6):**
- **Problem:** 6 attempts per connection gives attackers too many guesses
- **Solution:** Limit to 3 attempts per connection
- **Math:**
  - Old: 6 attempts/connection × unlimited connections = unlimited attempts
  - New: 3 attempts/connection × limited by rate limiting/Fail2Ban = much harder to brute force
- **Impact:** Slows brute force attacks significantly without affecting legitimate users (most people don't mistype their password 3+ times)

**PasswordAuthentication no:**
- **Problem:** Passwords can be guessed/brute forced given enough time
- **Solution:** SSH keys use 2048+ bit encryption - practically impossible to brute force
- **Security difference:**
  - Password: Can try millions of combinations
  - SSH key: Would take thousands of years to brute force
- **Eliminates:** Entire class of password-based attacks
