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
3. **Network intrusion detection** - Custom Snort rules to detect attacks
4. **System hardening** - SSH, firewall, services, file permissions
5. **Automated prevention** - Fail2Ban integrated with firewall to automatically block attackers
6. **Integration testing** - Simulated real attacks to validate everything works together

The goal was to build a defense-in-depth system where multiple security controls work together, so even if one layer fails, another would catch the threat.

### Skills I Demonstrated

- Linux system administration (services, networking, permissions)
- SSH hardening and secure remote access
- Intrusion detection system configuration (Snort)
- Intrusion prevention implementation (Fail2Ban)
- Firewall management (UFW)
- Log analysis and event correlation
- Attack simulation and security validation
- Security automation and orchestration

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

### 1.2 Testing SSH Access from Kali Linux

With SSH enabled and the firewall configured, I tested remote access from the Kali VM.

**From Kali Linux terminal:**
```bash
# Test SSH connection to Ubuntu Server
ssh ubuntu@10.0.2.8
```
**✅ SSH connection successful!**

Now I could manage the Ubuntu server remotely from Kali Linux, which is more convenient than using the VirtualBox console.

![SSH Connection from Kali](screenshots/03-ssh-connection-success.png)
