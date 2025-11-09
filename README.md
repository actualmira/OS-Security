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

1. **Baseline documentation** - Captured the initial state before making changes
2. **Network intrusion detection** - Custom Snort rules to detect attacks
3. **System hardening** - SSH, firewall, services, file permissions
4. **Automated prevention** - Fail2Ban integrated with firewall to automatically block attackers
5. **Integration testing** - Simulated real attacks to validate everything works together

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
