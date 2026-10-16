# NetShield – Network Threat Detection Lab

A Python tool that watches network traffic, detects suspicious behavior,
and produces SOC-style alert reports. Built in a Kali Linux lab to learn how
attacks look from a defender's point of view.

## What it detects
- **Port scans**: one source touching many unique ports in a short window
- **DNS burst / beaconing**: many unique domains queried quickly
- **Long DNS names**: possible DNS tunneling

## How it works
Traffic → Scapy sniffer → detection rules → CSV logs → combined SOC report

## Features
- Time-windowed tracking per source IP
- Alert cooldowns to avoid duplicate alerts
- Speed-based risk scoring (HIGH / MEDIUM / LOW)
- Trusted-domain allowlist to reduce false positives

## Lessons learned
- My first long-domain rule flagged normal Firefox traffic (a false positive).
  I fixed it with an allowlist instead of just raising the threshold.
- Duplicate alerts appeared because each DNS lookup sends A and AAAA queries.
  I fixed it with a per-domain cooldown.
- Nmap's `--max-rate` still sends its first few probes close together, so I
  kept an aggressive HIGH threshold on purpose: missing a fast scan is worse
  than one extra alert.

## Usage
```bash
pip install -r requirements.txt
sudo venv/bin/python scan_detector.py
sudo venv/bin/python dns_detector.py
python3 report.py
```

## Ethical note
Tested only against my own lab machines. Do not scan or monitor networks
you don't own or have permission to test.
