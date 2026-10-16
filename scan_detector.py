from scapy.all import sniff, TCP, IP
from collections import defaultdict
import time
import csv
import os

syn_tracker = defaultdict(set)
syn_timestamps = defaultdict(list)   # tracks every SYN's arrival time per IP
first_seen = {}
last_alert = {}

WINDOW_SECONDS = 10
PORT_THRESHOLD = 6
ALERT_COOLDOWN = 15
LOG_FILE = "netshield_alerts.csv"

TRUSTED_IPS = []

IGNORE_DEST_PORTS = {
    9200,
}

def is_trusted(ip):
    return ip in TRUSTED_IPS

def log_alert(src, ports, timestamps):
    file_exists = os.path.isfile(LOG_FILE)
    port_count = len(ports)

    if len(timestamps) >= 2:
        span = timestamps[-1] - timestamps[0]
        avg_gap = span / (len(timestamps) - 1)
    else:
        avg_gap = 999

    if avg_gap < 0.5:
        risk = "HIGH"
    elif avg_gap < 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "source_ip", "alert_type", "unique_ports", "port_count", "avg_gap_sec", "risk"])
        writer.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S"),
            src, "Port Scan",
            ";".join(str(p) for p in sorted(ports)),
            port_count, round(avg_gap, 3), risk
        ])
    return risk, avg_gap

def handle_packet(pkt):
    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return
    if pkt[TCP].flags != "S":
        return

    src = pkt[IP].src
    dport = pkt[TCP].dport

    if is_trusted(src):
        return
    if dport in IGNORE_DEST_PORTS:
        return

    now = time.time()

    if src in first_seen and (now - first_seen[src]) > WINDOW_SECONDS:
        syn_tracker[src].clear()
        syn_timestamps[src].clear()
        first_seen[src] = now
    elif src not in first_seen:
        first_seen[src] = now

    syn_tracker[src].add(dport)
    syn_timestamps[src].append(now)
    print(f"SYN  {src} -> port {dport}   (unique ports so far: {len(syn_tracker[src])})")

    on_cooldown = src in last_alert and (now - last_alert[src]) < ALERT_COOLDOWN

    if len(syn_tracker[src]) >= PORT_THRESHOLD and not on_cooldown:
        risk, avg_gap = log_alert(src, syn_tracker[src], syn_timestamps[src])
        print("=" * 50)
        print("  ALERT: Possible Port Scan")
        print(f"  Source IP   : {src}")
        print(f"  Unique ports: {sorted(syn_tracker[src])}")
        print(f"  Avg gap     : {round(avg_gap, 3)}s between SYNs")
        print(f"  Risk        : {risk}")
        print("=" * 50)
        last_alert[src] = now
        syn_tracker[src].clear()
        syn_timestamps[src].clear()
        first_seen[src] = now

print("Sniffing for port scans... (Ctrl+C to stop)")
sniff(filter="tcp", prn=handle_packet, store=False, iface="lo")
