from scapy.all import sniff, DNS, DNSQR, IP
from collections import defaultdict
import time
import csv
import os

queried_domains = defaultdict(set)
first_seen = {}
last_alert = {}
alerted_domains = {}          # domain -> time of last long-domain alert

WINDOW_SECONDS = 15
DOMAIN_THRESHOLD = 8
LONG_DOMAIN_LENGTH = 40
ALERT_COOLDOWN = 20
LONG_ALERT_COOLDOWN = 60
LOG_FILE = "netshield_dns_alerts.csv"

TRUSTED_DOMAINS = [
    "mozilla.com",
    "mozilla.net",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "microsoft.com",
    "windowsupdate.com",
]

def is_trusted(domain):
    return any(domain.endswith(t) for t in TRUSTED_DOMAINS)

def log_alert(src, alert_type, detail, risk):
    file_exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "source_ip", "alert_type", "detail", "risk"])
        writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), src, alert_type, detail, risk])

def handle_packet(pkt):
    if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.haslayer(IP)):
        return
    if pkt[DNS].qr != 0:
        return

    src = pkt[IP].src
    domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
    now = time.time()

    print(f"DNS  {src} -> {domain}")

    # Check 1: suspiciously long domain name (once per domain per minute)
    if len(domain) >= LONG_DOMAIN_LENGTH and not is_trusted(domain):
        last = alerted_domains.get(domain)
        if last is None or (now - last) > LONG_ALERT_COOLDOWN:
            alerted_domains[domain] = now
            print(f"  ⚠ Long domain name ({len(domain)} chars)")
            log_alert(src, "Long Domain Name", f"{domain} ({len(domain)} chars)", "MEDIUM")

    # Check 2: burst of unique domains from one source
    if src in first_seen and (now - first_seen[src]) > WINDOW_SECONDS:
        queried_domains[src].clear()
        first_seen[src] = now
    elif src not in first_seen:
        first_seen[src] = now

    queried_domains[src].add(domain)

    on_cooldown = src in last_alert and (now - last_alert[src]) < ALERT_COOLDOWN

    if len(queried_domains[src]) >= DOMAIN_THRESHOLD and not on_cooldown:
        print("=" * 50)
        print("  ALERT: Possible DNS Beaconing / Domain Burst")
        print(f"  Source IP      : {src}")
        print(f"  Unique domains : {len(queried_domains[src])}")
        print(f"  Within         : {WINDOW_SECONDS} seconds")
        print("=" * 50)
        log_alert(src, "Domain Burst", f"{len(queried_domains[src])} unique domains", "MEDIUM")
        last_alert[src] = now
        queried_domains[src].clear()
        first_seen[src] = now

print("Sniffing DNS traffic for anomalies... (Ctrl+C to stop)")
sniff(filter="udp port 53", prn=handle_packet, store=False, iface="eth0")
