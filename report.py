import csv
import os
from collections import Counter

SCAN_LOG = "netshield_alerts.csv"
DNS_LOG = "netshield_dns_alerts.csv"

def load_scan_alerts():
    alerts = []
    if not os.path.isfile(SCAN_LOG):
        return alerts
    with open(SCAN_LOG, "r") as f:
        for row in csv.DictReader(f):
            alerts.append({
                "timestamp": row["timestamp"],
                "source_ip": row["source_ip"],
                "alert_type": row["alert_type"],
                "risk": row["risk"],
                "evidence": f"Ports: {row['unique_ports'].replace(';', ', ')} "
                            f"({row['port_count']} ports, avg gap {row['avg_gap_sec']}s)",
                "reason": "Multiple ports contacted from the same source in a short time.",
                "action": "Investigate source host and review related network traffic.",
            })
    return alerts

def load_dns_alerts():
    alerts = []
    if not os.path.isfile(DNS_LOG):
        return alerts
    with open(DNS_LOG, "r") as f:
        for row in csv.DictReader(f):
            if row["alert_type"] == "Domain Burst":
                reason = "Many unique domains queried quickly, which can indicate beaconing."
                action = "Check which process on the host is making these lookups."
            else:
                reason = "Unusually long domain name, which can indicate DNS tunneling."
                action = "Inspect the domain and check whether it looks random or encoded."
            alerts.append({
                "timestamp": row["timestamp"],
                "source_ip": row["source_ip"],
                "alert_type": row["alert_type"],
                "risk": row["risk"],
                "evidence": row["detail"],
                "reason": reason,
                "action": action,
            })
    return alerts

def generate_report():
    alerts = load_scan_alerts() + load_dns_alerts()
    if not alerts:
        print("No alerts logged yet.")
        return

    alerts.sort(key=lambda a: a["timestamp"])
    by_type = Counter(a["alert_type"] for a in alerts)
    by_risk = Counter(a["risk"] for a in alerts)

    print("\n" + "=" * 46)
    print("     NETSHIELD SUMMARY")
    print("=" * 46)
    print(f"Total alerts : {len(alerts)}")
    print("By type      : " + ", ".join(f"{k} ({v})" for k, v in by_type.items()))
    print("By risk      : " + ", ".join(f"{k} ({v})" for k, v in by_risk.items()))
    print()

    for a in alerts:
        print("=" * 46)
        print(f"  [{a['risk']}] {a['alert_type']}")
        print("=" * 46)
        print(f"Timestamp : {a['timestamp']}")
        print(f"Source IP : {a['source_ip']}")
        print(f"Evidence  : {a['evidence']}")
        print(f"Reason    : {a['reason']}")
        print(f"Action    : {a['action']}")
        print()

if __name__ == "__main__":
    generate_report()
