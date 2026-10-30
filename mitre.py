MITRE = {
    "Port Scan": {
        "tactic": "Discovery",
        "technique": "T1046",
        "name": "Network Service Discovery",
    },
    "Domain Burst": {
        "tactic": "Command and Control",
        "technique": "T1071.004",
        "name": "Application Layer Protocol: DNS",
    },
    "Long Domain Name": {
        "tactic": "Command and Control",
        "technique": "T1572",
        "name": "Protocol Tunneling",
    },
}

def lookup(alert_type):
    return MITRE.get(alert_type, {"tactic": "Unmapped", "technique": "-", "name": "-"})
