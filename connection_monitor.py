# netshield_phase1.py
import psutil
from socket import SOCK_STREAM, SOCK_DGRAM

PROTO = {SOCK_STREAM: "TCP", SOCK_DGRAM: "UDP"}

def show_connections():
    print(f"{'Source IP':<18}{'Destination IP':<18}{'Port':<8}{'Protocol':<10}{'State'}")
    print("-" * 68)
    for c in psutil.net_connections(kind="inet"):
        if not c.raddr:          # skip listening sockets with no remote end
            continue
        print(f"{c.laddr.ip:<18}{c.raddr.ip:<18}{c.raddr.port:<8}"
              f"{PROTO.get(c.type, '?'):<10}{c.status}")

if __name__ == "__main__":
    show_connections()
