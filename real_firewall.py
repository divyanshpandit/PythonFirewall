from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, ICMP

BLOCKED_IPS = ['192.168.1.10']
BLOCKED_PORTS = [80, 443]
BLOCKED_PROTOCOLS = ['ICMP']

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    ip_src = scapy_packet.src
    ip_dst = scapy_packet.dst

    if ip_src in BLOCKED_IPS or ip_dst in BLOCKED_IPS:
        print(f"[Blocked IP] {ip_src} -> {ip_dst}")
        packet.drop()
        return

    if ICMP in scapy_packet and 'ICMP' in BLOCKED_PROTOCOLS:
        print(f"[Blocked Protocol ICMP] {ip_src} -> {ip_dst}")
        packet.drop()
        return

    if TCP in scapy_packet or UDP in scapy_packet:
        sport = scapy_packet.sport
        dport = scapy_packet.dport
        if sport in BLOCKED_PORTS or dport in BLOCKED_PORTS:
            proto = "TCP" if TCP in scapy_packet else "UDP"
            print(f"[Blocked {proto} Port] {ip_src}:{sport} -> {ip_dst}:{dport}")
            packet.drop()
            return

    print(f"[Allowed] {ip_src} -> {ip_dst}")
    packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, process_packet)

try:
    print("Real Firewall running... Press CTRL+C to stop.")
    nfqueue.run()
except KeyboardInterrupt:
    print("Stopping Firewall...")

nfqueue.unbind()
