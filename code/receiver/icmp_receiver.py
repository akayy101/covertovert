import scapy

# Python
from scapy.all import ICMP, IP, sniff

# Implement your ICMP receiver here


def packet_callback(packet):
    # Check if the packet is an ICMP request with TTL value 1
    if packet.haslayer(ICMP) and packet[IP].ttl == 1:
        packet.show()

#waiting for packets
if __name__ == "__main__":
    sniff(filter="icmp", prn=packet_callback)
