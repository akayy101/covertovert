import scapy

# Python
from scapy.all import ICMP, IP, sniff

# Implement your ICMP receiver here


def packet_callback(packet):
    # Check if the packet is an ICMP request with TTL value 1
    if (
        IP in packet
        and ICMP in packet
        and packet[IP].ttl == 1
        and packet[ICMP].type == 8
    ):
        print("Received ICMP request packet:")
        print(packet.show())


def capture_icmp_requests():
    # Sniff for ICMP packets
    sniff(filter="icmp", prn=packet_callback)


if __name__ == "__main__":
    print("Listening for ICMP requests...")
    capture_icmp_requests()
