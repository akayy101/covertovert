from scapy.all import ICMP, IP, send


def send_icmp_request():
    # Create an IP packet with destination to 'receiver' container and TTL set to 1
    ip_packet = IP(dst="receiver", ttl=1)
    icmp_packet = ICMP()
    packet = ip_packet / icmp_packet
    # Send the packet
    send(packet)


if __name__ == "__main__":
    send_icmp_request()
