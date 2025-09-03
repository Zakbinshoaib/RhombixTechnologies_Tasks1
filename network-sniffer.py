from scapy.all import sniff, TCP, IP, ARP, Ether, DNS, UDP, ICMP


def packet_callback(packet):

    # TCP Packet
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print(f"TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}")

    # IP Packet
    elif packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")

    # ARP Packet    
    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        print(f"ARP Packet: {arp_layer.psrc} -> {arp_layer.pdst}")

    # Ethernet Packet
    elif packet.haslayer(Ether):
        ether_layer = packet[Ether]
        print(f"Ethernet Packet: {ether_layer.src} -> {ether_layer.dst}")

    # DNS Packet
    elif packet.haslayer(DNS):
        dns_layer = packet[DNS]
        print(f"DNS Packet: {dns_layer.qd.qname}")

    # UDP Packet
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print(f"UDP Packet: {udp_layer.sport} -> {udp_layer.dport}")

    # ICMP Packet
    elif packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        print(f"ICMP Packet: {icmp_layer.type}")



sniff(prn=packet_callback, store=False)


    
    
