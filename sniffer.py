from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] Packet Captured:")
        print(f"    Source IP      : {ip_layer.src}")
        print(f"    Destination IP : {ip_layer.dst}")
        print(f"    Protocol       : {ip_layer.proto}", end='')

        if packet.haslayer(TCP):
            print(" (TCP)")
            print(f"    Source Port    : {packet[TCP].sport}")
            print(f"    Dest Port      : {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(" (UDP)")
            print(f"    Source Port    : {packet[UDP].sport}")
            print(f"    Dest Port      : {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print(" (ICMP)")

        payload = bytes(packet[IP].payload)
        print(f"    Payload        : {payload[:50]}{'...' if len(payload) > 50 else ''}")

print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
