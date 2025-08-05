from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = "OTHER"

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"

        print(f"[+] {ip_layer.src} --> {ip_layer.dst} | Protocol: {protocol}")
        
        if packet.haslayer(Raw):
            print(f"    Payload: {packet[Raw].load[:50]}")
        
        print("-" * 60)

print("🌐 Starting Packet Sniffer... Press CTRL+C to stop.\n")
sniff(prn=packet_callback, store=False, count=20)
