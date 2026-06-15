import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        proto_name = "Other"
        if protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        elif protocol == 1:
            proto_name = "ICMP"

        print(f"\n[*] Packet: {ip_src} -> {ip_dst} | Proto: {proto_name}")

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload_data = bytes(packet[IP].payload)
            if payload_data:
                ascii_text = ''.join([chr(b) if 32 <= b < 127 else '.' for b in payload_data])
                print(f"    Data: {ascii_text[:60]}")

def main():
    print("--- Network Sniffer Initialized ---")
    try:
        sniff(prn=process_packet, store=False)
    except PermissionError:
        print("Error: Run this script with sudo / Administrator privileges.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopping sniffer.")
        sys.exit(0)

if __name__ == "__main__":
    main()
