from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        else:
            protocol = str(proto)

        print(f"[+] {src_ip} -> {dst_ip} | Protocol: {protocol}")

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            try:
                payload = bytes(packet[TCP].payload)
                print(f"    Payload: {payload[:50]}")
            except:
                pass
        print()

print("Starting packet sniffer... Press Ctrl+C to stop.\n")
sniff(filter="ip", prn=process_packet, store=0)

