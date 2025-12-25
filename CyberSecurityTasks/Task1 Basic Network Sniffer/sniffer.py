from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_handler(packet):
    if IP in packet:
        print("\n==============================")

        print("Source IP      :", packet[IP].src)
        print("Destination IP :", packet[IP].dst)

        if TCP in packet:
            print("Protocol       : TCP")
            print("Source Port    :", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif UDP in packet:
            print("Protocol       : UDP")
            print("Source Port    :", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        elif ICMP in packet:
            print("Protocol       : ICMP")

        if packet.haslayer(TCP) and packet[TCP].payload:
            print("Payload        :", bytes(packet[TCP].payload))

print(" Starting Network Sniffer...")
print("Press CTRL + C to stop\n")

sniff(prn=packet_handler, store=False)
