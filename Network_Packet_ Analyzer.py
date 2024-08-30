import scapy.all as scapy

def packet_callback(packet):
    # Check if the packet contains an IP layer
    if packet.haslayer(scapy.IP):
        # Extract source and destination IP addresses and the protocol used
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        # Print basic packet information
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        # Check if the packet contains a TCP layer
        if packet.haslayer(scapy.TCP):
            # Attempt to extract and decode the payload
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                print(f"TCP Payload: {decoded_payload}")
            except (IndexError, UnicodeDecodeError):
                print("Unable to decode TCP payload.")

        # Check if the packet contains a UDP layer
        elif packet.haslayer(scapy.UDP):
            # Attempt to extract and decode the payload
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                print(f"UDP Payload: {decoded_payload}")
            except (IndexError, UnicodeDecodeError):
                print("Unable to decode UDP payload.")

def start_sniffing():
    # Start sniffing packets, calling packet_callback for each packet
    scapy.sniff(store=False, prn=packet_callback)

# Start the packet sniffing process
start_sniffing()
