# PRODIGY_CS_05
Packet Sniffer using Scapy: A Python script utilizing Scapy to capture and analyze network packets. It identifies IP, TCP, and UDP packets, extracting and decoding payloads when available. The script prints source/destination IPs, protocol, and decoded payloads for TCP/UDP traffic. Ideal for network analysis and monitoring
markdown
Copy code
# Network Packet Sniffer with Scapy

## Overview

This Python script uses the Scapy library to capture and analyze network packets. It provides basic information about IP, TCP, and UDP packets by extracting and printing details such as source and destination IP addresses, protocol type, and decoded payloads. This tool is useful for network traffic analysis and monitoring.

## Features

- **IP Layer Extraction**: Identifies packets with an IP layer and extracts source and destination IP addresses.
- **Protocol Detection**: Determines whether the packet is using TCP or UDP.
- **Payload Decoding**: Attempts to decode and display the payload of TCP and UDP packets in UTF-8 format.

## Prerequisites

To run this script, you need to have Python and Scapy installed. You can install Scapy using pip:

```bash
pip install scapy
Usage

Clone this repository to your local machine:
bash
Copy code
git clone https://github.com/your-username/your-repository.git
Navigate to the project directory:
bash
Copy code
cd your-repository
Run the script:
bash
Copy code
python your_script_name.py
Replace your_script_name.py with the actual name of your script file.
Code Explanation

packet_callback(packet): This function processes each packet captured. It checks for an IP layer and extracts relevant information. If the packet is TCP or UDP, it attempts to decode and print the payload.
start_sniffing(): This function starts the packet sniffing process, calling packet_callback for each packet.
