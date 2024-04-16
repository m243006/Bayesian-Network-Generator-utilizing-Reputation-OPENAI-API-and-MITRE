from scapy.all import rdpcap
import os
import sys
import requests
import json
from scapy.all import rdpcap
import ipaddress

# IPQS_API_KEY = 'J3taPQ8PTwQvJG6w8GtH9gMdsw7kNBKP'
IPQS_API_KEY = input("Input API Key:")
IPQS_API_URL = 'https://ipqualityscore.com/api/json/ip'
UNIQUE_IP_FILE = 'unique_ips.txt'  # File to store unique IPs

def read_unique_ips(file_path):
    if not os.path.exists(file_path):
        return set()  # Return an empty set if the file doesn't exist
    with open(file_path, 'r') as file:
        return set(file.read().splitlines())

def add_ip_to_file(ip_address, file_path):
    with open(file_path, 'a') as file:
        file.write(ip_address + '\n')

def get_ip_reputation(ip_address, unique_ips):
    # Check if the IP is already processed
    if ip_address in unique_ips:
        return

    params = {'key': IPQS_API_KEY, 'ip': ip_address}
    response = requests.get(IPQS_API_URL, params=params)
    result = response.json()

    if 'fraud_score' in result:
        print(f"\nIP Address: {ip_address}")
        print(f"Reputation: {result['fraud_score']} (Fraud Score)")
        
        # Define your criteria for a malicious IP here, for example:
        if result['fraud_score'] > 50:  # Example criterion
            add_ip_to_file(ip_address, UNIQUE_IP_FILE)
            unique_ips.add(ip_address)  # Add the IP address to the set as well

def print_ips_and_reputation_from_pcap(pcap_file, unique_ips):
    packets = rdpcap(pcap_file)
    for packet in packets:
        if 'IP' in packet:
            src_ip = packet['IP'].src
            # if not ipaddress.ip_address(src_ip).is_private:
            get_ip_reputation(src_ip, unique_ips)
            # else:
            print(src_ip)

def process_all_pcaps_in_directory(directory, unique_ips):
    for filename in os.listdir(directory):
        if filename.endswith(".pcapng"):
            pcap_file_path = os.path.join(directory, filename)
            print(f"\nProcessing {pcap_file_path}:")
            print_ips_and_reputation_from_pcap(pcap_file_path, unique_ips)

if __name__ == "__main__":
    unique_ips = read_unique_ips(UNIQUE_IP_FILE)
    if len(sys.argv) > 1:
        pcap_file_path = sys.argv[1]
        print(f"\nProcessing {pcap_file_path}:")
        print_ips_and_reputation_from_pcap(pcap_file_path, unique_ips)
    else:
        pcap_file_path = "sample.pcapng"
        print(f"\nProcessing {pcap_file_path}:")
        print_ips_and_reputation_from_pcap(pcap_file_path, unique_ips)
