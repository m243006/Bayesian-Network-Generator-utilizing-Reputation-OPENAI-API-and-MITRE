#just more aditional info
import dpkt
import datetime
from dpkt.utils import mac_to_str, inet_to_str

def mac_addr(address):
    return ':'.join('%02x' % b for b in address)

def hexdump(data, width=16):
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        print(' '.join(f'{b:02X}' for b in chunk))

def analyze_packet(ts, packet, unique_ips):
    output = []

    eth = dpkt.ethernet.Ethernet(packet)

    # Make sure the Ethernet frame contains an IP packet
    if not isinstance(eth.data, dpkt.ip.IP) or len(packet) < 61:
        return ""

    # Print timestamp in UTC
    output.append('Timestamp: ' + str(datetime.datetime.utcfromtimestamp(ts)))
    ip = eth.data


    # Check if source or destination IP is in the list of unique IPs
    if (dpkt.utils.inet_to_str(ip.src) in unique_ips or dpkt.utils.inet_to_str(ip.dst) in unique_ips):
        # Print common information
        output.append(f"Packet Length: {len(packet)} bytes")

        # Ethernet frame information
        output.append("\nEthernet Frame:")
        output.append(f"Source MAC: {mac_addr(eth.src)}")
        output.append(f"Destination MAC: {mac_addr(eth.dst)}")
        output.append(f"Ethernet Type: {eth.type}")

        # IP layer information
        output.append("\nIP:")
        output.append(f"Source IP: {dpkt.utils.inet_to_str(ip.src)}")
        output.append(f"Destination IP: {dpkt.utils.inet_to_str(ip.dst)}")
        output.append(f"IP Protocol: {ip.p}")
        output.append(f"TTL: {ip.ttl}")
        output.append(f"DF (Don't Fragment): {ip.df}")
        output.append(f"MF (More Fragments): {ip.mf}")
        output.append(f"Fragment Offset: {ip.offset}")
#        output.append('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' %(inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, ip.df, ip.mf, ip.offset))

        # TCP layer information
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            output.append("\nTCP:")
            output.append(f"Source Port: {tcp.sport}")
            output.append(f"Destination Port: {tcp.dport}")

            # Decode TCP flags
            flags_str = []
            if tcp.flags & dpkt.tcp.TH_FIN:
                flags_str.append('FIN')
            if tcp.flags & dpkt.tcp.TH_SYN:
                flags_str.append('SYN')
            if tcp.flags & dpkt.tcp.TH_RST:
                flags_str.append('RST')
            if tcp.flags & dpkt.tcp.TH_PUSH:
                flags_str.append('PSH')
            if tcp.flags & dpkt.tcp.TH_ACK:
                flags_str.append('ACK')
            if tcp.flags & dpkt.tcp.TH_URG:
                flags_str.append('URG')
            if tcp.flags & dpkt.tcp.TH_ECE:
                flags_str.append('ECE')
            if tcp.flags & dpkt.tcp.TH_CWR:
                flags_str.append('CWR')

            output.append(f"TCP Flags: {', '.join(flags_str)}")

            # Payload analysis for TCP packets
            if len(tcp.data) > 0:
                output.append("\nTCP Payload:")
                try:
                    decoded_payload = tcp.data.decode('utf-8')
                    output.append(f"Decoded Payload: {decoded_payload}")
                except UnicodeDecodeError:
                    output.append("Unable to decode payload as UTF-8")
                #hexdump(tcp.data)
                #check if it works better with the hex dump 
            else:
                output.append("No TCP data")

        # UDP layer information
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            output.append("\nUDP:")
            output.append(f"Source Port: {udp.sport}")
            output.append(f"Destination Port: {udp.dport}")

            # Payload analysis for UDP packets
            if len(udp.data) > 0:
                output.append("\nUDP Payload:")
                try:
                    decoded_payload = udp.data.decode('utf-8')
                    output.append(f"Decoded Payload: {decoded_payload}")
                except UnicodeDecodeError:
                    output.append("Unable to decode payload as UTF-8")
                #hexdump(udp.data)
                #check if it works better with the hex dump 
            else:
                output.append("No UDP data")

        output.append("\n")
    return ' '.join(output)

# Replace 'your_pcap_file.pcapng' and 'unique_ips.txt' with the actual file paths
def print_packet_info_for_unique_ips(pcap_file, unique_ips_file):
    formatted_packets = []
    # Read unique IPs from file
    with open(unique_ips_file, 'r') as unique_ips_file:
        unique_ips = set(line.strip() for line in unique_ips_file)

    with open(pcap_file, 'rb') as f:
        try:
            pcap = dpkt.pcapng.Reader(f)
        except dpkt.dpkt.NeedData:
            print("Error: Invalid pcapng file")
            return

        for ts, pkt in pcap:
            formatted_description = analyze_packet(ts, pkt, unique_ips)
            #formatted_description = format_packet_for_classification(ts, pkt , unique_ips)
            if formatted_description:
                formatted_packets.append(formatted_description)
    return formatted_packets

# Replace 'your_pcap_file.pcapng' and 'unique_ips.txt' with the actual file paths
#print_packet_info_for_unique_ips('Scan-1.pcapng', 'unique_ips.txt')



def format_packet_for_classification(ts, packet, unique_ips):
    """
    Formats the packet data into a descriptive text format for classification.
    """
    output = []
    eth = dpkt.ethernet.Ethernet(packet)

    # Only process IP packets
    if not isinstance(eth.data, dpkt.ip.IP):
        return ""

    ip = eth.data
    src_ip = dpkt.utils.inet_to_str(ip.src)
    dst_ip = dpkt.utils.inet_to_str(ip.dst)

    # Basic packet details
    output.append(f"Timestamp: {datetime.datetime.utcfromtimestamp(ts)}")
    output.append(f"Packet Length: {len(packet)} bytes")
    output.append(f"Source IP: {src_ip}")
    output.append(f"Destination IP: {dst_ip}")

    # Additional details can be added here based on classification needs

    return ' '.join(output)



