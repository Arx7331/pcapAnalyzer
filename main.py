import pyshark
from collections import Counter
import requests
import socket
from datetime import datetime

common_services = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP",
    123: "NTP",
    25565: "Minecraft"
}

def get_local_ip():
    return socket.gethostbyname(socket.gethostname())

def get_asn(ip):
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json')
        data = response.json()
        return data.get('org', 'Unknown')
    except Exception as e:
        print(f"Error fetching ASN for IP {ip}: {e}")
        return "Unknown"

def tcp_flags_to_str(flags_hex):
    flags_str = []
    if int(flags_hex, 16) & 0x02:
        flags_str.append("SYN")
    if int(flags_hex, 16) & 0x04:
        flags_str.append("RST")
    if int(flags_hex, 16) & 0x08:
        flags_str.append("PSH")
    if int(flags_hex, 16) & 0x10:
        flags_str.append("ACK")
    if int(flags_hex, 16) & 0x20:
        flags_str.append("URG")
    if int(flags_hex, 16) & 0x40:
        flags_str.append("ECE")
    if int(flags_hex, 16) & 0x80:
        flags_str.append("CWR")
    return ",".join(flags_str)

def analyze_pcap(pcap_file, exclude_ips, save_to_file=False):
    cap = pyshark.FileCapture(pcap_file)

    ip_counter = Counter()
    protocol_counter = Counter()

    dport_counter = Counter()
    sport_counter = Counter()

    total_traffic_bytes = 0 

    local_ip = get_local_ip()

    exclude_ips = set(exclude_ips.split(','))

    for packet in cap:
        try:
            src_ip = packet.ip.src
            if src_ip != local_ip and src_ip not in exclude_ips:
                ip_counter.update([src_ip])
                if packet.highest_layer == 'ICMP':
                    protocol_counter.update(['ICMP'])
                else:
                    protocol_counter.update([packet.transport_layer])
                if hasattr(packet, 'udp'):
                    dport_counter.update([packet.udp.dstport])
                    sport_counter.update([packet.udp.srcport])
                elif hasattr(packet, 'tcp'):
                    dport_counter.update([packet.tcp.dstport])
                    sport_counter.update([packet.tcp.srcport])
                total_traffic_bytes += int(packet.length)
        except AttributeError:
            pass

    total_packets = sum(protocol_counter.values())
    unique_ips = len(ip_counter)

    most_common_ip, most_common_ip_count = ip_counter.most_common(1)[0]

    most_common_asn = get_asn(most_common_ip)
    print(f"Unique IPs: {unique_ips}")
    print(f"Most common source IP: {most_common_ip} (appeared {most_common_ip_count} times)")
    print(f"Most common ASN: {most_common_asn}")
    print("Attack Protocols:")
    for protocol, count in protocol_counter.items():
        percentage = (count / total_packets) * 100
        print(f"[{protocol} {percentage:.2f}%]")

    total_traffic_mb = total_traffic_bytes / (1024 * 1024)
    print(f"Total Traffic Volume: {total_traffic_mb:.2f} MB")

    if dport_counter:
        most_common_dport, dport_count = dport_counter.most_common(1)[0]
        service_name = common_services.get(int(most_common_dport), "Unknown")
        print(f"Most common destination port: {most_common_dport}/{service_name} (appeared {dport_count} times)")

    if sport_counter:
        most_common_sport, sport_count = sport_counter.most_common(1)[0]
        service_name = common_services.get(int(most_common_sport), "Unknown")
        print(f"Most common source port: {most_common_sport}/{service_name} (appeared {sport_count} times)")

    if save_to_file:
        now = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        file_name = f"{now}_{pcap_file}.txt"
        with open(file_name, "w") as f:
            f.write(f"Unique IPs: {unique_ips}\n")
            f.write(f"Most common source IP: {most_common_ip} (appeared {most_common_ip_count} times)\n")
            f.write(f"Most common ASN: {most_common_asn}\n")
            f.write("Attack Protocols:\n")
            for protocol, count in protocol_counter.items():
                percentage = (count / total_packets) * 100
                f.write(f"[{protocol} {percentage:.2f}%]\n")

            f.write(f"Total Traffic Volume: {total_traffic_mb:.2f} MB\n")

            if dport_counter:
                most_common_dport, dport_count = dport_counter.most_common(1)[0]
                service_name = common_services.get(int(most_common_dport), "Unknown")
                f.write(f"Most common destination port: {most_common_dport}/{service_name} (appeared {dport_count} times)\n")

            if sport_counter:
                most_common_sport, sport_count = sport_counter.most_common(1)[0]
                service_name = common_services.get(int(most_common_sport), "Unknown")
                f.write(f"Most common source port: {most_common_sport}/{service_name} (appeared {sport_count} times)\n")

if __name__ == "__main__":
    pcap_file = input("Enter the path to the pcap file: ")
    exclude_ips = input("Enter IPs to exclude from most common IPs (separated by commas): ")
    save_option = input("Do you want to save the statistics to a file? (yes/no): ").lower()
    if save_option == "yes":
        analyze_pcap(pcap_file, exclude_ips, save_to_file=True)
    else:
        analyze_pcap(pcap_file, exclude_ips)
