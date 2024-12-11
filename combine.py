from scapy.all import ARP, DNS, sniff

def detect_arp_spoof(packet):
    """Detect ARP spoofing by checking if the same IP has multiple MAC addresses."""
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
        source_ip = packet[ARP].psrc
        source_mac = packet[ARP].hwsrc

        # Static cache to store IP-MAC mappings
        if source_ip in ip_mac_cache:
            if ip_mac_cache[source_ip] != source_mac:
                print(f"[ALERT] ARP Spoofing detected! IP {source_ip} is associated with multiple MACs: {ip_mac_cache[source_ip]} and {source_mac}")
        else:
            ip_mac_cache[source_ip] = source_mac

def detect_dns_spoof(packet):
    """Analyze DNS packets to detect potential spoofing."""
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 1:  # Only DNS responses
        dns_resp = packet.getlayer(DNS)
        # Check if the DNS response has unexpected or suspicious IP addresses
        if dns_resp.an:
            for answer in dns_resp.an:
                if answer.type == 1:  # Check for A record (IPv4 address)
                    # Replace with your trusted IP addresses or logic
                    trusted_ips = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
                    if answer.rdata not in trusted_ips:
                        print(f"[ALERT] Potential DNS spoofing detected! Domain: {answer.rrname.decode('utf-8')}, IP: {answer.rdata}")

def combined_callback(packet):
    """Callback function to handle packets for both ARP and DNS spoofing detection."""
    detect_arp_spoof(packet)
    detect_dns_spoof(packet)

if __name__ == "__main__":
    # Initialize a cache to store IP-MAC mappings
    ip_mac_cache = {}

    print("[INFO] Starting ARP and DNS spoof detection...")
    try:
        # Replace 'your_interface' with your network interface name, e.g., 'eth0' or 'wlan0'
        sniff(prn=combined_callback, filter="arp or udp port 53", store=0, iface="enp0s3")
    except KeyboardInterrupt:
        print("\n[INFO] Stopping ARP and DNS spoof detection.")
