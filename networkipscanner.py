from scapy.all import srp, Ether, ARP

def arp_scan(ip_range):
    # Create an ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

    # Send the packet and capture the response
    result = srp(arp_request, timeout=2, verbose=False)[0]

    # Extract and print the IP and MAC addresses from the response
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        print(f"IP: {received.psrc}\tMAC: {received.hwsrc}")

    return devices

# Example: Scan the 192.168.1.0/24 subnet
ip_range = "192.168.1.0/24"
arp_scan(ip_range)

