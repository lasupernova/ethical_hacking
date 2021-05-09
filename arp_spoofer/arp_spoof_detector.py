import scapy.all as scapy

def get_mac_from_ip(ip):
    '''
    Function taking an ip address and returning the associated MAC address

    :param ip: IP address of interest
    :return: mac_address
    '''
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    response_list, _ = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)

    mac_address = response_list[0][1].hwsrc

    return mac_address

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_package)

def process_sniffed_package(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op ==2 :
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print(f"[+] You are under attack from {response_mac}!")

        except IndexError:
            pass

if __name__ == "__main__":
    sniff('eth0')
