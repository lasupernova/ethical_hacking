#!/usr/bin/env python

#----- import libraries and modules -----

#import scapy.all as scapy
import scapy.all as scapy
import optparse
import os

#-----define functions------

def get_args():
    '''
    Get command line arguments
    '''

    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="Target IP or IP range. Form: xxx.xxx.xxx.xxx[/xx]")
    #parser.add_option("-o", "--output", dest="response_output", help="Indicate if responses should be printed to screen")

    (options, _) = parser.parse_args()

    if (not options.ip):
        parser.error("[-] Specify an IP (range) using '-t <value>' or use '--help' for more info")
        quit()
    else:
        return options.ip

def scan(ip):
    '''
    Function taking an IP or IP range, sending an ARP request to all provided IPs via the network's broadcast channel
    and scanning all responding IPs for their MAC address. The function outputs all MAC addresses and returns
    a list of dicts containing a dict with 'ip' and 'mac'-keys for each response.

    :param ip:
    :return: client_list; list containing dict for ip and MAC for each response
    '''
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_request

    (response_list, no_response_list) = scapy.srp(arp_req_broadcast, timeout=2, verbose=False)

    clients_list = []
    for response in response_list: #response_list is a list of tuples with a tuple for each response received
        #print(response[1].summary()) ##each response is a tuple with the request at loc 1 and the response t loc 2; each of these is an ARP packet, which can be analyzed using .summary() or of which information can be extracted using .psrc or .hwsrc

        current_ip = response[1].psrc
        current_mac = response[1].hwsrc
        clients_dict = {"ip": current_ip, "MAC": current_mac}
        clients_list.append(clients_dict)

    return clients_list

def print_response(client_list):
    print("IP\t\t||\tMAC address")
    print("-----------------------------------------")

    for response in client_list:
        try:
            print(f"{response['ip']}\t||\t{response['MAC']}")
        except SyntaxError:
            print("Use 'python3 net_scan.py -t <IP>'")
            quit()

#------call functions-----
if __name__ == "__main__":
    print("\n\n")
    ip = get_args()
    response_list = scan(ip)
    print_response(response_list)






