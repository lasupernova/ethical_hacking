#!/usr/bin/env python3

import subprocess
import optparse

def get_args():
    '''
    Get command line arguments
    '''

    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change MAC address for")
    parser.add_option("-m", "--mac", dest="new_mac", help="Desired MAC address")

    (options, arguments) = parser.parse_args()

    if (not options.interface) and (not options.new_mac):
        parser.error("[-] Specify an interface and a MAC address! Use '--help' for info")
    elif not options.interface:
        parser.error("[-] Specify an interface using '-i <value>' or use '--help' for info")
    elif not options.new_mac:
        parser.error("[-] Specify an MAC address using '-m <value>' or use '--help' for info")
    else:
        return options

def check_interface_MAC(interface):
    info = subprocess.Popen(["ifconfig", interface], stdout=subprocess.PIPE)
    text = subprocess.check_output(["grep", "ether"], stdin=info.stdout)
    reg = r"((?:\w{2}:){5}(?:\w{2}))"
    detected_mac = re.findall(reg, str(text)) #text is a byte-like object -> use str() to convert into string
    if len(detected_mac) < 1:
        print("ERROR: No currently used AC address for specified interface found! Check interface input\n")
        return 0
    elif len(detected_mac) > 1:
        print(f"ERROR: {len(detected_mac)} MAC addresses detected.")
        return 0
    else:
        return detected_mac[0]

def change_mac(interface, new_mac):
    '''
    MAC changer taking command line arguments to specify interface and desired MAC address
    '''

    print("\n\t- - - - - - MAC address changer - - - - - -\n")

    current_mac = check_interface_MAC(interface)

    if current_mac == new_mac:
        print(f"\t[-] The current MAC address for {interface} is already {new_mac}")
        print("\n\t    Quitting program.")
        quit()
    elif current_mac != 0:
        print(f"\nCurrent MAC address for {interface}: {current_mac}")
    else:
        quit()

    print(f"\n\t[+] Changing MAC address for {interface}")

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

    current_mac = check_interface_MAC(interface)
    if (current_mac !=0) and (current_mac==new_mac):
        print(f"\n\t[+] MAC address for {interface} changed to: {current_mac}")
    else:
        print(f"\n\t[-] MAC address for {interface} could not be changed. The current MAC address is {current_mac}")
        quit()

if __name__ == "__main__":
    options = get_args()
    change_mac(options.interface, options.new_mac)


