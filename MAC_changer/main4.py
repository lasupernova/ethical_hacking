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

def change_mac(interface, new_mac):
    '''
    MAC changer taking command line arguments to specify interface and desired MAC address
    '''

    print("\n\t- - - - - - MAC address changer - - - - - -\n")
    print(f"\n[+] Changing MAC address for {interface}")

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

    print(f"\n[+] MAC address changed to {new_mac}\n")

    subprocess.call(f"ifconfig eth0", shell=True)

if __name__ == "__main__":
    options = get_args()
    change_mac(options.interface, options.new_mac)


