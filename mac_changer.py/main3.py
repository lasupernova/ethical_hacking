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

    return parser.parse_args()

def change_mac(interface, new_mac):
    '''
    MAC changer taking command line arguments to specify interface and desired MAC address
    '''

    print("\n\t- - - - - - MAC address changer - - - - - -\n")
    print(f"\n[+] Changing MAC address for {interface}")

    '''
    NOTE: when using f-strings or other Python 3 specific functionality in linux, 
    specify and run "python3 main.py" instead of "python main.py"
    '''

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

    print(f"\n[+] MAC address changed to {new_mac}\n")

    subprocess.call(f"ifconfig eth0", shell=True)

(options, _)= get_args()
change_mac(options.interface, options.new_mac)

'''
NOTE: the way of using subprocess.call()shown in this string is suboptimal, 
as it allows for code injections, e.g. by writing 'eth0;ls;' into the prompt;
--> better: use the way shown above (in active code) to call subprocess.call();

subprocess.call(f"ifconfig {interface} down", shell=True) #Shell=True enables running shell-commands through this function
subprocess.call(f"ifconfig {interface} hw ether {new_mac}", shell=True)
subprocess.call(f"ifconfig {interface} up", shell=True)
'''

