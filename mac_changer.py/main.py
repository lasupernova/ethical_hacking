#!/usr/bin/env python3

'''
MAC changer taking command line arguments to specify interface and desired MAC address
'''
import subprocess
import optparse

print("-------MAC address changer-------\n")
interface = input("Interface to change MAC address for > ")
new_mac = input("\nDesired MAC-address > ")

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


'''
NOTE: the way of using subprocess.call()shown in this string is suboptimal, 
as it allows for code injections, e.g. by writing 'eth0;ls;' into the prompt;
--> better: use the way shown above (in active code) to call subprocess.call();

subprocess.call(f"ifconfig {interface} down", shell=True) #Shell=True enables running shell-commands through this function
subprocess.call(f"ifconfig {interface} hw ether {new_mac}", shell=True)
subprocess.call(f"ifconfig {interface} up", shell=True)
'''

