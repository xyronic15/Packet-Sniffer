from time import sleep
import os, sys, signal
from os import path

def signal_handler(signal, frame):
    print("\nClearing firewall rules")
    for i in p_threats:
        os.system('netsh advfirewall firewall delete rule name="BLOCK IP {}"'.format(i))
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

while not path.exists('p_threats.txt'):
    sleep(3)

while path.exists('p_threats.txt'):
    
    p_threats = []
    sniffed = []

    # read the txt file
    f = open('p_threats.txt', 'r+')
    for i in f:
        sniffed.append(i)
    f.close()

    # Remove any duplicates and empty spaces
    for i in sniffed:
        i = (i[:-1])
        if i not in p_threats:
            p_threats.append(i)

    # send firewall rules out
    for i in p_threats:
        os.system('netsh advfirewall firewall add rule name="BLOCK IP {}" dir=out action=block remoteip={}'.format(i,i))
    
    sleep(10)

    for i in p_threats:
        os.system('netsh advfirewall firewall delete rule name="BLOCK IP {}"'.format(i))

# while path.exists('p_threats.txt'):
#     sleep(3)