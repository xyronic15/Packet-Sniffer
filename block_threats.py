from time import sleep
import os, sys, signal
from os import path

# def signal_handler(signal, frame):
#     print("\nClearing firewall rules")
#     for i in p_threats:
#         os.system('netsh advfirewall firewall delete rule name="BLOCK IP {}"'.format(i))
#     sys.exit(0)

# signal.signal(signal.SIGINT, signal_handler)

# while not path.exists('p_threats.txt'):
#     sleep(3)

# while path.exists('p_threats.txt'):
    
#     p_threats = []
#     sniffed = []

#     # Blocker.read_threats()
#     # read the txt file
#     f = open('p_threats.txt', 'r+')
#     for i in f:
#         sniffed.append(i)
#     f.close()

#     # Remove any duplicates and empty spaces
#     for i in sniffed:
#         i = (i[:-1])
#         if i not in p_threats:
#             p_threats.append(i)
#     # Blocker.read_threats()

#     # Blocker.add_rules()
#     # send firewall rules out
#     for i in p_threats:
#         os.system('netsh advfirewall firewall add rule name="BLOCK IP {}" dir=out action=block remoteip={}'.format(i,i))
#     # Blocker.add_rules()
    
#     sleep(10)

#     # Blocker.remove_rules()
#     for i in p_threats:
#         os.system('netsh advfirewall firewall delete rule name="BLOCK IP {}"'.format(i))
#     # Blocker.remove_rules()

# # while path.exists('p_threats.txt'):
# #     sleep(3)

class Blocker(object):
    def __init__(self, *args):
        self.sniffed = []
        self.p_threats = []

    def read_threats(self):
        # read the txt file
        f = open('p_threats.txt', 'r+')
        for i in f:
            self.sniffed.append(i)
        f.close()

        # Remove any duplicates and empty spaces
        for i in self.sniffed:
            i = (i[:-1])
            if i not in self.p_threats:
                self.p_threats.append(i)

    def add_rules(self):
        for i in self.p_threats:
            os.system('netsh advfirewall firewall add rule name="BLOCK IP {}" dir=out action=block remoteip={}'.format(i,i))
    
    def remove_rules(self):
        for i in self.p_threats:
            os.system('netsh advfirewall firewall delete rule name="BLOCK IP {}"'.format(i))
        self.p_threats.clear()
        self.sniffed.clear()