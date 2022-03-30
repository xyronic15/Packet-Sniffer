from time import sleep
from scapy.all import *
from scapy.utils import PcapWriter
from datetime import *
import os, sys, signal

FILTER = "tcp[tcpflags] & (tcp-syn) != 0  or port 53"

# signal handler for easy exit
# def signal_handler(signal, fram):
#     print("Exiting gracefully")
#     sys.exit(0)

# signal.signal(signal.SIGINT, signal_handler)
# win = ["win32", "win64"]
# platform = sys.platform

# if platform in win:
#     print("Windows")
#     now = datetime.now()
#     stop = now + timedelta(seconds=20)
#     flushdns = os.system("ipconfig /flushdns")

#     try:
#         while datetime.now() < stop:
#             # sniff the packets
#             # Sniffer.sniff()
#             packets = sniff(filter=FILTER, session=IPSession, count=2, prn=lambda x:x.summary())
#             dump1 = PcapWriter("sniffed.pcap", append=True, sync=True)
#             dump1.write(packets)
#             # Sniffer.sniff()

#             # save sniffed packets to pcap file
#             # Sniffer.analyze()
#             pcap = 'sniffed.pcap'
#             pkts = rdpcap(pcap)
#             UDP_ips = []
#             TCP_ips = []
#             # info = []

#             # iterate through sniffed packets and get the addresses for those with TCP and UDP layers
#             for packet in pkts:
#                 # info.append(packet.show(dump=True))
#                 if packet.haslayer(TCP):
#                     # print(packet[IP].dst)
#                     if packet.haslayer(IP):
#                         TCP_ips.append(packet[IP].dst)
#                     elif packet.haslayer(IPv6):
#                         TCP_ips.append(packet[IPv6].dst)
#                 if packet.haslayer(UDP):
#                     if packet.haslayer(IP):
#                         UDP_ips.append(packet[IP].dst)
#                     elif packet.haslayer(IPv6):
#                         UDP_ips.append(packet[IPv6].dst)
#                     # check if there is a response from the DNS layer
#                     if packet.haslayer(DNSRR):
#                         # count the number of answers returned by the DNS layer
#                         answer_count = packet[DNS].ancount
#                         i = answer_count + 4
#                         arp = "arpa"
                        
#                         while i > 4:
#                             # if the rdata is an ip address then add to the list
#                             if str(packet[0][i].rdata)[0].isnumeric():
#                                 UDP_ips.append(packet[0][i].rdata)
#                             # Check if the IP might have been passed at the end of the rrname
#                             elif packet[0][i].rrname.decode().count("in-addr.arpa") > 0:
#                                 base = packet[0][i].rrname.decode()
#                                 # get the last 13 digits which would be the IP
#                                 chop = base[:-14]
#                                 work = chop.split('.')
#                                 final = work[3] + "." + work[2] + "." + work[1] + "." + work[0]
#                             i-=1
#             # remove any TCP addresses that are not seen in UDP IPs
#             in_TCP_not_UDP = list(set(TCP_ips)-set(UDP_ips))
#             # Sniffer.analyze()

#             # Sniffer.write()
#             # write to external txt file
#             with open('p_threats.txt', 'w+') as f:
#                 for i in in_TCP_not_UDP:
#                     f.write(str(i) + "\n")
#                 f.close()
            
#             # with open('info.txt', 'w+') as f:
#             #     for i in info:
#             #         f.write(str(i) + "\n")
#             #     f.close()
#             # Sniffer.write()
#     except KeyboardInterrupt:
#         print("Sniffing stopped")

                
class Sniffer():
    def __init__(self):
        self.UDP_ips = []
        self.TCP_ips = []
        self.in_TCP_not_UDP = []
        # self.info = []
    
    def sniff(self):
        packets = sniff(filter=FILTER, session=IPSession, count=2, prn=lambda x:x.summary())
        dump1 = PcapWriter("sniffed.pcap", append=True, sync=True)
        dump1.write(packets)
    
    def analyze(self):
        pcap = 'sniffed.pcap'
        pkts = rdpcap(pcap)
        # self.info = []

        # iterate through sniffed packets and get the addresses for those with TCP and UDP layers
        for packet in pkts:
            # self.info.append(packet.show(dump=True))
            if packet.haslayer(TCP):
                # print(packet[IP].dst)
                if packet.haslayer(IP):
                    self.TCP_ips.append(packet[IP].dst)
                elif packet.haslayer(IPv6):
                    self.TCP_ips.append(packet[IPv6].dst)
            if packet.haslayer(UDP):
                if packet.haslayer(IP):
                    self.UDP_ips.append(packet[IP].dst)
                elif packet.haslayer(IPv6):
                    self.UDP_ips.append(packet[IPv6].dst)
                # check if there is a response from the DNS layer
                if packet.haslayer(DNSRR):
                    # count the number of answers returned by the DNS layer
                    answer_count = packet[DNS].ancount
                    i = answer_count + 4
                    arp = "arpa"
                    
                    while i > 4:
                        # if the rdata is an ip address then add to the list
                        if str(packet[0][i].rdata)[0].isnumeric():
                            self.UDP_ips.append(packet[0][i].rdata)
                        # Check if the IP might have been passed at the end of the rrname
                        elif packet[0][i].rrname.decode().count("in-addr.arpa") > 0:
                            base = packet[0][i].rrname.decode()
                            # get the last 13 digits which would be the IP
                            chop = base[:-14]
                            work = chop.split('.')
                            final = work[3] + "." + work[2] + "." + work[1] + "." + work[0]
                        i-=1
        # remove any TCP addresses that are not seen in UDP IPs
        self.in_TCP_not_UDP = list(set(TCP_ips)-set(UDP_ips))
    
    def write(self):
        # write to external txt file
        with open('p_threats.txt', 'w+') as f:
            for i in in_TCP_not_UDP:
                f.write(str(i) + "\n")
            f.close()
        
        # with open('info.txt', 'w+') as f:
        #     for i in info:
        #         f.write(str(i) + "\n")
        #     f.close()