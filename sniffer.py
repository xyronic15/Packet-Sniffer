from time import sleep
from scapy.all import *
from scapy.utils import PcapWriter
from datetime import *
import os, sys, signal

FILTER = "tcp[tcpflags] & (tcp-syn) != 0  or port 53"

# signal handler for easy exit
def signal_handler(signal, fram):
    print("Exiting gracefully")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
win = ["win32", "win64"]
platform = sys.platform

if platform in win:
    print("Windows")
    now = datetime.now()
    stop = now + timedelta(seconds=120)
    flushdns = os.system("ipconfig /flushdns")

    while datetime.now() < stop:
        packets = sniff(filter=FILTER, session=IPSession, count=20, prn=lambda x:x.summary())
        dump1 = PcapWriter("sniffed.pcap", append=True, sync=True)
        dump1.write(packets)

        pcap = 'sniffed.pcap'
        pkts = rdpcap(pcap)
        UDPips = []
        TCPips = []

        for packet in pkts:
            if packet.haslayer(TCP):
                TCPips.append(packet[IP].dst)
            if packet.haslayer(UDP):
                UDPips.append(packet[IP].dst)
            