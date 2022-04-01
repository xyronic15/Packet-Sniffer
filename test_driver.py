from time import sleep
from scapy.all import *
from scapy.utils import PcapWriter
from datetime import *
import ctypes, os, sys, signal
from os import path
from sniffer import Sniffer
from block_threats import Blocker

win = ["win32", "win64"]
platform = sys.platform

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def sniff_threats(sniffer):

    sniffer.sniff()
    sniffer.analyze()
    sniffer.print_summary()
    sniffer.write()

def block_threats(blocker):
    
    blocker.read_threats()
    blocker.add_rules()

def main():
    
    # check if admin privileges or not
    if is_admin():
        if platform in win:
            print("Windows")
            print("admin")
            # sleep(10)

            # Create sniffer and blocker
            sniffer = Sniffer()
            blocker = Blocker()

            try:
                while True:
                    now = datetime.now()
                    stop = now + timedelta(seconds=20)
                    flushdns = os.system("ipconfig /flushdns")

                    # sniff for threats
                    while datetime.now() < stop:
                        sniff_threats(sniffer)
                    
                    block_threats(blocker)

                    sleep(10)

                    blocker.remove_rules()

            except KeyboardInterrupt:
                print("Removing all rules")
                blocker.remove_rules()
                print("Exiting gracefully")
                exit(0)
            except Exception as e:
                print(str(e))
                sleep(100)

    else:
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

if __name__ == '__main__':
    main()
    