from time import sleep
from scapy.all import *
from scapy.utils import PcapWriter
from datetime import *
import ctypes, os, sys
from os import path
from sniffer import Sniffer
from block_threats import Blocker
import PySimpleGUI as sg
import threading

win = ["win32", "win64"]
platform = sys.platform

# layout of gui window
layout = [[sg.Text('Summary of Packets Sniffed:', font=20)],
          [sg.Multiline('Waiting for summary...', size=(75,10), disabled=True, key='summary')],
          [sg.Text('IP addresses blocked:', font=20)],
          [sg.Multiline('Blocking IPs...', size=(75,10), disabled=True, key='blocked')]
          ]

# create the window
window = sg.Window('Packet Sniffer', layout, finalize=True)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def sniff_threats(sniffer):

    # sniff and analyze the network
    sniffer.sniff()
    sniffer.analyze()
    # sniffer.print_summary()

    # write the unwanted IPs to p_threats.txt
    sniffer.write()

def block_threats(blocker):
    
    # read threats from p_threats.txt
    blocker.read_threats()

    # block by adding rules to Windows Firewall
    blocker.add_rules()

def to_string(given_list):

    to_display = '\n'.join([str(i) for i in given_list])
    return to_display

def run_thread(window, sniffer, blocker):
    # Create sniffer and blocker
    # sniffer = Sniffer()
    # blocker = Blocker()

    now = datetime.now()
    stop = now + timedelta(seconds=20)
    flushdns = os.system("ipconfig /flushdns")

    # sniff for threats
    while datetime.now() < stop:
        sniff_threats(sniffer)
        # display packet summaries into the window
        summary_string = to_string(sniffer.summary)
        # window['summary'].update(summary_string)
        # TBC
        window.write_event_value('packets', summary_string)
        sniffer.sniffer_clear()
    
    block_threats(blocker)

    # Update blocked IPs window
    ips_string = to_string(blocker.p_threats)
    # window['blocked'].update(ips_string)
    # TBC
    window.write_event_value('ips', ips_string)

    # blocker.remove_rules()

    # return [summary_string, ips_string]
    return

def remove_blocked(blocker):
    print("Removing all rules")
    blocker.remove_rules()
    return

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

            # # create the window
            # window = sg.Window('Packet Sniffer', layout)

            i = 1
            window.write_event_value('continue', i)

            try:
                while True:

                    event, values = window.read(timeout=100)
                    if event == sg.WIN_CLOSED or event == 'Cancel': # if user closes window or clicks cancel
                        break
                    window.refresh()
                    
                    if event == 'continue':
                        print("Running iteration " + str(i))
                        i+=1
                        window.perform_long_operation(lambda: run_thread(window, sniffer, blocker), 'block done')
                        # threading.Thread(target=run_thread, args=(window, sniffer, blocker), daemon=True)
                    elif event == 'block done':
                        # print(values)
                        # window['summary'].update(values[event][0])
                        # window['blocked'].update(values[event][1])
                        window.refresh()
                        # blocker = values[event][2]
                        window.perform_long_operation(lambda: sleep(10), 'remove rules')
                    elif event == 'remove rules':
                        window.perform_long_operation(lambda: remove_blocked(blocker), 'continue')
                    elif event == 'packets':
                        window.Element('summary').Update(values[event])
                        window.Element('summary').set_vscroll_position(1)
                        window.refresh()
                    elif event == 'ips':
                        window['blocked'].update(values[event])
                        window.Element('blocked').set_vscroll_position(1)
                        window.refresh()



                    # else:
                    # print("running iteration " + str(i))
                    # i+=1
                    # now = datetime.now()
                    # stop = now + timedelta(seconds=20)
                    # flushdns = os.system("ipconfig /flushdns")

                    # # sniff for threats
                    # while datetime.now() < stop:
                    #     sniff_threats(sniffer)
                    #     # display packet summaries into the window
                    #     summary_string = to_string(sniffer.summary)
                    #     window['summary'].update(summary_string)
                    
                    # block_threats(blocker)

                    # # Update blocked IPs window
                    # ips_string = to_string(blocker.p_threats)
                    # window['blocked'].update(ips_string)

                    # event, values = window.read(timeout=100)
                    # sleep(10)

                    # blocker.remove_rules()

            except KeyboardInterrupt:
                print("Removing all rules")
                blocker.remove_rules()
                print("Exiting gracefully")
                exit(0)
            except Exception as e:
                print(str(e))
                sleep(40)
            
            # end the application
            print("Removing all rules")
            blocker.remove_rules()
            print("Exiting gracefully")
            window.close()
            exit(0)

    else:
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

if __name__ == '__main__':
    main()
    