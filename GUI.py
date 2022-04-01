import PySimpleGUI as sg

# dummy list to simulate list of sniffed packets !--REMOVE WHEN INTEGRATING--!
sniffed = ['Ether / IPv6 / UDP / DNS Qry "b''discord.com.''"',
           'Ether / IPv6 / UDP / DNS Qry "b''discord.com.''"',
           'Ether / IPv6 / UDP / DNS Qry "b''discord.com.''"',
           'Ether / IPv6 / UDP / DNS Qry "b''discord.com.''"',
           'Ether / IPv6 / UDP / DNS Qry "b''discord.com.''"']

sniffed2 = ['Ether / IPv6 / UDP / DNS Qry "b''.com.''"',
           'Ether / IPv6 / UDP / DNS Qry "b''.com.''"',
           'Ether / IPv6 / UDP / DNS Qry "b''.com.''"',
           'Ether / IPv6 / UDP / DNS Qry "b''.com.''"',
           'Ether / IPv6 / UDP / DNS Qry "b''.com.''"']


# dummy list to simulate list of blocked ip !--REMOVE WHEN INTEGRATING--!
ips = ['10.18.254.151', '209.165.226.40', '86.128.213.12', '209.165.226.40', '41.130.248.117']

# create a string with newline delimiter for printing
list_packets = '\n'.join([str(i) for i in ips])
list_sniffed = '\n'.join([str(i) for i in sniffed])

# layout of gui window
layout = [[sg.Text('Summary of Packets Sniffed:', font=20)],
          [sg.Multiline('', size=(75,10), disabled=True, key='summary')],
          [sg.Multiline('list_packets', size=(75,10), disabled=True, key='blocked')]
          ]

# create the window
window = sg.Window('Window Title', layout)

# loop through to keep window open till its closed
while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Cancel': # if user closes window or clicks cancel
        break
    print('You entered ', values[0])

window.close()