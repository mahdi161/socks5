
#!/usr/bin/python
# -*- coding:utf-8 -*-
import requests
import socket
import struct
import json,os

# function check proxy performance
# Returns True if the proxy is working, returns False for any errors.
def checkproxy(ip, port):
    try:
        port = int(port)
    except ValueError as msg:
        print('Invalid port')
        return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((ip, port))
            s.sendall(struct.pack(
                '!BBB',
                0x05,  # SOCKS version number
                0x01,  # Number of authentication methods supported
                0x00,  # Numbers of authentication methods, 1 byte for each method
                ))
            recv = s.recv(1024)
             # server response
             # 1 byte - SOCKS version number (must be 0x05 for this version)
             # 1 byte - Selected authentication method or 0xFF if there is no acceptable method.
            s.close()
            if recv == b'\x05\x00':
                return True
            return False
    except socket.gaierror as msg:
        print("Invalid address")
        return False
    except socket.timeout as msg:
        #print("Timeframe subclusions")
        return False
    except Exception as e:
        pass


# connect to the proxy site
url = "https://mtpro.xyz/api/?type=socks"
reqheaders = {
    'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) \ '
                  'AppleWebKit/537.36 (KHTML, like Gecko) \ '
                  'Chrome/62.0.3202.94 Safari/537.36',
}
session = requests.Session()
resp = session.get(url, data={}, headers=reqheaders)
# getting an answer code
if resp.status_code != 200:
    print("Error reading page. HTTP response code - " + resp.status_code)
proxys =[]

for n in range(49):
    proxy=json.loads(resp.text)
    proxys.append(proxy[n]['ip']+":"+proxy[n]['port'])
os.remove("downloads/proxy.txt")
for i in proxys:
    testit=i.split(":")
    if checkproxy(testit[0], testit[1]) == True:
        print("Work SOCKS5 proxy: {0}:{1}".format(testit[0], testit[1]))
        filesuccess=open("downloads/proxy.txt","a")
        filesuccess.write(str(testit[0]+":"+testit[1])+"\n")
        filesuccess.close()
        
