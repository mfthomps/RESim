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
host = 'localhost'
port = 60026
if len(sys.argv) > 1:
    port = int(sys.argv[1].strip())
print('port %d' % port)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_addr = (host, port)
infile = '/tmp/sendudp'

with open (infile) as fh:
    s = fh.read()
    time.sleep(10)
    sock.sendto(s, server_addr)
    print('did send')
