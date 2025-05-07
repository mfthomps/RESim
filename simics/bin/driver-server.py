#!/usr/bin/env python3
import socket,os,sys
from ast import literal_eval as make_tuple
'''
Receive directives from a simics host and interact
with the target accordingly.
'''
log = open('/tmp/serverx.log', 'a') 
print('driver-server begin', file=log)
# Server 
host = '0.0.0.0'        
port = 6459 

did_ip_addr = False
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((host, port))
src_ip_file = './source_ip'
if len(sys.argv) > 1 and sys.argv[1] == 'restart':
    print('driver-server is restart', file=log)
    is_restart = True
    if os.path.isfile(src_ip_file):
        print('driver-server found ip file', file=log)
        with open(src_ip_file) as fh:
            source_ip = fh.read()
            source = make_tuple(source_ip) 
            s.sendto('xxx'.encode(), source)
            print('sent start signal to %s' % source_ip, file=log)
    else:
        print('no ip file found', file=log)

log.flush()
while True:
    while True:
        f, source = s.recvfrom(1024)
        if not did_ip_addr:
            with open(src_ip_file, 'w') as fh:
                fh.write(str(source))
                print('wrote source %s' % str(source), file=log)
        did_ip_addr = True
        if f is None or len(f) == 0:
            break
        header = f.decode()
        print('len of f is %d source %s' % (len(f), source), file=log)
        log.flush()
        if header.endswith("=EOFX="):
            # OBSCURE: anthing other than 'ack' reflects that this service supports UDP acks.
            # Otherwise, if 'ack', acks are not used.  The driver-server version is managed
            # by the driver_server_version and genMonitor which stores that in snapshots and
            # copies its value to the workspace to be found by drive-driver.
            s.sendto('ac1'.encode(), source)
            ack, source = s.recvfrom(3)
            print('got ack ack', file=log)
            parts = str(header).split()
            cmd = str(parts[0])
            if cmd == 'FILE:':
                the_size = str(parts[1])
                name = str(" ".join(parts[2:-1]))
                print("-- Receive file: " + name + " (" + the_size + ")", file=log)
                local_name = os.path.join('/tmp/', name) 
                g = open(local_name, 'wb')
                tot=0
                count = 0
                while True:
                    read_data, source = s.recvfrom(1024)
                    print('len of read_data is %d' % len(read_data), file=log)
                    tot=tot+len(read_data)
                    try: 
                        if read_data.decode().endswith('=EOFX=') == True: 
                            break
                    except: 
                        pass
                    count += 1
                    if count % 20 == 0:
                        s.sendto('ack'.encode(), source)
                        print('sent ack count %d' % count, file=log)
                    g.write(read_data)
                    log.flush()
                g.write(read_data[:-6])
                g.close()
                if the_size == str(os.path.getsize(local_name)): 
                    print(">> Size verified.", file=log)
                else: 
                    print("sizes do not match", file=log)
                    msg = 'size from header %s,  size of file %s' % (the_size, str(os.path.getsize(local_name)))
                    print(msg, file=log)
                s.sendto('ack'.encode(), source)
                print('tot %d' % tot, file=log)
            elif cmd == 'RUN:':
                dothis = " ".join(parts[1:-1])
                os.system(dothis)
                print('did cmd: %s' % dothis, file=log)
            elif cmd == 'RUN_LONG:':
                dothis = " ".join(parts[1:-1])
                os.spawnl(os.P_NOWAIT, dothis)
                print('did long cmd: %s' % dothis, file=log)
            else:
                print('unknown command %s in %s' % (cmd, header), file=log)
        log.flush()
