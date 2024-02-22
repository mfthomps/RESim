#!/usr/bin/env python3
import socket,os
 
# Server 
host = '0.0.0.0'        
port = 6459 

log = open('/tmp/server.log', 'w') 
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((host, port))
print('driver-server begin', file=log)
while True:
    while True:
        f, source = s.recvfrom(1024)
        if f is None or len(f) == 0:
            break
        header = f.decode()
        print('len of f is %d' % len(f), file=log)
        log.flush()
        if header.endswith("=EOFX="):
            s.sendto('ack'.encode(), source)
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
                while True:
                    read_data, source = s.recvfrom(1024)
                    print('len of read_data is %d' % len(read_data), file=log)
                    tot=tot+len(read_data)
                    try: 
                        if read_data.decode().endswith('=EOFX=') == True: break
                    except: pass
                    g.write(read_data)
                    log.flush()
                g.write(read_data[:-6])
                g.close()
                if the_size == str(os.path.getsize(local_name)): print(">> Size verified.", file=log)
                else: print("sizes do not match", file=log)
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
