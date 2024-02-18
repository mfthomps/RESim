#!/usr/bin/env python3
import socket,os
 
# Server 
host = '0.0.0.0'        
port = 6459 
 
d = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
d.bind((host, port))
d.listen(1)
while True:
    s,a = d.accept()
    while True:
        f = s.recv(1024)
        if f is None or len(f) == 0:
            break
        header = f.decode()
        print('len of f is %d' % len(f))
        if header.endswith("=EOFX="):
            s.send('ack'.encode())
            s.recv(3)
            print('got ack ack')
            parts = str(header).split()
            cmd = str(parts[0])
            if cmd == 'FILE:':
                the_size = str(parts[1])
                name = str(" ".join(parts[2:-1]))
                print("-- Receive file: " + name + " (" + the_size + ")")
                local_name = os.path.join('/tmp/', name) 
                g = open(local_name, 'wb')
                tot=0
                while True:
                    read_data = s.recv(1024)
                    print('len of read_data is %d' % len(read_data))
                    tot=tot+len(read_data)
                    try: 
                        if read_data.decode().endswith('=EOFX=') == True: break
                    except: pass
                    g.write(read_data)
                g.write(read_data[:-6])
                g.close()
                if the_size == str(os.path.getsize(local_name)): print(">> Size verified.")
                else: print("sizes do not match")
                s.send('ack'.encode())
                print('tot %d' % tot)
            elif cmd == 'RUN:':
                dothis = " ".join(parts[1:-1])
                os.system(dothis)
                print('did cmd: %s' % dothis)
            elif cmd == 'RUN_LONG:':
                dothis = " ".join(parts[1:-1])
                os.spawnl(os.P_NOWAIT, dothis)
                print('did long cmd: %s' % dothis)
            else:
                print('unknown command %s in %s' % (cmd, header))
    s.close()
d.close()
