#!/usr/bin/env python3
'''
Send data files to the driver and from there, send them to one or more target IP/ports.
Optionally executes magic instruction 99 just prior to sending data to reset RESim origin,
and disconnects the driver from the system.


directive file example:
    some.io 171.10.0.1  29121

Or, multiwrite TCP (with read between them):
    first.io
    second.io  171.10.0.1 29121

Directive lines that start with a # are ignored.
Lines that start with ! are treated as shell commands to be executed on the driver.
'''
import os
import time
import socket
import sys
import subprocess
import argparse
import shlex
resim_dir = os.getenv('RESIM_DIR')
user_name = os.getenv('RESIM_DIR')
core_path=os.path.join(resim_dir,'simics', 'monitorCore')
sys.path.append(core_path)
import runAFL
import resimUtils
def main():
    parser = argparse.ArgumentParser(prog='drive-driver.py', description='Send files to the driver and from there to one or more targets.')
    parser.add_argument('directives', action='store', help='File containing driver directives')
    parser.add_argument('-d', '--disconnect', action='store_true', help='Disconnect driver and set new origin after sending data.')
    parser.add_argument('-t', '--tcp', action='store_true', help='Use TCP.')
    parser.add_argument('-b', '--broadcast', action='store_true', help='Use broadcast.')
    parser.add_argument('-x', '--tcpx', action='store_true', help='Use TCP but do not read between writes -- experimental.')
    parser.add_argument('-s', '--server', action='store_true', help='Accept TCP connections from a client, and send the data.')
    parser.add_argument('-p', '--port', action='store', type=int, default=4022, help='Alternate ssh port, default is 4022')
    parser.add_argument('-r', '--replay', action='store_true', help='Treat the directives as PCAPS to be sent via tcpreplay')
    parser.add_argument('-c', '--command', action='store_true', help='The directive simply names a script to be xfered and run from the driver.')
    parser.add_argument('-j', '--json', action='store_true', help='Send UDP packets found in a given json file')
    args = parser.parse_args()
    sshport = args.port
    print('Drive driver')
    if not os.path.isfile(args.directives):
        print('No file found at %s' % args.directives)
        exit(1)
    if args.server:
        client_cmd = 'serverTCP'
    elif args.tcp:
        client_cmd = 'clientTCP'
    elif args.tcpx:
        client_cmd = 'clientTCPnoread'
        args.tcp = True
    elif args.replay:
        client_cmd = None
    elif args.broadcast:
        client_cmd = 'clientudpBroad'
    elif args.json:
        client_cmd = 'clientudpJson'
    elif args.command:
        client_cmd = None
    else:
        client_cmd = 'clientudpMult'
    if client_cmd is not None:
        client_mult_path = os.path.join(core_path, client_cmd)
    
        cmd = 'scp -P %d %s  mike@localhost:/tmp/' % (sshport, client_mult_path)
        result = -1
        count = 0
        while result != 0:
            result = os.system(cmd)
            #print('result is %s' % result)
            if result != 0:
                print('scp of %s failed, wait a bit' % client_mult_path)
                time.sleep(3)
                count += 1
                if count > 10:
                    print('Time out, more than 10 failures trying to scp to driver.')
                    sys.exit(1)
    if args.disconnect:
        magic_path = os.path.join(resim_dir, 'simics', 'magic', 'simics-magic')
        cmd = 'scp -P %d %s  mike@localhost:/tmp/' % (sshport, magic_path)
        os.system(cmd)

    user_dir = os.path.join('/tmp', user_name)
    try:
        os.mkdir(user_dir)
    except:
        pass
    remote_directives_file = os.path.join(user_dir, 'directives.sh')
    directives_script = '/tmp/directives.sh'
    driver_file = open(remote_directives_file, 'w')
    driver_file.write('sleep 2\n')
    if args.disconnect:
        driver_file.write('/tmp/simics-magic\n')
    file_list = []
    last_io_file = None
    with open(args.directives) as fh:
        for line in fh:
            if line.strip().startswith('#'):
                continue
            if len(line.strip()) == 0:
                continue
            if line.strip().startswith('!'):
                driver_file.write(line[1:]+'\n')
                continue
            parts = line.split()
            if len(parts) == 2 and parts[0] == 'sleep':
                driver_file.write(line)
            elif args.command:
                for p in parts[:-1]:
                    tfile = p.strip()
                    cmd = 'scp -P %d %s  mike@localhost:/tmp/%s' % (sshport, tfile, os.path.basename(tfile))
                    os.system(cmd)
                command = parts[-1].strip()
                cmd = 'scp -P %d %s  mike@localhost:/tmp/' % (sshport, command)
                os.system(cmd)
                directive = 'sudo /tmp/%s' % (command)
                driver_file.write(directive+'\n')

            elif len(parts) == 1:
                ''' multiple data files to be sent, last line will include directive info'''
                iofile = parts[0].strip()
                file_list.append(iofile)
                if iofile != last_io_file:
                    cmd = 'scp -P %d %s  mike@localhost:/tmp/' % (sshport, iofile)
                    os.system(cmd)
                    last_io_file = iofile
            elif not args.tcp and len(parts) != 4 and not args.server and not args.broadcast and not args.replay and not args.json:
                print('Invalid driver directive: %s' % line)
                print('    iofile ip port header')
                exit(1)
            elif args.replay:
                pcap = parts[0].strip()
                interface = parts[1].strip()
                file_list.append(pcap)
                cmd = 'scp -P %d %s  mike@localhost:/tmp/' % (sshport, pcap)
                os.system(cmd)
                pcap_base = os.path.basename(pcap)
                directive = 'sudo /usr/bin/tcpreplay -i %s /tmp/%s' % (interface, pcap_base)
                driver_file.write(directive+'\n')
            else:
                iofile = parts[0]
                file_list.append(iofile)
                ip = parts[1]
                port = parts[2]
                local_ip = ''
                if not args.tcp and not args.server and not args.json:
                    header = parts[3]
                    if args.broadcast:
                        local_ip = parts[4]
                else:
                    header = ''
                flist = ''
                for f in file_list:
                    full = '/tmp/%s' % os.path.basename(f)
                    flist = flist + full + ' '
                directive = '/tmp/%s  %s %s %s %s %s' % (client_cmd, ip, port, local_ip, header, flist)
                driver_file.write(directive+'\n')
                cmd = 'scp -P %d %s  mike@localhost:/tmp/' % (sshport, iofile)
                os.system(cmd)
                file_list = []

    driver_file.close()

    cmd = 'chmod a+x %s' % remote_directives_file
    os.system(cmd)

    cmd = 'scp -P %d %s  mike@localhost:/tmp/' % (sshport, remote_directives_file)
    os.system(cmd)
    cmd = 'ssh -p %d mike@localhost "nohup %s > /tmp/directive.log 2>&1 &"' % (sshport, directives_script)
    os.system(cmd)

if __name__ == '__main__':
    sys.exit(main())
