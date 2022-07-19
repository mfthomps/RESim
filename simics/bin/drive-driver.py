#!/usr/bin/env python3
'''
Send data files to the driver and from there, send them to one or more target IP/ports.
Executes magic instruction 99 just prior to sending data to reset RESim origin.


directive file example:
    some.io 171.10.0.1  29121

Or, multiwrite TCP (with read between them):
    first.io
    second.io  171.10.0.1 29121
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
    parser.add_argument('-n', '--no_magic', action='store_true', help='Do not execute magic instruction.')
    parser.add_argument('-t', '--tcp', action='store_true', help='Use TCP.')
    parser.add_argument('-p', '--port', action='store', type=int, default=4022, help='Alternate ssh port, default is 4022')
    args = parser.parse_args()
    sshport = args.port
    print('Drive driver')
    if not os.path.isfile(args.directives):
        print('No file found at %s' % args.directives)
        exit(1)
    if args.tcp:
        client_cmd = 'clientTCP'
    else:
        client_cmd = 'clientudpMult'
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
    exit
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
    if not args.no_magic:
        driver_file.write('/tmp/simics-magic\n')
    file_list = []
    with open(args.directives) as fh:
        for line in fh:
            if line.strip().startswith('#'):
                continue
            if len(line.strip()) == 0:
                continue
            parts = line.split()
            if len(parts) == 2 and parts[0] == 'sleep':
                driver_file.write(line)
            #if args.tcp and len(parts) != 3:
            #    print('Invalid TCP driver directive: %s' % line)
            #    print('    iofile ip port')
            #    exit(1)
            elif len(parts) == 1:
                iofile = parts[0].strip()
                file_list.append(iofile)
                cmd = 'scp -P %d %s  mike@localhost:/tmp/' % (sshport, iofile)
                os.system(cmd)
            elif not args.tcp and len(parts) != 4:
                print('Invalid driver directive: %s' % line)
                print('    iofile ip port header')
                exit(1)
            else:
                iofile = parts[0]
                file_list.append(iofile)
                ip = parts[1]
                port = parts[2]
                if not args.tcp:
                    header = parts[3]
                else:
                    header = ''
                flist = ''
                for f in file_list:
                    full = '/tmp/%s' % os.path.basename(f)
                    flist = flist + full + ' '
                directive = '/tmp/%s  %s %s %s %s' % (client_cmd, ip, port, header, flist)
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
