#!/usr/bin/env python3
'''
Send data files to the driver and from there, send them to one or more target IP/ports.
Executes magic instruction 99 just prior to sending data to reset RESim origin.
'''
import os
import socket
import sys
import subprocess
import argparse
import shlex
resim_dir = os.getenv('RESIM_DIR')
core_path=os.path.join(resim_dir,'simics', 'monitorCore')
sys.path.append(core_path)
import runAFL
import resimUtils
def main():
    parser = argparse.ArgumentParser(prog='drive-driver.py', description='Send files to the driver and from there to one or more targets.')
    parser.add_argument('directives', action='store', help='File containing driver directives')
    parser.add_argument('-n', '--no_magic', action='store_true', help='Do not execute magic instruction.')
    args = parser.parse_args()
    if not os.path.isfile(args.directives):
        print('No file found at %s' % args.directives)
        exit(1)
    client_mult_path = os.path.join(core_path, 'clientudpMult')

    cmd = 'scp -P 4022 %s  localhost:/tmp/' % client_mult_path
    os.system(cmd)

    magic_path = os.path.join(resim_dir, 'simics', 'magic', 'simics-magic')
    cmd = 'scp -P 4022 %s  localhost:/tmp/' % magic_path
    os.system(cmd)

    remote_directives_file = '/tmp/directives.sh'
    driver_file = open(remote_directives_file, 'w')
    driver_file.write('sleep 2\n')
    if not args.no_magic:
        driver_file.write('/tmp/simics-magic\n')
    with open(args.directives) as fh:
        for line in fh:
            if line.strip().startswith('#'):
                continue
            parts = line.split()
            if len(parts) == 2 and parts[0] == 'sleep':
                driver_file.write(line)
            elif len(parts) != 4:
                print('Invalid driver directive: %s' % line)
                print('    iofile ip port header')
                exit(1)
            else:
                iofile = parts[0]
                ip = parts[1]
                port = parts[2]
                header = parts[3]
                base = os.path.basename(iofile)
                directive = '/tmp/clientudpMult  %s %s %s /tmp/%s' % (ip, port, header, base)
                driver_file.write(directive+'\n')
                cmd = 'scp -P 4022 %s  localhost:/tmp/' % iofile
                os.system(cmd)

    driver_file.close()

    cmd = 'chmod a+x %s' % remote_directives_file
    os.system(cmd)

    cmd = 'scp -P 4022 %s  localhost:/tmp/' % remote_directives_file
    os.system(cmd)
    cmd = 'ssh -p 4022 mike@localhost "nohup %s > /dev/null 2>&1 &"' % remote_directives_file
    os.system(cmd)

if __name__ == '__main__':
    sys.exit(main())
