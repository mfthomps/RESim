#!/usr/bin/env python3
'''
Send data files to the driver and from there, send them to one or more target IP/ports.
Optionally executes magic instruction 99 just prior to sending data to reset RESim origin,
and disconnects the driver from the system.


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
def keyValue(line):
    key = None
    value = None
    if '=' in line:
        parts = line.split('=', 1)
        key = parts[0].strip()
        value = parts[1].strip()
    else:
        print('bad line %s' % line)
    return key, value
    
class Directive():
    def __init__(self, fname):
        self.device = None
        self.ip = None
        self.port = None
        self.src_ip = None
        self.src_port = None
        self.session = None
        self.header = None
        self.file = []
        self.load(fname)

    def load(self, fname):
        with open(fname) as fh:
            for line in fh:
                if line.strip().startswith('#'):
                    continue
                if len(line.strip()) == 0:
                    continue
                key, value = keyValue(line)
                if key == 'DEVICE':
                    self.device = value
                elif key == 'IP':
                    self.ip = value
                elif key == 'PORT':
                    self.port = value
                elif key == 'SRC_IP':
                    self.src_ip = value
                elif key == 'SRC_PORT':
                    self.src_port = value
                elif key == 'SESSION':
                    self.session = value
                elif key == 'HEADER':
                    self.header = value
                elif key == 'FILE':
                    self.file.append(value)
    def getArgs(self):
        retval = ' --ip %s --port %s' % (self.ip, self.port)
        if self.src_ip is not None:
            retval = retval + ' --src_ip %s' % self.src_ip
        if self.src_port is not None:
            retval = retval + ' --src_port %s' % self.src_port
        if self.device is not None:
            retval = retval + ' --device %s' % self.device
        flist = ' '.join(self.file)
        retval = retval+' --file "%s"' % flist
        return retval
           
def main():
    parser = argparse.ArgumentParser(prog='drive-driver.py', description='Send files to the driver and from there to one or more targets.')
    parser.add_argument('directives', action='store', help='File containing driver directives')
    parser.add_argument('-d', '--disconnect', action='store_true', help='Disconnect driver and set new origin after sending data.')
    parser.add_argument('-b', '--broadcast', action='store_true', help='Use broadcast.')
    parser.add_argument('-x', '--tcpx', action='store_true', help='Use TCP but do not read between writes -- experimental.')
    parser.add_argument('-s', '--server', action='store_true', help='Accept TCP connections from a client, and send the data.')
    parser.add_argument('-p', '--port', action='store', type=int, default=4022, help='Alternate ssh port, default is 4022')
    parser.add_argument('-r', '--replay', action='store_true', help='Treat the directives as PCAPS to be sent via tcpreplay')
    parser.add_argument('-c', '--command', action='store_true', help='The directive simply names a script to be xfered and run from the driver.')
    parser.add_argument('-j', '--json', action='store_true', help='Send UDP packets found in a given json file')
    args = parser.parse_args()
    sshport = args.port
    print('Drive driver22')
    if not os.path.isfile(args.directives):
        print('No file found at %s' % args.directives)
        exit(1)
    directive = Directive(args.directives)

    if args.server:
        client_cmd = 'serverTCP'
    elif directive.session == 'TCP':
        client_cmd = 'clientTCP'
    elif args.replay:
        client_cmd = None
    elif args.broadcast:
        client_cmd = 'clientudpBroad'
    elif args.json:
        if directive.src_ip is not None:
            client_cmd = 'clientudpJsonScapy'
        else:
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

    for file in directive.file:
        cmd = 'scp -P %d %s  mike@localhost:/tmp/' % (sshport, file)
        os.system(cmd)

    args = directive.getArgs()
    directive_line = 'sudo /tmp/%s  %s' % (client_cmd, args)

    driver_file.write(directive_line+'\n')

    driver_file.close()

    cmd = 'chmod a+x %s' % remote_directives_file
    os.system(cmd)
    cmd = 'scp -P %d %s  mike@localhost:/tmp/' % (sshport, remote_directives_file)
    os.system(cmd)
    cmd = 'ssh -p %d mike@localhost "nohup %s > /tmp/directive.log 2>&1 &"' % (sshport, directives_script)
    os.system(cmd)
    print('cmd was %s' % cmd)

if __name__ == '__main__':
    sys.exit(main())
