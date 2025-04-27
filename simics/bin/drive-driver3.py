#!/usr/bin/env python3
'''
Send data files to the driver and from there, send them to one or more target IP/ports.
Optionally executes magic instruction 99 just prior to sending data to reset RESim origin,
and disconnects the driver from the system.


Directive lines that start with a # are ignored.
'''
import os
import socket
import sys
import subprocess
import argparse
import shlex
resim_dir = os.getenv('RESIM_DIR')
user_name = os.getenv('USER')
core_path=os.path.join(resim_dir,'simics', 'monitorCore')
sys.path.append(core_path)
def expandValue(value): 
    if value.startswith('$'):
        if os.path.sep in value:
            env_var, rest = value.split(os.path.sep,1)
            expanded = os.getenv(env_var[1:])
            if expanded is None:
                print('ERROR***** Could not expand %s' % value)
                return None
            value = os.path.join(expanded, rest)
        else:
            value = os.getenv(value[1:])
    return value
def keyValue(line):
    key = None
    value = None
    if '=' in line:
        parts = line.split('=', 1)
        key = parts[0].strip()
        value = parts[1].strip()
        value = expandValue(value)
        
    else:
        print('bad line %s' % line)
    return key, value

    
def getSocket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return sock

def doCommand(command, sock, target):
    fstr = 'RUN: ' + command  + ' =EOFX='
    sock.sendto(fstr.encode(), target)
    ack, source = sock.recvfrom(3)
    sock.sendto('ack'.encode(), target)

def doBackgroundCommand(command, sock, target):
    fstr = 'RUN_LONG: ' + command  + ' =EOFX='
    sock.sendto(fstr.encode(), target)
    ack, source = sock.recvfrom(3)
    sock.sendto('ack'.encode(), target)

def sendFiles(file_list, sock, target):
    retval = None
    for file in file_list: 
        flen = str(os.path.getsize(file))
        fstr = 'FILE: ' + flen + ' ' + os.path.basename(file) + ' =EOFX='
        print("- Send file: " + file + " (" + flen + ")")
        fstr_encoded = fstr.encode()
        sock.sendto(fstr_encoded, target)
        print('sent header %d bytes' % len(fstr_encoded))
        use_ack = True
        ack, source = sock.recvfrom(3)
        print('got ack of header')
        if ack.decode() == 'ack':
            use_ack = False
            print('Old server, not using UDP acks')
        if retval is None:
            retval = ack
        sock.sendto('ack'.encode(), target)
        print('before send got %s' % str(ack))
        #time.sleep(1)
        pcount = 0
        with open(file, 'rb') as f:
            print('now read')
            fileData = f.read()
            remain = len(fileData)
            ptr = 0
            while remain > 0:
                # Begin sending file
                if remain >= 1024:
                    end = ptr+1024
                    send_this = fileData[ptr:end]
                    remain = remain - 1024
                    ptr = ptr + 1024
                else:
                    end = ptr+remain
                    send_this = fileData[ptr:end]
                    remain = 0 
                print('now send %d bytes' % len(send_this))
                sock.sendto(send_this, target)
                pcount += 1
                if use_ack and pcount % 20 == 0:
                    ack, source = sock.recvfrom(3)
                    print('back from getting ack pcount %d' % pcount)
            sock.sendto('=EOFX='.encode(), target)
            print('sent EOF')
        f.close()
        print('>> Transfer: ' + file + ' complete.\n')
        ack, source = sock.recvfrom(3)
        print('got %s' % str(ack))
    return retval

class Directive():
    def __init__(self, fname):
        self.device = None
        self.ip = None
        self.port = None
        self.src_ip = None
        self.src_port = None
        self.session = None
        self.client = None
        self.header = None
        self.iface = None
        self.file = []
        self.commands = []
        self.hang = False
        self.load(fname)

    def load(self, fname):
        with open(fname) as fh:
            for line in fh:
                if line.strip().startswith('#'):
                    continue
                if len(line.strip()) == 0:
                    continue
                key, value = keyValue(line)
                key = key.upper()
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
                elif key == 'CLIENT':
                    self.client = value
                elif key == 'HEADER':
                    self.header = value
                elif key == 'FILE':
                    self.file.append(value)
                elif key == 'COMMAND':
                    self.commands.append(value)
                elif key == 'IFACE':
                    self.iface = value
                elif key == 'HANG':
                    if value.lower() in ['true', 'yes']:
                        self.hang = True
    def getArgs(self):
        retval = ' --ip %s --port %s' % (self.ip, self.port)
        if self.src_ip is not None:
            retval = retval + ' --src_ip %s' % self.src_ip
        if self.src_port is not None:
            retval = retval + ' --src_port %s' % self.src_port
        if self.device is not None:
            retval = retval + ' --device %s' % self.device
        if self.header is not None:
            retval = retval + ' --header %s' % self.header
        if self.hang:
            retval = retval + ' --hang'
        farg = ''
        for f in self.file:
            farg = farg + ' /tmp/%s' % os.path.basename(f)
        retval = retval+' --file "%s"' % farg.strip()
        return retval

def main():
    parser = argparse.ArgumentParser(prog='drive-driver.py', description='Send files to the driver and from there to one or more targets.')
    parser.add_argument('directives', action='store', help='File containing driver directives')
    parser.add_argument('-d', '--disconnect', action='store_true', help='Disconnect driver and set new origin after sending data.')
    parser.add_argument('-p', '--port', action='store', type=int, default=4022, help='Alternate ssh port, default is 4022')
    parser.add_argument('-w', '--wait_restart', action='store_true', help='Wait for the driver to restart, assumes a replace.directive')
    args = parser.parse_args()
    sshport = args.port
    print('Drive driver')
    if not os.path.isfile(args.directives):
        print('No file found at %s' % args.directives)
        exit(1)
    directive = Directive(args.directives)

    sock = getSocket()
    host = 'localhost'
    PORT = 6459
    target = (host, PORT)
    client_cmd = None
    # NOTE client_cmd defaults to clientudpMult3, unless replay
    if directive.session is not None:
        if directive.session.lower() == 'servertcp':
            client_cmd = 'serverTCP3'
        elif directive.session.lower() == 'tcp':
            client_cmd = 'clientTCP3'
        elif directive.session.lower() == 'udp_json':
            if directive.src_ip is not None:
                client_cmd = 'clientudpJsonScapy'
            else:
                client_cmd = 'clientudpJson'
        elif directive.session.lower() == 'tcp_json':
            client_cmd = 'clientTCPJson'
        elif directive.session.lower() == 'client':
            client_cmd = directive.client
        elif directive.session.lower() not in ['replay', 'command']:
            client_cmd = 'clientudpMult3'
        if client_cmd is not None:
            if directive.client is not None:
                client_path = directive.client
            else:
                client_path = os.path.join(core_path, client_cmd)
            sendFiles([client_path], sock, target)
            cmd='/bin/chmod a+x /tmp/%s' % client_cmd
            doCommand(cmd, sock, target)
    if args.disconnect:
        magic_path = os.path.join(resim_dir, 'simics', 'magic', 'simics-magic')
        sendFiles([magic_path], sock, target)

    udir = os.path.join('/tmp', user_name)
    print('udir is %s' % udir)
    try:
        os.mkdir(udir)
    except:
        pass
    remote_directives_file = os.path.join(udir, 'directives.sh')
    print('remote_directives_file is %s' % remote_directives_file)

    directives_script = '/tmp/directives.sh'
    driver_file = open(remote_directives_file, 'w')
    driver_file.write('#!/bin/bash\n')
    if args.disconnect:
        driver_file.write('chmod a+x /tmp/simics-magic\n')
        driver_file.write('/tmp/simics-magic\n')
    file_list = []
    for file in directive.file:
        file_list.append(file)
    ack = sendFiles(file_list, sock, target)
    if ack is not None:
        with open('.driver_server_version', 'w') as fh:
            fh.write(ack.decode())
    dev = None
    host = None
    if directive.iface is not None:
        if ':' in directive.iface:
            dev, host = directive.iface.split(':')
            cmd = 'ip addr add %s dev %s' % (host, dev)
            driver_file.write(cmd+'\n')
            cmd = 'ip link set dev %s up' % dev
            driver_file.write(cmd+'\n')

    direct_args = directive.getArgs()
    print('direct_args %s' % direct_args)
    if directive.session is not None:
        if client_cmd is not None:
            directive_line = 'sudo /tmp/%s  %s' % (client_cmd, direct_args)
            driver_file.write(directive_line+'\n')
        elif directive.session.lower() == 'replay':
            if directive.device is not None:
                for pcap in directive.file:
                    pcap_base = os.path.basename(pcap)
                    directive_line = 'sudo /usr/bin/tcpreplay -i %s /tmp/%s' % (directive.device, pcap_base)
                    driver_file.write(directive_line+'\n')
            else:
                print('The replay directive needs an DEVICE value as the source device for tcpreplay.')
                exit(1)
    for command in directive.commands:
        driver_file.write(command+'\n')

    driver_file.close()
    sendFiles([remote_directives_file], sock, target)
    cmd = '/bin/chmod a+x /tmp/%s' % os.path.basename(remote_directives_file)
    doCommand(cmd, sock, target)
    cmd = '%s > /tmp/directive.log 2>&1 &' % directives_script
    #doBackgroundCommand(cmd, sock)
    doCommand(cmd, sock, target)
    print('cmd was %s' % cmd)

    if args.wait_restart:
        print('Wait for restart')
        ack, source = sock.recvfrom(3)
        print('Got ack from restart')
    print('Close sock.')
    sock.close()
    print('Done.')

if __name__ == '__main__':
    sys.exit(main())
