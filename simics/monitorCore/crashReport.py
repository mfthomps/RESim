#!/usr/bin/env python3
'''
Executable program for generating crash reports by starting/stopping
RESim for each crash.
'''
import os
import sys
import glob
import subprocess
import shutil
try:
    import ConfigParser
except:
    import configparser as ConfigParser
import threading
import time
import argparse
import aflPath
'''
Create crash reports for a given AFL target.
This is an example of a script that repeatedly starts
RESim (and thus Simics) to handle multi-packet udp crash
analysis.  
'''
def feedDriver(ip, port, header, client_path, magic_path, tcp):
    ''' Use the given script (assume drive_driver) to send data found in /tmp/sendfile'''
    print('feedDriver')

    tcp_flag = ''
    if tcp:
        tcp_flag = '-t'
    if header is None:
        header = ''
    line = '/tmp/sendfile %s %d %s' % (ip, port, header)
    cmd = '%s %s /tmp/directive' % (client_path, tcp_flag)
    print('cmd is %s' % cmd)
    result = os.system(cmd)

def main():
    here= os.path.dirname(os.path.realpath(__file__))
    client_path = os.path.join(os.path.dirname(here),'bin', 'drive-driver.py')
    print('Client path is %s' % client_path)
    parser = argparse.ArgumentParser(prog='crashReport', description='Generate reports on crashes found by AFL.')
    parser.add_argument('ini', action='store', help='The RESim ini file used during the AFL session.')
    parser.add_argument('target', action='store', help='The afl output directory relative to AFL_OUTPUT in the ini file, or AFL_DATA in bashrc.')
    parser.add_argument('-f', '--fd', action='store', help='FD read by target process.  Needed for driver-based systems, e.g., for multipacket  sessions.')
    parser.add_argument('-d', '--report_dir', action='store', default='/tmp/crash_reports', help='Directory to place crash reports.  Defaults to /tmp/crash_reports.')
    parser.add_argument('-m', '--max_sessions', action='store', type=int, default=-1, help='Stop after this number of sessoins')
    parser.add_argument('-t', '--tcp', action='store_true', help='TCP sessions (only needed if fd is given, i.e., multi-packet')

    args = parser.parse_args()
    resim_ini = args.ini
    target = args.target
    ''' ini file to run in RESim '''
    #resim_ini = sys.argv[1]
    ''' target name, e.g., subdirectory of AFL output directory '''
    #target = sys.argv[2]
    
    ''' If multiple packets are within any of the crashing inputs,
        use a driver and trackIO.
    '''
    trackFD = None
    header = ''
    if args.fd:
        ''' Will use trackIO vice injectIO '''
        trackFD = args.fd
        os.environ['ONE_DONE_PARAM2']=trackFD
        config = ConfigParser.ConfigParser()
        config.read(resim_ini)
        if not config.has_option('ENV', 'TARGET_IP'):
            print('The %s file is missing a TARGET_IP' % resim_ini)
            exit(1)
        if not config.has_option('ENV', 'TARGET_PORT'):
            print('The %s file is missing a TARGET_PORT' % resim_ini)
            exit(1)
        target_ip = config.get('ENV', 'TARGET_IP')
        target_port = int(config.get('ENV', 'TARGET_PORT'))
         
        header = ''
        if config.has_option('ENV', 'AFL_UDP_HEADER'):
            header = config.get('ENV', 'AFL_UDP_HEADER')
            if args.tcp:
                self.lgr.error('TCP switch conflicts with having a UDP header.')
                sys.exit(1)
    
    if os.path.isfile(target):
        ''' single file to report on '''
        flist = [target]
    else:

        crash_list = aflPath.getTargetCrashes(target)
        flist=[]
        for g in crash_list:
            if os.path.basename(g).startswith('id:'):
                flist.append(g)
    
    ''' The script to be called by RESim once it is initialized '''
    os.environ['ONE_DONE_SCRIPT'] = os.path.join(here, 'onedoneCrash.py')
    resim_path = os.path.join(os.getenv('RESIM_DIR'), 'simics', 'bin', 'resim')
    os.environ['ONE_DONE_PARAM3'] = args.report_dir
    already_done = []
    if os.path.isdir(args.report_dir):
        done_list = os.listdir(args.report_dir)
        for f in done_list:
            if 'crash_report' in f:
                path = os.path.join(args.report_dir, f)
                if os.path.isfile(path):
                    with open(path) as fh:
                        for line in fh:
                            if 'Crash report for' in line:
                                qfile = line.split()[-1]
                                already_done.append(qfile)
        
    resim_dir = os.getenv('RESIM_DIR')
    magic_path = os.path.join(resim_dir, 'simics', 'magic', 'simics-magic')
    index = len(already_done)
    count = 0
    print('Found %d crashes to analyze, and %d already done' % (len(flist), len(already_done)))
    for f in sorted(flist):
        if f in already_done:
            print('Already ran %s, skipping' % f)
            continue
        os.environ['ONE_DONE_PATH'] = f
        os.environ['ONE_DONE_PARAM'] = str(index)
        if trackFD is not None:
            shutil.copyfile(f, '/tmp/sendfile')
            driver = threading.Thread(target=feedDriver, args=(target_ip, target_port, header, client_path, magic_path, args.tcp))
            driver.start()
            #os.system('./tmpdrive.sh &')
        print("starting monitor without UI")
        result = os.system('%s %s -n' % (resim_path, resim_ini))
        print('Monitor exited, try next')
        if result != 0:
            exit
    
        index += 1
        count += 1
        print('count is %d  max_sessions %d' % (count, args.max_sessions))
        if args.max_sessions > 0 and count >= args.max_sessions:
            print('Hit max sessions.')
            exit
            break
        
    print('done')

if __name__ == '__main__':
    sys.exit(main())


