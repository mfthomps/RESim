#!/usr/bin/env python
'''
Executable program for generating crash reports by starting/stopping
RESim for each crash.
'''
import os
import sys
import glob
import subprocess
import shutil
import ConfigParser
import threading
import time
import argparse
'''
Create crash reports for a given AFL target.
This is an example of a script that repeatedly starts
RESim (and thus Simics) to handle multi-packet udp crash
analysis.  
'''
def feedDriver(ip, port, header):
    result = 1
    cmd = 'scp -P 4022 /tmp/sendudp localhost:/tmp/sendudp'
    while result != 0:
        result = os.system(cmd)
        if result != 0:
            print('driver not responding')
            time.sleep(1)
    
    cmd = 'scp -P 4022 %s localhost:/tmp/' % client_path
    result = os.system(cmd)
    cmd = 'ssh -p 4022 mike@localhost chmod a+x /tmp/clientudpMult'
    result = os.system(cmd)
    cmd = 'ssh -p 4022 mike@localhost /tmp/clientudpMult %s %d %s' % (ip, port, header)
    result = os.system(cmd)

def main():
    here= os.path.dirname(os.path.realpath(__file__))
    client_path = os.path.join(here, 'clientudpMult')
    print('Client path is %s' % client_path)
    parser = argparse.ArgumentParser(prog='crashReport', description='Generate reports on crashes found by AFL.')
    parser.add_argument('ini', action='store', help='The RESim ini file used during the AFL session.')
    parser.add_argument('target', action='store', help='The afl output directory relative to AFL_OUTPUT in the ini file, or AFL_DATA in bashrc.')
    parser.add_argument('-f', '--fd', action='store', help='FD read by target process.  Needed for driver-based systems, e.g., for multipacket  sessions.')

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
    
    if os.path.isfile(target):
        ''' single file to report on '''
        flist = [target]
    else:
        ''' path to AFL output directory '''
        afl_output = os.getenv('AFL_OUTPUT')
        if afl_output is None:
            afl_output = os.getenv('AFL_DATA')
            afl_dir = os.path.join(afl_output, 'output', target)
        else:
            afl_dir = os.path.join(afl_output, target)
        if not os.path.isdir(afl_dir):
           print('No afl directory found at %s' % afl_dir)
           exit
        
        
        ''' Get all crash files '''
        gmask = afl_dir+'/resim_*/crashes/*'
        glist = glob.glob(gmask)
        if len(glist) == 0:
            ''' not parallel '''
            crashes_dir = os.path.join(afl_dir, 'crashes*')
            gmask = '%s/*' % crashes_dir
            print("ReportCrash gmask: %s" % gmask)
            glist = glob.glob(gmask)
        flist=[]
        for g in glist:
            if os.path.basename(g).startswith('id:'):
                flist.append(g)
    
    ''' The script to be called by RESim once it is initialized '''
    os.environ['ONE_DONE_SCRIPT'] = os.path.join(here, 'onedoneCrash.py')
    resim_path = os.path.join(os.getenv('RESIM_DIR'), 'simics', 'bin', 'resim')
    
    index=0
    for f in sorted(flist):
        os.environ['ONE_DONE_PATH'] = f
        os.environ['ONE_DONE_PARAM'] = str(index)
        if trackFD is not None:
            shutil.copyfile(f, '/tmp/sendudp')
            driver = threading.Thread(target=feedDriver, args=(target_ip, target_port, header, ))
            driver.start()
            #os.system('./tmpdrive.sh &')
        print("starting monitor without UI")
        result = os.system('%s %s -n' % (resim_path, resim_ini))
        print('Monitor exited, try next')
        if result != 0:
            exit
    
        index += 1
    print('done')

if __name__ == '__main__':
    sys.exit(main())


