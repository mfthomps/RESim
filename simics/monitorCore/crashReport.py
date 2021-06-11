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
'''
Create crash reports for a given AFL target.
This is an example of a script that repeatedly starts
RESim (and thus Simics) to handle multi-packet udp crash
analysis.  
'''
here= os.path.dirname(os.path.realpath(__file__))
client_path = os.path.join(here, 'clientudpMult')
print('Client path is %s' % client_path)
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

''' ini file to run in RESim '''
resim_ini = sys.argv[1]
''' target name, e.g., subdirectory of AFL output directory '''
target = sys.argv[2]

''' If multiple packets are within any of the crashing inputs,
    use a driver and trackIO.
'''
trackFD = None
header = ''
if len(sys.argv) > 3:
    ''' Will use trackIO vice injectIO '''
    trackFD = sys.argv[3]
    os.environ['ONE_DONE_PARAM2']=trackFD
    config = ConfigParser.ConfigParser()
    config.read(resim_ini)
    target_ip = config.get('ENV', 'TARGET_IP')
    target_port = int(config.get('ENV', 'TARGET_PORT'))
    header = config.get('ENV', 'AFL_UDP_HEADER')
    if target_ip is None:
        print('The %s file is missing a TARGET_IP' % resim_ini)
        exit(1)
    if header is None:
        header = ''

if os.path.isfile(target):
    flist = [target]
else:
    ''' path to AFL output directory '''
    afl_output = os.path.join(os.getenv('HOME'), 'SEED','afl','afl-output')
    afl_dir = os.path.join(afl_output, target)
    if not os.path.isdir(afl_dir):
       print('No afl directory found at %s' % afl_dir)
       exit
    
    
    ''' Get all crash files '''
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

index=0
for f in sorted(flist):
    os.environ['ONE_DONE_PATH'] = f
    os.environ['ONE_DONE_PARAM'] = str(index)
    if trackFD is not None:
        shutil.copyfile(f, '/tmp/sendudp')
        driver = threading.Thread(target=feedDriver, args=(target_ip, target_port, header, ))
        driver.start()
        #os.system('./tmpdrive.sh &')
    print("starting monitor")
    result = os.system('./monitor.sh %s' % resim_ini)
    print('Monitor exited, try next')
    if result != 0:
        exit

    index += 1
print('done')
