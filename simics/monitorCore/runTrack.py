#!/usr/bin/env python3
'''
Executable program for running injectIO for all AFL queue sessions by starting/stopping
RESim for each session.  This permits multi-packet replays which would otherwise corrupt
the origin bookmark if run repeatedly in a single Simics session.
'''
import os
import sys
import glob
import subprocess
import shutil
import threading
import signal
try:
    import ConfigParser
except:
    import configparser as ConfigParser
import threading
import time
import argparse
import json
import select
import shlex
import aflPath
import resimUtils
'''
'''
global stop_threads
def handler(signum, frame):
    global stop_threads
    print('sig handler with %d' % signum)
    stop_threads = True

def oneTrack(afl_list, resim_path, resim_ini, only_thread, stop_threads, lgr):
    here = os.getcwd()
    workspace = os.path.basename(here)
    log = '/tmp/resim-%s.log' % workspace
    if only_thread:
        os.environ['ONE_DONE_PARAM2']='True'
    with open(log, 'wb') as fh:
        for f in afl_list:
            os.environ['ONE_DONE_PATH'] = f
            base = os.path.basename(f)
            tdir = os.path.dirname(os.path.dirname(f))
            trackdir = os.path.join(tdir, 'trackio')
            try:
                os.mkdir(trackdir)
            except:
                pass
            trackoutput = os.path.join(tdir, 'trackio', base)
            if os.path.isfile(trackoutput):
                lgr.debug('path exists, skip it %s' % trackoutput)
                continue
            try:
                os.open(trackoutput, os.O_CREAT | os.O_EXCL)
            except:
                continue
            lgr.debug('path for %s is %s' % (workspace, f))
    
            os.environ['ONE_DONE_PARAM'] = trackoutput
            #result = os.system('%s %s -n' % (resim_path, resim_ini))
            cmd = '%s %s -n' % (resim_path, resim_ini)
            print("starting monitor without UI cmd: %s" % cmd)
            lgr.debug("%s starting monitor without UI cmd: %s" % (workspace, cmd))
            resim_ps = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=fh,stderr=fh)
            resim_ps.wait()
            if stop_threads():
                print('oneTrack sees stop, exiting.')
                lgr.debug('oneTrack %s sees stop, exiting.' % workspace)
                return
        
        print('done')

def main():
    global stop_threads
    lgr = resimUtils.getLogger('runTrack', '/tmp/', level=None)
    here= os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(prog='runTrack', description='Run injectIO on all sessions in a target found by AFL.')
    parser.add_argument('ini', action='store', help='The RESim ini file used during the AFL session.')
    parser.add_argument('target', action='store', help='The afl output directory relative to AFL_OUTPUT in the ini file, or AFL_DATA in bashrc.')
    parser.add_argument('-o', '--only_thread', action='store_true', help='Only track references of single thread.')
    
    args = parser.parse_args()
    resim_ini = args.ini
    target = args.target
    
    ''' If multiple packets are within any of the crashing inputs,
        use a driver and trackIO.
    '''
    trackFD = None
    afl_list = [] 
    if os.path.isfile(target):
        ''' single file to report on '''
        afl_list = [target]
    else:
        afl_list = aflPath.getTargetQueue(target)

    ''' remove any empty or corrupt track jsons '''
    track_list = aflPath.getAFLTrackList(target)
    for track_file in track_list:
        if os.path.isfile(track_file):
            with open(track_file) as fh:
                try:
                    jfile = json.load(fh)
                except:
                    print('removing empty or corrupt file %s' % track_file)
                    os.remove(track_file) 

    ''' The script to be called by RESim once it is initialized '''
    os.environ['ONE_DONE_SCRIPT'] = os.path.join(here, 'onedoneTrack.py')
    resim_path = os.path.join(os.getenv('RESIM_DIR'), 'simics', 'bin', 'resim')
    glist = glob.glob('resim_*/')
    thread_list = []
    stop_threads=False
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    here = os.getcwd()
    if len(glist) > 0: 
        print('Parallel, doing %d instances' % len(glist))
        for instance in glist:
            if not os.path.isdir(instance):
                continue
            os.chdir(instance)
            lgr.debug('start oneTrack from workspace %s' % instance)
            track_thread = threading.Thread(target=oneTrack, args=(afl_list, resim_path, resim_ini, args.only_thread, lambda: stop_threads, lgr))
            thread_list.append(track_thread)
            track_thread.start()
            os.chdir(here)
    else:
        track_thread = threading.Thread(target=oneTrack, args=(afl_list, resim_path, resim_ini, args.only_thread, lambda: stop_threads, lgr))
        thread_list.append(track_thread)
        track_thread.start()
   
    lgr.debug('Wait for threads to finish')
    for thread in thread_list:
        thread.join()     

if __name__ == '__main__':
    sys.exit(main())


