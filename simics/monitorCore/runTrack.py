#!/usr/bin/env python
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
import ConfigParser
import threading
import time
import argparse
import json
import aflPath
import resim_utils
'''
'''

def main():
    lgr = resim_utils.getLogger('runTrack', '/tmp/', level=None)
    here= os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(prog='runTrack', description='Run injectIO on all sessions in a target found by AFL.')
    parser.add_argument('ini', action='store', help='The RESim ini file used during the AFL session.')
    parser.add_argument('target', action='store', help='The afl output directory relative to AFL_OUTPUT in the ini file, or AFL_DATA in bashrc.')
    
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
    
        afl_output = aflPath.getAFLOutput()
        target = target
        afl_dir = os.path.join(afl_output, target)
        unique_path = os.path.join(afl_dir, target+'.unique')
        print('TrackAFL, NOTE will only play the first packet.  Paths from %s' % unique_path)
        if os.path.isfile(unique_path):
            cover_list = json.load(open(unique_path))
            for path in cover_list:
                base = os.path.basename(path)
                grand = os.path.dirname(os.path.dirname(path))
                new = os.path.join(grand, 'queue', base)
                afl_list.append(new)
            lgr.debug('trackAFL found unique file at %s, %d entries' % (unique_path, len(afl_list)))
        else:
            gpath = os.path.join(afl_dir, 'resim_*', 'queue', 'id:*')
            glist = glob.glob(gpath)
            if len(glist) > 0:
                for path in glist:
                    if 'sync:' not in path:
                        afl_list.append(path)
            else:
                if os.path.isdir(afl_dir):
                    afl_list = [f for f in os.listdir(afl_dir) if os.path.isfile(os.path.join(afl_dir, f))]

    ''' The script to be called by RESim once it is initialized '''
    os.environ['ONE_DONE_SCRIPT'] = os.path.join(here, 'onedoneTrack.py')
    resim_path = os.path.join(os.getenv('RESIM_DIR'), 'simics', 'bin', 'resim')
    
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
        if not os.path.isfile(trackoutput):
            os.environ['ONE_DONE_PARAM'] = trackoutput
            print("starting monitor without UI")
            result = os.system('%s %s -n' % (resim_path, resim_ini))
            print('Monitor exited, try next')
            if result != 0:
                exit
    
    print('done')

if __name__ == '__main__':
    sys.exit(main())


