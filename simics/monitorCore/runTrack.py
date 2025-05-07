#!/usr/bin/env python3
'''
Executable program for running injectIO for all AFL queue sessions by starting/stopping
RESim for each session.  This permits multi-packet replays which would otherwise corrupt
the origin bookmark if run repeatedly in a single Simics session.
Multiple instances of this program may be started.  Each looks at all queue files
and uses simple file exclusive create for locking.
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
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'fuzz_bin'))
import find_new_states

global stop_threads
def handler(signum, frame):
    global stop_threads
    print('sig handler with %d' % signum)
    stop_threads = True

def oneTrack(file_list, resim_path, resim_ini, only_thread, no_page_faults, max_marks, target, targetFD, trace_all, stop_threads, lgr, instance_path, file_path):
    if instance_path is not None:
        os.chdir(instance_path)
    here = os.getcwd()
    working_dir = os.path.basename(here)
    log = '/tmp/resim-%s.log' % working_dir
    lgr.debug('oneTrack, working_dir: %s will log to %s length of file_list %d' % (working_dir, log, len(file_list)))
    if only_thread:
        os.environ['ONE_DONE_PARAM2']='True'
    count = 0
    if no_page_faults:
        os.environ['ONE_DONE_PARAM3']='True'
    if max_marks is not None:
        os.environ['ONE_DONE_PARAM4']=max_marks
    if target is not None:
        os.environ['ONE_DONE_PARAM5']=target
    if trace_all:
        os.environ['ONE_DONE_PARAM6']='True'
    if targetFD is not None:
        os.environ['ONE_DONE_PARAM7']=targetFD
    track_blacklist = aflPath.getTrackBlacklist(file_path)
    with open(log, 'wb') as fh:
        for f in file_list:
            #os.chdir(here)
            lgr.debug('oneTrack, f: %s' % f)
            now_here = os.getcwd()
            lgr.debug('oneTrack, here: %s, cwd says %s' % (here, now_here))
            os.environ['ONE_DONE_PATH'] = f
            base = os.path.basename(f)
            pdir = os.path.dirname(f)
            tdir = os.path.dirname(pdir)
            ntdir  = os.path.dirname(tdir)
            lgr.debug('tdir %s ntdir %s' % (tdir, ntdir))
            if os.path.basename(pdir) == 'manual_queue':
                if trace_all:
                    trackdir = os.path.join(tdir, 'manual_trace')
                else:
                    trackdir = os.path.join(tdir, 'manual_trackio')
            else:
                if trace_all:
                    trackdir = os.path.join(tdir, 'trace')
                else:
                    trackdir = os.path.join(tdir, 'trackio')
            try:
                #trackdir=os.path.join(here,"watch_script/trackio")
                os.mkdir(trackdir)
            except:
                pass
            trackoutput = os.path.join(trackdir, base)
            if trackoutput in track_blacklist:
                lgr.debug('%s path in blacklist, skip it %s' % (working_dir, trackoutput))
                continue
            if os.path.isfile(trackoutput):
                lgr.debug('%s path exists, skip it %s' % (working_dir, trackoutput))
                continue
            try:
                os.open(trackoutput, os.O_CREAT | os.O_EXCL)
            except:
                continue
            lgr.debug('path for %s is %s' % (working_dir, f))
    
            os.environ['ONE_DONE_PARAM'] = trackoutput
            #result = os.system('%s %s -n' % (resim_path, resim_ini))
            cmd = '%s %s -n' % (resim_path, resim_ini)
            now_here = os.getcwd()
            count = count + 1
            print("%s: starting monitor from %s count %d" % (working_dir, now_here, count))
            lgr.debug("%s: starting monitor from %s count %d" % (working_dir, now_here, count))
            resim_ps = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=fh,stderr=fh)
            resim_ps.wait()
            if stop_threads():
                print('oneTrack sees stop, exiting.')
                lgr.debug('oneTrack %s sees stop, exiting.' % working_dir)
                return
        
        print('done with %s' % working_dir)

def main():
    global stop_threads
    here = os.getcwd()
    working_dir = os.path.basename(here)
    log_name = 'runTrack-%s' % working_dir
    lgr = resimUtils.getLogger(log_name, '/tmp/', level=None)
    script_path= os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(prog='runTrack', description='Run injectIO on all sessions found by AFL.')
    parser.add_argument('ini', action='store', help='The RESim ini file used during the AFL session.')
    parser.add_argument('-d','--directory', action='store', help='Optional seedfile directory in the workspace for use in auto generation of seeds based on tracked string comparisons.')
    parser.add_argument('-w','--workspace', action='store', help='The afl output directory relative to AFL_OUTPUT in the ini file, or AFL_DATA in bashrc (often the Simics workspace.) Optionally a single file to be processed for testing.')
    parser.add_argument('-o', '--only_thread', action='store_true', help='Only track references of single thread.')
    parser.add_argument('-n', '--no_page_faults', action='store_true', help='Do not watch page faults.  Only use when needed, will miss SEGV.')
    parser.add_argument('-m', '--max_marks', action='store', help='Optional maximum watch marks to record before stopping simulation.')
    parser.add_argument('-T', '--target', action='store', help='Optional name of target process, may have prefix of cell name followed by a colon.')
    parser.add_argument('-F', '--targetFD', action='store', help='File descriptor for use if target is provided.')
    parser.add_argument('-t', '--trace_all', action='store_true', help='Do not track, trace all system calls.')
    
    args = parser.parse_args()
    resim_ini = args.ini
    workspace = args.workspace
    seedfiles = args.directory
    if workspace is None and seedfiles is None:
        print("Please enter a workspace name (-w workspace) for an afl session or a directory in the workspace (-d new_iofiles) with new io files")
        lgr.debug("Please enter a workspace name (-w workspace) for an afl session or a directory in the workspace (-d new_iofiles) with new io files")
        sys.exit()

    ''' If multiple packets are within any of the crashing inputs,
        use a driver and trackIO.
    '''
    trackFD = None
    file_list = [] 

    # Check if the input is a seedfile directory or an afl workspace 
    if seedfiles is None:
        # Is either an AFL workspace or a single file
        file_path = aflPath.getTargetPath(workspace)
        if os.path.isfile(workspace):
            # single file to report on 
            lgr.debug('runTrack single file %s' % workspace)
            file_list = [workspace]
        else:
            #file_list = aflPath.getTargetQueue(target, ws_filter=workspace)
            if workspace.startswith('next_ws_'):
                # Auto fuzz workspaces
                file_list = find_new_states.queueFilesForWS(workspace)
            else:
                file_list = aflPath.getTargetQueue(workspace)
            if len(file_list) == 0:
                lgr.error('runTrack no queue files found for workspace %s' % workspace)
                return
            lgr.debug('runTrack file list from %s len %d' % (workspace, len(file_list)))
        # remove any empty or corrupt track jsons 
        track_list = aflPath.getAFLTrackList(workspace, ws_filter=working_dir)
        for track_file in track_list:
            if os.path.isfile(track_file):
                with open(track_file) as fh:
                    try:
                        jfile = json.load(fh)
                    except:
                        print('removing empty or corrupt file %s' % track_file)
                        os.remove(track_file) 
    else:
        file_path = os.path.join(here,seedfiles) 
        seed_list = os.listdir(file_path)
        for seed in seed_list:
            file_list.append(os.path.join(file_path,seed))
    ''' The script to be called by RESim once it is initialized '''
    os.environ['ONE_DONE_SCRIPT'] = os.path.join(script_path, 'onedoneTrack.py')
    resim_path = os.path.join(os.getenv('RESIM_DIR'), 'simics', 'bin', 'resim')
    thread_list = []
    stop_threads=False
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    lgr.debug('runTrack create thread')
    track_thread = threading.Thread(target=oneTrack, args=(file_list, resim_path, resim_ini, args.only_thread, args.no_page_faults, 
          args.max_marks, args.target, args.targetFD, args.trace_all, lambda: stop_threads, lgr, None, file_path))
    thread_list.append(track_thread)
    track_thread.start()
   
    lgr.debug('Wait for threads to finish')
    for thread in thread_list:
        thread.join()     

if __name__ == '__main__':
    sys.exit(main())


