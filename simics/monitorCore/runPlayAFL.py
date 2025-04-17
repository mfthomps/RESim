#!/usr/bin/env python3
'''
Executable python script to run multiple parallel instances of RESim to play previous
AFL sessions as found in queue files.


'''
import os
import json
import stat
import sys
import subprocess
import argparse
import shlex
import time
import glob
import threading
import select
import aflPath
import resimUtils
def ioHandler(read_array, stop, lgr):
    log = '/tmp/resim.log'
    with open(log, 'wb') as fh:
        while(True):
            if stop():
                print('ioHandler sees stop, exiting.')
                lgr.debug('ioHandler sees stop, exiting.')
                return
            try:
                r, w, e = select.select(read_array, [], [], 10) 
            except ValueError:
                print('select error, must be closed.')
                lgr.debug('select error, must be closed.')
                return
            for item in r:
                try:
                    file_num = item.fileno()
                    data = os.read(file_num, 800)
                except:
                    lgr.debug('read error, must be closed.')
                    return
                if len(data.strip()) == 0:
                    continue
                finfo = str.encode('fnum: %d ' % file_num)
                fh.write(finfo+data+b'\n')
                if 'Error' in str(data):
                    print(data)
                    print("use ctrl-C, fatal error.")
                    exit(1)
                    return
                   

def handleClose(resim_procs, read_array, remote, lgr):
    stop_threads = False
    io_handler = threading.Thread(target=ioHandler, args=(read_array, lambda: stop_threads, lgr))
    io_handler.start()
    total_time = 0
    sleep_time = 4
    lgr.debug('handleClose, wait for all procs')
    for proc in resim_procs:
        proc.wait()
        lgr.debug('proc exited')

    stop_threads = True
    for fd in read_array:
        fd.close()


def runPlay(args, lgr, hits_prefix, full, workspace):
    here= os.path.dirname(os.path.realpath(__file__))
    if args.search_list is None:
        os.environ['ONE_DONE_SCRIPT'] = os.path.join(here, 'onedonePlay.py')
    else:
        os.environ['ONE_DONE_SCRIPT'] = os.path.join(here, 'onedoneSearch.py')
    resim_dir = os.getenv('RESIM_DIR')
    if resim_dir is None:
        print('missing RESIM_DIR envrionment variable')
        exit(1)
    resim_path = os.path.join(resim_dir, 'simics', 'bin', 'resim')
    hostname = aflPath.getHost()
    here = os.getcwd()
    if workspace is not None:
        afl_name = workspace
    else:
        afl_name = os.path.basename(here)
    print('Using afl_name %s' % afl_name)
    lgr.debug('Using afl_name %s' % afl_name)
    resim_procs = []

    if not args.ini.endswith('.ini'):
        args.ini = args.ini+'.ini'
    if not os.path.isfile(args.ini):
        lgr.error('Ini file %s not found.' % args.ini)
        exit(1)

    glist = glob.glob('resim_*/')
    if len(glist) == 0:
        glist = ['./']
    #if args.tcp:
    #    os.environ['ONE_DONE_PARAM']='tcp'
    #else:
    #    os.environ['ONE_DONE_PARAM']='udp'
    if args.only_thread:
        os.environ['ONE_DONE_PARAM2']='True'
    os.environ['ONE_DONE_PARAM3']=args.program
    if args.target is not None:
        os.environ['ONE_DONE_PARAM4']=args.target
    if args.targetFD is not None:
        os.environ['ONE_DONE_PARAM5']=args.targetFD
    os.environ['ONE_DONE_PARAM6']=args.count
    os.environ['ONE_DONE_PARAM7']=str(args.no_page_faults)
    os.environ['ONE_DONE_PARAM8']=str(args.search_list)
    if args.workspace is not None:
        os.environ['ONE_DONE_PARAM9']=args.workspace
         
    cover_list = aflPath.getAFLCoverageList(afl_name, get_all=True)
    print('Found %d files in cover list' % len(cover_list))
    lgr.debug('Found %d files in cover list' % len(cover_list))
    for cfile in cover_list:
        fstat = os.stat(cfile)
        if fstat.st_size == 0:
            os.remove(cfile)
            print('removed zero length %s' % cfile) 

    read_array = []
    if len(glist) > 0:
        lgr.debug('Parallel, doing %d instances' % len(glist))
        print('Parallel, doing %d instances' % len(glist))
        for instance in glist:
            if not os.path.isdir(instance):
                continue
            os.chdir(instance)

            resim_ini = args.ini
            cmd = '%s %s -n' % (resim_path, resim_ini)
            lgr.debug('cmd is %s' % cmd)
            resim_ps = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            resim_procs.append(resim_ps)
            read_array.append(resim_ps.stdout)
            read_array.append(resim_ps.stderr)
            lgr.debug('created resim')
            os.chdir(here)

        handleClose(resim_procs, read_array, args.remote, lgr)

        if args.search_list is None:
            cover_list = aflPath.getAFLCoverageList(afl_name, get_all=True)
            all_hits = []
            for hit_file in cover_list:
                if not os.path.isfile(hit_file):
                    print('did not find %s, old unique file?' % hit_file)
                    continue
                try:
                    coverage = json.load(open(hit_file))
                except:
                    with open(hit_file, 'w'):
                        pass
                    continue 
                print('do hit file %s' % hit_file)
                lgr.debug('runPlayAFL do hit file %s' % hit_file)
                for hit in coverage:
                    hit_i = int(hit)
                    if hit_i not in all_hits:
                        all_hits.append(hit_i)

            hits_file = '%s.%s.hits' % (full, afl_name)

            hits_path = os.path.join(hits_prefix, hits_file)
            os.makedirs(os.path.dirname(hits_path), exist_ok=True)
            s = json.dumps(all_hits)
            with open(hits_path, 'w') as fh:
                fh.write(s)
            print('Wrote hits to %s' % hits_path) 
            lgr.debug('Wrote hits to %s' % hits_path) 
            print('all hits total %d' % len(all_hits))
        else:
            print('Was a search list')
    else:
        print('Nothing to do.')

def main():
    lgr = resimUtils.getLogger('runPlay', '/tmp/', level=None)
    parser = argparse.ArgumentParser(prog='runPlay', description='Run AFL sessions in parallel to collect coverage data.')
    parser.add_argument('ini', action='store', help='The RESim ini file used during the AFL session.')
    parser.add_argument('program', action='store', help='Name of the program that was fuzzed, TBD move to snapshot?')
    #parser.add_argument('-t', '--tcp', action='store_true', help='TCP sessions with potentially multiple packets.')
    parser.add_argument('-r', '--remote', action='store_true', help='Remote run, will wait for /tmp/resim_die.txt before exiting.')
    parser.add_argument('-o', '--only_thread', action='store_true', help='Only track coverage of single thread.')
    parser.add_argument('-T', '--target', action='store', help='Optional name of target process, with optional prefix of target cell followed by colon.')
    parser.add_argument('-F', '--targetFD', action='store', help='Optional file descriptor for moving target to selected recv based on count.')
    parser.add_argument('-C', '--count', action='store', default='1', help='Used with targetFD to advance to nth read before tracking coverage. Defaults to 1.')
    parser.add_argument('-n', '--no_page_faults', action='store_true', help='Do not watch page faults.  Only use when neeed, will miss SEGV.')
    parser.add_argument('-s', '--search_list', action='store', help='Name of file containing search criteria, e.g., to find writes to a range')
    parser.add_argument('-w', '--workspace', action='store', help='Name of the workspace that originated the AFL artifacts (if other than current workspace).')
    try:
        os.remove('/tmp/resim_restart.txt')
    except:
        pass
    args = parser.parse_args()

    ida_data = os.getenv('RESIM_IDA_DATA')

    target_cell = None
    if args.target is not None:
        if ':' in args.target:
            parts = args.target.rsplit(':',1)
            target_cell = parts[0]
    if target_cell is not None:
        root_prefix = resimUtils.getIniTargetValue(args.ini, 'RESIM_ROOT_PREFIX', target=target_cell)
    else:
        root_prefix = resimUtils.getIniTargetValue(args.ini, 'RESIM_ROOT_PREFIX')
    root_name = os.path.basename(root_prefix)
    root_dir = os.path.basename(os.path.dirname(root_prefix))
    hits_prefix = os.path.join(ida_data, root_dir, root_name)
    lgr.debug('runPlayAFL hits_prefix %s' % hits_prefix)
    os.makedirs(hits_prefix, exist_ok=True)
    if '/' in args.program:
        full = args.program
        full_with_prefix = os.path.join(root_prefix, full)
    else:
        full_with_prefix = resimUtils.getFullPath(args.program, args.ini, lgr=lgr)
        if full_with_prefix is None:
            print('ERROR failed to get full path for program %s' % args.program)
            exit(1)
        full = full_with_prefix[len(root_prefix)+1:]
    if not os.path.isfile(full_with_prefix):
        print('ERROR, no file at %s' % full_with_prefix)
        return
    print('Using analysis for program: %s' % full)   
    lgr.debug('runPlayAFL Using analysis for program: %s' % full)   
    runPlay(args, lgr, hits_prefix, full, args.workspace)
  
if __name__ == '__main__':
    sys.exit(main())


