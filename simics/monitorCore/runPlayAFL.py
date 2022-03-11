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
                    data = os.read(item.fileno(), 800)
                except:
                    lgr.debug('read error, must be closed.')
                    return
                fh.write(data+b'\n')
                   

def handleClose(resim_procs, read_array, remote, fifo_list, lgr):
    stop_threads = False
    io_handler = threading.Thread(target=ioHandler, args=(read_array, lambda: stop_threads, lgr))
    io_handler.start()
    total_time = 0
    sleep_time = 4
    do_restart = False
    lgr.debug('handleClose, wait for all procs')
    for proc in resim_procs:
        proc.wait()
        lgr.debug('proc exited')

    stop_threads = True
    for fd in read_array:
        fd.close()
    return do_restart


def runPlay(args, lgr):
    here= os.path.dirname(os.path.realpath(__file__))
    os.environ['ONE_DONE_SCRIPT'] = os.path.join(here, 'onedonePlay.py')
    resim_dir = os.getenv('RESIM_DIR')
    if resim_dir is None:
        print('missing RESIM_DIR envrionment variable')
        exit(1)
    resim_path = os.path.join(resim_dir, 'simics', 'bin', 'resim')
    hostname = aflPath.getHost()

    do_restart = False 
    here = os.getcwd()
    afl_name = os.path.basename(here)
    resim_procs = []

    if not args.ini.endswith('.ini'):
        args.ini = args.ini+'.ini'
    if not os.path.isfile(args.ini):
        lgr.error('Ini file %s not found.' % args.ini)
        exit(1)

    glist = glob.glob('resim_*/')

    if args.tcp:
        os.environ['ONE_DONE_PARAM']='tcp'
    else:
        os.environ['ONE_DONE_PARAM']='udp'

    read_array = []
    fifo_list = []
    if len(glist) > 0:
        lgr.debug('Parallel, doing %d instances' % len(glist))
        print('Parallel, doing %d instances' % len(glist))
        for instance in glist:
            if not os.path.isdir(instance):
                continue
            os.chdir(instance)

            try:
                os.remove('resim_ctl.fifo')
            except:
                pass
            try:
                os.mkfifo('resim_ctl.fifo')
            except OSError as e:
                lgr.debug('fifo create failed %s' % e)    
            resim_ini = args.ini
            cmd = '%s %s -n' % (resim_path, resim_ini)
            lgr.debug('cmd is %s' % cmd)
            resim_ps = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            resim_procs.append(resim_ps)
            read_array.append(resim_ps.stdout)
            read_array.append(resim_ps.stderr)
            if stat.S_ISFIFO(os.stat('resim_ctl.fifo').st_mode):
                lgr.debug('open fifo %s' % os.path.abspath('resim_ctl.fifo'))
                fh = os.open('resim_ctl.fifo', os.O_WRONLY)
                lgr.debug('back from open fifo')
                fifo_list.append(fh)
            else:
                lgr.debug('no fifo found')
            lgr.debug('created resim')
            os.chdir(here)

        do_restart = handleClose(resim_procs, read_array, args.remote, fifo_list, lgr)
        cover_list = aflPath.getAFLCoverageList(afl_name)
        all_hits = []
        for hit_file in cover_list:
            if not os.path.isfile(hit_file):
                print('did not find %s, old unique file?' % hit_file)
                continue
            coverage = json.load(open(hit_file))
            for hit in coverage:
                hit_i = int(hit)
                if hit_i not in all_hits:
                    all_hits.append(hit_i)
        ida_data = os.getenv('RESIM_IDA_DATA')
        hits_file = '%s.%s.hits' % (args.program, afl_name)
        hits_path = os.path.join(ida_data, args.program, hits_file)
        s = json.dumps(all_hits)
        with open(hits_path, 'w') as fh:
            fh.write(s)
        
        print('all hits total %d' % len(all_hits))
    return do_restart

def main():
    lgr = resimUtils.getLogger('runPlayAFL', '/tmp/', level=None)
    parser = argparse.ArgumentParser(prog='runPlayAFL', description='Run AFL sessions in parallel to collect coverage data.')
    parser.add_argument('ini', action='store', help='The RESim ini file used during the AFL session.')
    parser.add_argument('program', action='store', help='Name of the program that was fuzzed, TBD move to snapshot?')
    parser.add_argument('-t', '--tcp', action='store_true', help='TCP sessions with potentially multiple packets.')
    parser.add_argument('-r', '--remote', action='store_true', help='Remote run, will wait for /tmp/resim_die.txt before exiting.')
    try:
        os.remove('/tmp/resim_restart.txt')
    except:
        pass
    args = parser.parse_args()
    do_restart = runPlay(args, lgr)
    time.sleep(20)
    if do_restart:
        print('restarting resim in 10')
        os.remove('/tmp/resim_restart.txt')
        time.sleep(10)
        args.no_afl = True
        do_restart = runPlay(args, lgr)
  
if __name__ == '__main__':
    sys.exit(main())


