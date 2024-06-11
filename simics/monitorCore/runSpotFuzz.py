#!/usr/bin/env python3
'''
Executable python script to run multiple parallel instances of RESim for spot fuzzing


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
                file_num = item.fileno()
                try:
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
            if os.path.isfile('/tmp/spot_fuzz_done'):
                print('someone said spot fuzz done')
                return
                   

def handleClose(resim_procs, read_array, lgr):
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


def runSpot(args, lgr):
    here= os.path.dirname(os.path.realpath(__file__))
    os.environ['ONE_DONE_SCRIPT'] = os.path.join(here, 'onedoneSpotFuzz.py')
    resim_dir = os.getenv('RESIM_DIR')
    if resim_dir is None:
        print('missing RESIM_DIR envrionment variable')
        exit(1)
    resim_path = os.path.join(resim_dir, 'simics', 'bin', 'resim')
    hostname = aflPath.getHost()

    here = os.getcwd()
    afl_name = os.path.basename(here)
    resim_procs = []

    if not args.ini.endswith('.ini'):
        args.ini = args.ini+'.ini'
    if not os.path.isfile(args.ini):
        lgr.error('Ini file %s not found.' % args.ini)
        exit(1)

    glist = glob.glob('resim_*/')
    if len(glist) == 0:
        glist = ['./']
    os.environ['ONE_DONE_PARAM']=args.address
    os.environ['ONE_DONE_PARAM2']=str(args.data_length)
    os.environ['ONE_DONE_PARAM3']=str(args.breakpoint)
    os.environ['ONE_DONE_PARAM4']=json.dumps(args.fail_break)

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

        handleClose(resim_procs, read_array, lgr)

def auto_int(x):
    return int(x, 0)

def main():
    lgr = resimUtils.getLogger('runSpotFuzz', '/tmp/', level=None)
    parser = argparse.ArgumentParser(prog='runSpotFuzz', description='Run spotFuzz in parallel.')
    parser.add_argument('ini', action='store', help='The RESim ini file.')
    parser.add_argument('address', action='store', help='Address of data to fuzz.')
    parser.add_argument('breakpoint', action='store', help='breakpoint we want to hit.')
    parser.add_argument('-l', '--data_length', action='store', type=int, default=4, help='Optional data length, defaults to 4.')
    parser.add_argument('-f', '--fail_break', nargs="+", action='store', type=auto_int, help='fail breakpoint.')
    args = parser.parse_args()


    runSpot(args, lgr)
  
if __name__ == '__main__':
    sys.exit(main())


