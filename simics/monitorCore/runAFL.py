#!/usr/bin/env python3
'''
Executable python script to run multiple parallel instances of RESim/AFL on a single computer.
The design uses the AFL master/slave options and synch directories.

The script is intended to be run from a RESim workspace directory within which multiple copies
of the workspace were created using the clonewd.sh script.

Each AFL/RESim pair is given a unique port number over which to communicate.

'''
import os
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
                print('ioHandler sees stop, return.')
                lgr.debug('ioHandler sees stop, return.')
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
                if len(data.decode().strip()) > 0:
                    fh.write(data+b'\n')
                   

def handleClose(resim_procs, read_array, duration, remote, fifo_list, lgr):
    stop_threads = False
    io_handler = threading.Thread(target=ioHandler, args=(read_array, lambda: stop_threads, lgr))
    io_handler.start()
    total_time = 0
    sleep_time = 4
    do_restart = False
    if duration is None:
        print('any key to quit')
    else:
        print('any key to quit, or will exit in %d seconds' % duration)
    while (duration is None or total_time < duration) and not os.path.isfile('/tmp/resimdie.txt'):
        if remote:
            time.sleep(sleep_time)
        else:
            i, o, e = select.select( [sys.stdin], [], [], sleep_time )
            if len(i) > 0:
                print('got input key')
                break
        total_time = total_time + sleep_time
        if os.path.isfile('/tmp/resim_restart.txt'):
            do_restart = True
            break
        free = resimUtils.getFree()
        if free < 30:
            lgr.debug('found memory only at %d, must be leaking, restart simics' % free)
            do_restart = True
            break

    if not do_restart:
        print('did quit')
        lgr.debug('handleClose must have gotten quit')
        for fifo in fifo_list:
            os.write(fifo, bytes('quit\n', 'UTF-8'))
            lgr.debug('wrote quit to fifo') 
    else:
        for fifo in fifo_list:
            os.write(fifo, bytes('restart\n', 'UTF-8'))
            lgr.debug('wrote restart to fifo')
    for proc in resim_procs:
        proc.wait()
        lgr.debug('proc exited')

    stop_threads = True
    for fd in read_array:
        fd.close()
    return do_restart

def doOne(afl_path, afl_seeds, afl_out, size_str,port, afl_name, resim_ini, read_array, resim_path, resim_procs, dict_path, timeout, lgr):
    try:
        os.remove('resim_ctl.fifo')
    except:
        pass
    try:
        os.mkfifo('resim_ctl.fifo')
    except OSError as e:
        lgr.debug('fifo create failed %s' % e)    
        return

    fifo_list = []
    afl_cmd = '%s -i %s -o %s %s -p %d %s -R %s' % (afl_path, afl_seeds, afl_out, size_str, port, dict_path, afl_name)
    print('afl_cmd %s' % afl_cmd) 

    cmd = 'xterm -geometry 80x25 -e "%s;sleep 10"' % (afl_cmd)
    afl_ps = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    print('created afl')

    cmd = '%s %s -n' % (resim_path, resim_ini)
    os.environ['ONE_DONE_PARAM'] = str(port)
    print('cmd is %s' % cmd)
    resim_ps = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    resim_procs.append(resim_ps)
    read_array.append(resim_ps.stdout)
    read_array.append(resim_ps.stderr)
    print('created resim port %d' % port)
    lgr.debug('open fifo %s' % os.path.abspath('resim_ctl.fifo'))
    fh = os.open('resim_ctl.fifo', os.O_WRONLY)
    lgr.debug('back from open fifo')
    fifo_list.append(fh)
    handleClose(resim_procs, read_array, timeout, False, fifo_list, lgr)

    return resim_ps
    

def runAFLTilRestart(args, lgr):
    os.environ['AFL_SKIP_CPUFREQ']='True'
    here= os.path.dirname(os.path.realpath(__file__))
    os.environ['ONE_DONE_SCRIPT'] = os.path.join(here, 'onedoneAFL.py')
    resim_dir = os.getenv('RESIM_DIR')
    if resim_dir is None:
        print('missing RESIM_DIR envrionment variable')
        exit(1)
    resim_path = os.path.join(resim_dir, 'simics', 'bin', 'resim')
    hostname = aflPath.getHost()

    do_restart = False 
    here = os.getcwd()
    afl_name = os.path.basename(here)
    try:
        afl_path = os.path.join(os.getenv('AFL_DIR'), 'afl-fuzz')
    except:
        lgr.error('missing AFL_DIR envrionment variable')
        exit(1)
    resim_procs = []
    try:
        afl_data = os.getenv('AFL_DATA')
    except:
        lgr.error('missing AFL_DATA envrionment variable')
        exit(1)

    if not args.ini.endswith('.ini'):
        args.ini = args.ini+'.ini'
    if not os.path.isfile(args.ini):
        lgr.error('Ini file %s not found.' % args.ini)
        exit(1)
    afl_out = os.path.join(afl_data, 'output', afl_name)
    if args.continue_run == True:
        afl_seeds = '-'
    else:
        afl_seeds = os.path.join(afl_data, 'seeds', afl_name)

    try:
        os.makedirs(afl_out)
    except:
        pass
    try:
        os.makedirs(afl_seeds)
    except:
        pass
    if args.remote:
        master_slave = '-S'
    else:
        master_slave = '-M'
    glist = glob.glob('resim_*/')

    if args.tcp:
        os.environ['ONE_DONE_PARAM2']='tcp'
    else:
        os.environ['ONE_DONE_PARAM2']='udp'

    if args.dead:
        os.environ['ONE_DONE_PARAM3']='TRUE'

    if args.fname is not None: 
        os.environ['ONE_DONE_PARAM4']=args.fname

    if args.linear:
        os.environ['ONE_DONE_PARAM5']='TRUE'

    if args.max_bytes is not None:
        size_str = '-s %d' % args.max_bytes 
    else:
        size_str = ''

    dict_path = ''
    if args.dictionary is not None:
       dpath = os.path.join(os.path.dirname(afl_path), 'dictionaries', args.dictionary)
       if os.path.isfile(dpath):
           dict_path = '-x %s' % dpath
       else:
           lgr.error('No dictionary at %s' % dpath)
           exit(1)
        
    port = 8700
    read_array = []
    fifo_list = []
    if len(glist) > 0:
        lgr.debug('Parallel, doing %d instances' % len(glist))
        for instance in glist:
            fuzzid = '%s_%s' % (hostname, instance[:-1])
            if not os.path.isdir(instance):
                continue
            os.chdir(instance)
            if not args.no_afl:
                afl_cmd = '%s -i %s -o %s %s %s %s -p %d %s -R %s' % (afl_path, afl_seeds, afl_out, size_str, 
                      master_slave, fuzzid, port, dict_path, afl_name)
                #print('afl_cmd %s' % afl_cmd) 
                if args.remote or (args.quiet and master_slave == '-S'):
                    afllog = '/tmp/%s.log' % fuzzid 
                    fh = open(afllog, 'w')
                    cmd = '%s &' % (afl_cmd)
                    #afl_ps = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,stderr=fh)
                    afl_ps = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=fh,stderr=fh)
                elif args.quiet and master_slave == '-M':
                    afllog = '../master-%s.log' % fuzzid 
                    fh = open(afllog, 'w')
                    cmd = '%s &' % (afl_cmd)
                    afl_ps = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=fh,stderr=fh)
                else:
                    cmd = 'xterm -geometry 80x25 -e "%s;sleep 10"' % (afl_cmd)
                    afl_ps = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                lgr.debug('cmd %s' % cmd) 
                lgr.debug('created afl in dir %s' % instance)

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
            os.environ['ONE_DONE_PARAM'] = str(port)
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
            lgr.debug('created resim port %d' % port)
            os.chdir(here)
            master_slave = '-S'
            port = port + 1

        do_restart = handleClose(resim_procs, read_array, args.seconds, args.remote, fifo_list, lgr)
    else:
        lgr.debug('Running single instance')
        doOne(afl_path, afl_seeds, afl_out, size_str,port, afl_name, args.ini, read_array, resim_path, resim_procs, dict_path, args.seconds, lgr)
    return do_restart

def runAFL(args, lgr):
    while runAFLTilRestart(args, lgr):
        print('restarting resim in 10')
        lgr.debug('restarting resim in 10')
        try:
            os.remove('/tmp/resim_restart.txt')
        except:
            pass
        time.sleep(10)
        args.no_afl = True
    lgr.debug('runAFL out of runAFL loop')

def main():
    lgr = resimUtils.getLogger('runAFL', '/tmp/', level=None)
    parser = argparse.ArgumentParser(prog='runAFL', description='Run AFL.')
    parser.add_argument('ini', action='store', help='The RESim ini file used during the AFL session.')
    parser.add_argument('-c', '--continue_run', action='store_true', help='Do not use seeds, continue previous sessions.')
    parser.add_argument('-t', '--tcp', action='store_true', help='TCP sessions with potentially multiple packets.')
    parser.add_argument('-l', '--linear', action='store_true', default=False, help='Use LINEAR addressing for coverage breakpoints.')
    parser.add_argument('-d', '--dead', action='store_true', help='Trial run to identify dead blocks, i.e., those being hit by other threads.')
    parser.add_argument('-m', '--max_bytes', action='store', help='Maximum number of bytes for a write, will truncate AFL genereated inputs.')
    parser.add_argument('-x', '--dictionary', action='store', help='path to dictionary relative to AFL_DIR.')
    parser.add_argument('-f', '--fname', action='store', help='Optional name of shared library to fuzz.')
    parser.add_argument('-s', '--seconds', action='store', type=int, help='Run for given number of seconds, then exit.')
    parser.add_argument('-r', '--remote', action='store_true', help='Remote run, will wait for /tmp/resim_die.txt before exiting.')
    parser.add_argument('-n', '--no_afl', action='store_true', default=False, help='Do not start AFL, restarting RESim and reusing existing AFL.')
    parser.add_argument('-q', '--quiet', action='store_true', default=False, help='Redirect afl output to file in workspace directory')
    try:
        os.remove('/tmp/resim_restart.txt')
    except:
        pass
    args = parser.parse_args()
    do_restart = runAFL(args, lgr)
  
if __name__ == '__main__':
    sys.exit(main())


