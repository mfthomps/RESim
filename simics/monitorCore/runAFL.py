#!/usr/bin/env python3
'''
Executable python script to run multiple parallel instances of RESim/AFL on a single computer.
The design uses the AFL master/slave options and synch directories.

The script is intended to be run from a RESim workspace directory within which multiple copies
of the workspace were created using the clonewd.sh script.

Each AFL/RESim pair is given a unique port number over which to communicate.

'''
import os
import sys
import subprocess
import argparse
import shlex
import time
import glob
import threading
import select
def ioHandler(read_array, stop):
    log = '/tmp/resim.log'
    with open(log, 'wb') as fh:
        while(True):
            if stop():
                print('ioHandler sees stop, exiting.')
                return
            r, w, e = select.select(read_array, [], [], 10) 
            for item in r:
                    data = os.read(item.fileno(), 800)
                    fh.write(data+b'\n')

def doOne(afl_path, afl_seeds, afl_out, size_str,port, afl_name, resim_ini, read_array, resim_path, resim_procs, dict_path):
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

    stop_threads = False
    io_handler = threading.Thread(target=ioHandler, args=(read_array, lambda: stop_threads))
    io_handler.start()

    my_in = input('any key to quit')
    for ps in resim_procs:
        ps.stdin.write(b'quit\n')
    print('did quit')
    print('done')
    stop_threads = True
    for fd in read_array:
        fd.close()

    return resim_ps
    
def main():
    parser = argparse.ArgumentParser(prog='runAFL', description='Run AFL.')
    parser.add_argument('ini', action='store', help='The RESim ini file used during the AFL session.')
    parser.add_argument('-c', '--continue_run', action='store_true', help='Do not use seeds, continue previous sessions.')
    parser.add_argument('-t', '--tcp', action='store_true', help='TCP sessions with potentially multiple packets.')
    parser.add_argument('-d', '--dead', action='store_true', help='Trial run to identify dead blocks, i.e., those being hit by other threads.')
    parser.add_argument('-m', '--max_bytes', action='store', help='Maximum number of bytes for a write, will truncate AFL genereated inputs.')
    parser.add_argument('-x', '--dictionary', action='store', help='path to dictionary relative to AFL_DIR.')
    args = parser.parse_args()
    here= os.path.dirname(os.path.realpath(__file__))
    os.environ['ONE_DONE_SCRIPT'] = os.path.join(here, 'onedoneAFL.py')
    resim_dir = os.getenv('RESIM_DIR')
    if resim_dir is None:
        print('missing RESIM_DIR envrionment variable')
        exit(1)
    resim_path = os.path.join(resim_dir, 'simics', 'bin', 'resim')

    here = os.getcwd()
    afl_name = os.path.basename(here)
    try:
        afl_path = os.path.join(os.getenv('AFL_DIR'), 'afl-fuzz')
    except:
        print('missing AFL_DIR envrionment variable')
        exit(1)
    resim_procs = []
    try:
        afl_data = os.getenv('AFL_DATA')
    except:
        print('missing AFL_DATA envrionment variable')
        exit(1)

    if not args.ini.endswith('.ini'):
        args.ini = args.ini+'.ini'
    if not os.path.isfile(args.ini):
        print('Ini file %s not found.' % args.ini)
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
    master_slave = '-M'
    glist = glob.glob('resim_*/')

    if args.tcp:
        os.environ['ONE_DONE_PARAM2']='tcp'
    else:
        os.environ['ONE_DONE_PARAM2']='udp'

    if args.dead:
        os.environ['ONE_DONE_PARAM3']='TRUE'

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
           print('No dictionary at %s' % dpath)
           exit(1)
        
    port = 8700
    read_array = []
    if len(glist) > 0:
        print('Parallel, doing %d instances' % len(glist))
        for instance in glist:
            if not os.path.isdir(instance):
                continue
            afl_cmd = '%s -i %s -o %s %s %s %s -p %d %s -R %s' % (afl_path, afl_seeds, afl_out, size_str, 
                  master_slave, instance[:-1], port, dict_path, afl_name)
            print('afl_cmd %s' % afl_cmd) 
            os.chdir(instance)
        
            cmd = 'xterm -geometry 80x25 -e "%s;sleep 10"' % (afl_cmd)
            afl_ps = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            print('created afl')
    
            resim_ini = args.ini
            cmd = '%s %s -n' % (resim_path, resim_ini)
            os.environ['ONE_DONE_PARAM'] = str(port)
            print('cmd is %s' % cmd)
            resim_ps = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            resim_procs.append(resim_ps)
            read_array.append(resim_ps.stdout)
            read_array.append(resim_ps.stderr)
            print('created resim port %d' % port)
            os.chdir(here)
            master_slave = '-S'
            port = port + 1
    else:
        print('Running single instance')
        resim_ps = doOne(afl_path, afl_seeds, afl_out, size_str,port, afl_name, args.ini, read_array, resim_path, resim_procs, dict_path)
    stop_threads = False
    io_handler = threading.Thread(target=ioHandler, args=(read_array, lambda: stop_threads))
    io_handler.start()
    my_in = input('any key to quit')
    for ps in resim_procs:
        ps.stdin.write(b'quit\n')
    print('did quit')
    print('done')
    stop_threads = True
    for fd in read_array:
        fd.close()
    #output = resim_ps.communicate()
  
if __name__ == '__main__':
    sys.exit(main())


