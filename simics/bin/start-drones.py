#!/usr/bin/env python3
import os
import sys
import subprocess
import shlex
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir,'simics', 'monitorCore')
import runAFL
def docmd(cmd):
    ssh_ps = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    output = ssh_ps.communicate()
    for line in output[1].decode("utf-8").splitlines():
         print(line)
    for line in output[0].decode("utf-8").splitlines():
         print(line)

def main():
    parser = argparse.ArgumentParser(prog='start-drones.py', description='Start drones listed in the drones.txt file.')
    parser.add_argument('ini', action='store', help='The RESim ini file used during the AFL session.')
    parser.add_argument('-c', '--continue_run', action='store_true', help='Do not use seeds, continue previous sessions.')
    parser.add_argument('-t', '--tcp', action='store_true', help='TCP sessions with potentially multiple packets.')
    parser.add_argument('-l', '--linear', action='store_true', default=False, help='Use LINEAR addressing for coverage breakpoints.')
    parser.add_argument('-d', '--dead', action='store_true', help='Trial run to identify dead blocks, i.e., those being hit by other threads.')
    parser.add_argument('-m', '--max_bytes', action='store', help='Maximum number of bytes for a write, will truncate AFL genereated inputs.')
    parser.add_argument('-x', '--dictionary', action='store', help='path to dictionary relative to AFL_DIR.')
    parser.add_argument('-f', '--fname', action='store', help='Optional name of shared library to fuzz.')
    args = parser.parse_args()
    here = os.getcwd()
    base = os.path.basename(here)
    aflout = os.path.join(os.getenv('AFL_DATA'), 'output', base)
    user = os.getenv('USER')
    try:
        os.rm('/tmp/resimdie.txt')
    except:
        pass
    if not os.path.isfile('drones.txt'):
        print('No drones.txt file found.')
        sys.exit(1)
    with open('drones.txt') as fh:
        for line in fh:
            drone = line.strip()
            cmd = 'ssh %s@%s rm -f /tmp/resimdie.txt' % (user, drone)
            docmd(cmd)
            cmd = 'ssh -t %s@%s bash -ic "\'source ~/.resimrc\';/usr/bin/nohup $RESIM_DIR/simics/bin/remoteAFL.sh %s %s"' % (user, drone, here, args.ini)
            ssh_ps = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            docmd(cmd)


    docmd('get-tars.sh 30 &')
    runAFL.runAFL(args)
    print("Back from runAFL")
    with open('/tmp/resimdie.txt', 'w') as fh:
        fh.write('die')
    docmd(stop-drones.sh)
    docmd("kill $(ps aux | grep '[g]et-tars.sh' | awk '{print $2}')")
if __name__ == '__main__':
    sys.exit(main())
