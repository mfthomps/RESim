#!/usr/bin/env python3
import sys
import os
import argparse
import json
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils
trace = sys.argv[1]
#   something like 326bcae083--prctl option: SET_NAME changed comm to: new_dog tid:1415 (dog) cycle:0x326bcae083

def main():
    parser = argparse.ArgumentParser(prog='find_prog_rename', description='Search a trace for SET_NAME and create a json map of new names to original names.')
    parser.add_argument('ini', action='store', help='The ini file')
    parser.add_argument('trace', action='store', help='The trace file')
    args = parser.parse_args()
    lgr = resimUtils.getLogger('find_prog_rename', './logs', level=None)
    root_prefix = resimUtils.getIniTargetValue(args.ini, 'RESIM_ROOT_PREFIX')
    analysis_prefix = root_prefix.replace('images', 'analysis')
    print('root_prefix %s' % analysis_prefix)
    outfile = analysis_prefix+'.comm_map'
    comm_map = {}
    with open(args.trace) as fh:
        for line in fh:
            if 'SET_NAME' in line:
                parts = line.split('tid:') 
                new = parts[0].split()[-1].strip()
                rest = parts[1]
                comm_p = rest.split()[1]
                comm = comm_p[1:-1]
                print('new %s comm_p %s' % (new, comm))
                comm_map[new] = comm
    with open(outfile, 'w') as fh:
        fh.write(json.dumps(comm_map)) 
    print('Wrote comm map to %s' % outfile)
                

if __name__ == '__main__':
    sys.exit(main())
