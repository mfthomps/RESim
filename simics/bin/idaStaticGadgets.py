#!/usr/bin/env python3
#
# Use idaGadets on a set of files named in an input static program list
#
import os
import sys
import argparse
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils
import getStaticPaths
def main():
    parser = argparse.ArgumentParser(prog='idaStaticDump', description='For each executable listed in a pre-created static list, run idaDump.sh on it')
    parser.add_argument('ini', action='store', help='The RESim ini file.')
    parser.add_argument('static_list', action='store', help='The list of static DLLs')
    args = parser.parse_args()
    lgr = resimUtils.getLogger('bytesInStatic.log', '/tmp', level=None)
    args = parser.parse_args()
    if not os.path.isfile(args.static_list):
        print('No static list file at %s' % static_list)
        exit(1)
    root_dir = resimUtils.getIniTargetValue(args.ini, 'RESIM_ROOT_PREFIX')
    print('root dir %s' % root_dir)
    static_paths = getStaticPaths.getStaticPaths(args.static_list, root_dir, lgr)
    for item in static_paths:
        cmd = 'idaGadgets.sh %s' % item.path
        print('would run %s' % cmd)
        os.system(cmd)

if __name__ == '__main__':
    sys.exit(main())
