#!/usr/bin/env python3
'''
Shows kernel call numbers for kernel watch marks.
Intended for use in determining if input data used in mkdir, open or create...
'''
import sys
import os
import glob
import json
import argparse
try:
    import ConfigParser
except:
    import configparser as ConfigParser
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath
def main():
    parser = argparse.ArgumentParser(prog='showTrackSyscalls', description='Show kernel call numbers from watch marks, e.g., to see if any input data is used in a create')
    parser.add_argument('target', action='store', help='The target')
    args = parser.parse_args()
    flist = aflPath.getAFLTrackList(args.target)
    call_list = []
    for track in flist:
        #print('track: %s' % track)
        if not os.path.isfile(track):
            continue
        try:
            jtrack = json.load(open(track))
        except:
            continue
        mark_list = jtrack['marks']
        for mark in mark_list:
            if mark['mark_type'] == 'kernel':
                call_num = mark['callnum']
                if call_num not in call_list:
                    print(call_num)
                    call_list.append(call_num)

         

if __name__ == '__main__':
    sys.exit(main())
