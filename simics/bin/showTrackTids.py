#!/usr/bin/env python3
'''
Shows data values for watch marks TIDs for all tracks for a given afl target.
Intended for use in determining if multiple TIDs reference input data.
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
    parser = argparse.ArgumentParser(prog='showTrackTids', description='Show tids that recorded watch marks for a given target.  Intended to see if mulitple tids touched data.')
    parser.add_argument('target', action='store', help='The target')
    args = parser.parse_args()
    flist = aflPath.getAFLTrackList(args.target)
    wgot = []
    tid_list = []
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
            tid = mark['tid']
            if tid not in tid_list:
                tid_list.append(tid)
                print('tid is %s' % tid)
        

         

if __name__ == '__main__':
    sys.exit(main())
