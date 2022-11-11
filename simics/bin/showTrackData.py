#!/usr/bin/env python3
'''
Shows data values for watch marks at a given address across all trackio files
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
    parser = argparse.ArgumentParser(prog='showTrackData', description='Show values for data marks of a given address')
    parser.add_argument('target', action='store', help='The target')
    parser.add_argument('address', action='store', help='The address')
    args = parser.parse_args()
    try:
        address = int(args.address, 16)
    except:
        print('Expected hex address, got %s' % args.address)
        exit(1)
    flist = aflPath.getAFLTrackList(args.target)
    wgot = []
    for track in flist:
        if not os.path.isfile(track):
            continue
        try:
            jtrack = json.load(open(track))
        except:
            continue
        mark_list = jtrack['marks']
        for mark in mark_list:
            if mark['mark_type'] == 'read': 
                #print('ip is 0x%x' % mark['ip'])
                if mark['ip'] == address:
                    if 'value' in mark:
                        if mark['value'] not in wgot:
                            print('0x%x %s' % (mark['value'], track))
                            wgot.append(mark['value'])
        

         

if __name__ == '__main__':
    sys.exit(main())
