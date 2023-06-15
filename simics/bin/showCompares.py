#!/usr/bin/env python3
#
# Display the "compare" strings found in the watch marks.
#
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
import resimUtils
def main():
    parser = argparse.ArgumentParser(prog='showCompares', description='Show string comparisons for a given target')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    args = parser.parse_args()
    track_list = aflPath.getAFLTrackList(args.target)
    str_list = []
    no_match = []
    got_match = []
    no_match_track = {}
    for track in track_list:
        try:
            tj = json.load(open(track))
        except:
            continue
        mark_list = tj['marks']
        for mark in mark_list:
            if mark['mark_type'] == 'compare':
                src = mark['src_str']
                dst = mark['dst_str']
                print('%s to %s file: %s' % (src, dst, os.path.basename(track)))
                 
                if dst not in str_list:
                    str_list.append(dst)
                if dst != src:
                    if dst not in got_match and dst not in no_match:
                        no_match.append(dst)
                        no_match_track[dst] = track
                else:
                    if dst not in got_match:
                        got_match.append(dst)
                        if dst in no_match:
                            no_match.remove(dst)
                
    print('Unique compare strings')
    for s in str_list:
        print('\t %s' % s)
    print('Not matched:')
    for s in no_match:
        track = no_match_track[s]
        print('\t %s : %s' % (s, track))
        tj = json.load(open(track))
        mark_list = tj['marks']
        did_replace = False
        for mark in mark_list:
            if mark['mark_type'] == 'compare':
                src = mark['src_str']
                dst = mark['dst_str']
                if dst == s:
                    print('\t\t compare %s to %s' % (src, dst))
                    if not did_replace:
                        doReplace(src, dst, track) 
                        did_replace = True

def doReplace(src, dst, track):
    qfile = track.replace('trackio', 'queue')
    with open(qfile, 'br') as fh:
        data = fh.read()
        new_data = data.replace(bytes(src, encoding='utf8'), bytes(dst, encoding='utf8'))
        dst_fname = dst.replace('/','x')
        dst_fname = dst_fname.replace(' ','_')
        outfile = '/tmp/%s.io' % dst_fname
        with open(outfile, 'bw') as out:
            out.write(new_data)
if __name__ == '__main__':
    sys.exit(main())
