#!/usr/bin/env python3
'''
Generate a list of all read watch mark instruction addresses.
'''
import json
import argparse
import sys
import os
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath
import resimUtils

class AllReadMarks():
    def __init__(self, target):
        self.mark_list = []
        flist = aflPath.getAFLTrackList(target)
        track_json = None
        for f in flist:
            try:
                track_json = json.load(open(f))
            except:
                print('Failed opening %s' % f)
            for mark in track_json:
                    if mark['mark_type'] == 'read':
                        eip = mark['ip']
                        if eip not in self.mark_list:
                            self.mark_list.append(eip)
        print('%d marks' % len(self.mark_list))


    def getRefs(self):
        return self.mark_list

def getMarks(target):
    arm = AllReadMarks(target)
    return arm.getRefs()

def main():
    parser = argparse.ArgumentParser(prog='dataDiff', description='look for a pony')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    args = parser.parse_args()
    marks = getMarks(args.target)

if __name__ == '__main__':
    sys.exit(main())
            
