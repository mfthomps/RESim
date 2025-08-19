#!/usr/bin/env python3
'''
Show levels and io files that find new paths
'''
import sys
import os
import json
def showThisCover(in_dir, hit_list):
    hits_file = os.path.join(in_dir,'level.hits')
    if os.path.isfile(hits_file):
        with open(hits_file) as fh:
            hits_json = json.load(fh)
            new_hits = 0
            for hit in hits_json:
                if hit not in hit_list:
                    new_hits += 1
                    hit_list.append(hit)
            print('%d new hits at level %s' % (new_hits, in_dir))
            next_dir = os.path.join(in_dir, 'next_level')
            if os.path.isdir(next_dir):
                dir_list = os.listdir(next_dir)
                for d in dir_list:
                    dpath = os.path.join(next_dir, d)
                    if os.path.isdir(dpath):
                        showThisCover(dpath,hit_list)
            else:
                print('Nothing at %s, done' % next_dir)
in_dir = sys.argv[1]
hit_list = []
showThisCover(in_dir, hit_list)
