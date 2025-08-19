#!/usr/bin/env python3
'''
Show new hits
'''
import sys
import os
import json
def showCover(in_dir, hit_list):
    cover_dir = os.path.join(in_dir, 'coverage')
    if os.path.isdir(cover_dir):
        flist = os.listdir(cover_dir)
        #print('Summing hits in files in %s' % cover_dir)
        for f in flist:
            fpath = os.path.join(cover_dir, f)
            with open(fpath) as fh:
                jfile = json.load(fh)
                count = 0
                for addr_s in jfile:
                    addr = int(addr_s)
                    if addr not in hit_list:
                        hit_list.append(addr) 
                        count += 1
                if count > 0:
                    print('%d new hits for %s' % (count, fpath))

        next_dir = os.path.join(in_dir, 'next_level')
        if os.path.isdir(next_dir):
            dir_list = os.listdir(next_dir)
            for d in dir_list:
                dpath = os.path.join(next_dir, d)
                if os.path.isdir(dpath):
                    showCover(dpath, hit_list)
        else:
            print('Nothing at %s, done' % next_dir)
    else:
        print('No coverage dir at %s' % cover_dir)
in_dir = sys.argv[1]
hit_list = []
showCover(in_dir, hit_list)
