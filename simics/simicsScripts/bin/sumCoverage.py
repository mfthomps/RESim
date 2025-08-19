#!/usr/bin/env python3
'''
Record the sum of a hits for each level of coverage files
'''
import sys
import os
import json
def coverThis(in_dir):
    cover_dir = os.path.join(in_dir, 'coverage')
    if os.path.isdir(cover_dir):
        flist = os.listdir(cover_dir)
        hit_list=[]
        print('Summing hits in files in %s' % cover_dir)
        for f in flist:
            fpath = os.path.join(cover_dir, f)
            with open(fpath) as fh:
                jfile = json.load(fh)
                for addr_s in jfile:
                    addr = int(addr_s)
                    if addr not in hit_list:
                        hit_list.append(addr) 
        outfile = os.path.join(in_dir,'level.hits')
        with open(outfile, 'w') as fh:
            fh.write(json.dumps(hit_list))

        next_dir = os.path.join(in_dir, 'next_level')
        if os.path.isdir(next_dir):
            dir_list = os.listdir(next_dir)
            for d in dir_list:
                dpath = os.path.join(next_dir, d)
                if os.path.isdir(dpath):
                    coverThis(dpath)
        else:
            print('Nothing at %s, done' % next_dir)
    else:
        print('No coverage dir at %s' % cover_dir)
in_dir = sys.argv[1]
coverThis(in_dir)
