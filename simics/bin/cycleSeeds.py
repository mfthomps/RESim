#!/usr/bin/env python3
import sys
import os
import argparse
import shutil
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir,'simics', 'monitorCore'))
import aflPath
def main():
    parser = argparse.ArgumentParser(prog='cycleSeeds.py', description='Replace afl seed files with those found in the unique coverage file.')
    args = parser.parse_args()
    here = os.getcwd()
    target = os.path.basename(here)
    seeds_dir = aflPath.getTargetSeedsPath(target)
    if os.path.isdir(seeds_dir):
        ''' assuming this will read from the unique list '''
        qfiles = aflPath.getTargetQueue(target)    
        print('got %d unique queue files, copy to %s' % (len(qfiles), seeds_dir))
        for q in qfiles:
            shutil.copy(q, seeds_dir)
    else:
        print('No seeds dir found at: %s' % seeds_dir)
if __name__ == '__main__':
    sys.exit(main())
