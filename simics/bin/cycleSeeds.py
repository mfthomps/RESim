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
    parser.add_argument('-t', '--target', action='store', help='Optional target name from which to get the queue files (if different from current directory')
    args = parser.parse_args()
    here = os.getcwd()
    my_target = os.path.basename(here)
    seeds_dir = aflPath.getTargetSeedsPath(my_target)
    if args.target is None:
        source_target = my_target
    else:
        source_target = args.target
        try:
            os.mkdir(seeds_dir)
        except:
            pass
    if os.path.isdir(seeds_dir):
        ''' assuming this will read from the unique list '''
        qfiles = aflPath.getTargetQueue(source_target)    
        print('got %d unique queue files, copy to %s' % (len(qfiles), seeds_dir))
        for q in qfiles:
            shutil.copy(q, seeds_dir)
    else:
        print('No seeds dir found at: %s' % seeds_dir)
if __name__ == '__main__':
    sys.exit(main())
