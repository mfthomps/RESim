#!/usr/bin/env python3
import sys
import os
import argparse
import shutil
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir,'simics', 'monitorCore'))
import aflPath
def main():
    parser = argparse.ArgumentParser(prog='addInput.py', description='Manually add a file to fuzzing results.')
    parser.add_argument('path', action='store', help='Path to the file to add.')
    parser.add_argument('name', action='store', help='Name to give the file (descriptive, no spaces please).')
    parser.add_argument('-f', '--force', action='store_true', help='Overwrite file if it already exists.')
    args = parser.parse_args()
    if os.path.isfile(args.path):
         here = os.getcwd()
         target = os.path.basename(here)
         target_path = aflPath.getTargetPath(target) 
         if os.path.isdir(target_path):
             manual = os.path.join(target_path, 'manual_queue')
             try:
                 os.mkdir(manual)
             except:
                 pass
             dest = os.path.join(manual, args.name)
             if not os.path.isfile(dest) or args.force:
                 shutil.copyfile(args.path, dest)
                 print('%s copied to %s' % (args.path, dest))
                 if args.force:
                     ''' remove any coverage file '''
                     coverage = dest.replace('_queue', '_coverage')
                     try:
                         os.remove(coverage)
                     except:
                         pass
             else:
                 print('File at %s already exists, use -f to overwrite' % dest)
             
         else:
             print('No target directory found at %s' % target_path)
    else:
        print('No file found at: %s' % args.path)    

if __name__ == '__main__':
    sys.exit(main())
