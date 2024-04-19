#!/usr/bin/env python3
import sys
import os
import argparse
import shutil
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir,'simics', 'monitorCore'))
import aflPath
def main():
    parser = argparse.ArgumentParser(prog='addLive.py', description='Manually add a currently running AFL queues.')
    parser.add_argument('path', action='store', help='Path to the file to add.')
    args = parser.parse_args()
    our_name = 'live_add'
    if os.path.isfile(args.path):
         here = os.getcwd()
         target = os.path.basename(here)
         target_path = aflPath.getTargetPath(target) 
         live_path = os.path.join(target_path, our_name, 'queue')
         try:
             os.makedirs(live_path)
         except:
             pass
         entries = os.listdir(live_path)
         count = len(entries) 
         add_base = os.path.basename(args.path)
         add_name = 'id:%06d,%s:%s' % (count, our_name, add_base)
         target_path = os.path.join(live_path, add_name)
         shutil.copyfile(args.path, target_path)
         print('copied %s to %s' % (args.path, target_path))
         
    else:
        print('No file found at: %s' % args.path)    

if __name__ == '__main__':
    sys.exit(main())
