#!/usr/bin/env python3
#
# given a an AFL session named by target, provide a summary of
# queue files and unique hits files (post playAFL).
#
import sys
import os
import glob
import json
import argparse
import subprocess
try:
    import ConfigParser
except:
    import configparser as ConfigParser
resim_dir = os.getenv('RESIM_DIR')

sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath

def main():
    afldir = os.getenv('AFL_DIR')
    parser = argparse.ArgumentParser(prog='fuzz-summary.py', description='Show fuzzing summary')
    parser.add_argument('target', action='store', help='The target workspace name.')
    args = parser.parse_args()
    
    unique_files = aflPath.getTargetQueue(args.target)
    queue_files = aflPath.getTargetQueue(args.target, get_all=True)
    print('AFL found %d queue files (execution paths), some may be duplicates.' % len(queue_files))
    print('RESim sees %d unique execution paths.' % len(unique_files))
if __name__ == '__main__':
    sys.exit(main())
