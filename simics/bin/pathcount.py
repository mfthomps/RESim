#!/usr/bin/env python3
import os
import sys
import argparse
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath


def main():
    parser = argparse.ArgumentParser(prog='pathcount', description='Display count of uniqe code paths as determined by AFL')
    parser.add_argument('target', action='store', help='The target workspace')
    args = parser.parse_args()
    qlist = aflPath.getTargetQueue(args.target, get_all=True)
    count = len(qlist)
    print('AFL found %d paths.' % count)
    crashlist = aflPath.getTargetCrashes(args.target)
    print('and %d unique crashes.' % len(crashlist))

if __name__ == '__main__':
    sys.exit(main())
