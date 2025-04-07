#!/usr/bin/env python3
#
# Find functions not hit in a hits file
#
import sys
import os
import json
import argparse
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath
import resimUtils


def getFuns(prog_path):
    retval = None
    prog = prog_path+'.funs'
    retval = json.load(open(prog))
    return retval

def main():
    parser = argparse.ArgumentParser(prog='funsNotHit', description='Show functions not hit in a hits file.')
    parser.add_argument('ini', action='store', help='The ini file.')
    parser.add_argument('prog', action='store', help='The program that was fuzzed.  TBD should store via runAFL or similar?.')
    parser.add_argument('hits', action='store', help='The hits file.')
    args = parser.parse_args()
    lgr = resimUtils.getLogger('funsNotHit', '/tmp', level=None)
    lgr.debug('funsNotHit begin')
    analysis_path = resimUtils.getAnalysisPath(args.ini, args.prog, lgr=lgr)
    if analysis_path is None:
        print('Failed to get analysis path from ini %s for prog %s' % (args.ini, args.prog))
        exit(1)
    elif not os.path.isdir(analysis_path):
        print('Failed to find analysis path %s' % (analysis_path))
        exit(1)
    print('analysis_path is %s' % analysis_path)

    funs = getFuns(analysis_path)
    the_hits = None
    with open(args.hits) as fh:
        the_hits = json.load(fh)

    for the_fun in funs:
        faddr = int(the_fun)
        print('fun 0x%x' % faddr)
        if faddr not in the_hits:
            size = funs[the_fun]['end'] - funs[the_fun]['start']
            print('fun 0x%x not in hits size 0x%x' % (faddr, size))
        else:
            pass
            #print('fun 0x%x IS in hits' % faddr)
if __name__ == '__main__':
    sys.exit(main())
