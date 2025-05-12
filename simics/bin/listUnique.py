#!/usr/bin/env python3
#
# Display the list of queue files determined to be unique by dedupe.
#
import sys
import json
import os
import argparse
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath
import resimUtils
def main():
    parser = argparse.ArgumentParser(prog='listUnique', description='List the queue files that dedupe found to have unique coverage.')
    parser.add_argument('target', action='store', help='The AFL target, generally the name of the workspace.')
    args = parser.parse_args()
    lgr = resimUtils.getLogger('listUnique', '/tmp', level=None)
    flist = aflPath.getAFLCoverageList(args.target)
    index = 0
    all_hits = []
    for f in flist:
        hits = json.load(open(f))
        print('%d  %d hits in %s' % (index, len(hits), f))
        for h in hits:
            if h not in all_hits:
                all_hits.append(h)
        index += 1
    print('%d total hits' % len(all_hits))
if __name__ == '__main__':
    sys.exit(main())
