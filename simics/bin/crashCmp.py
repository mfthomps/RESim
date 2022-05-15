#!/usr/bin/env python
#
# Look for common byte values in the crash files of a target.
# Intended to find data that causes an initial read to fail,
# resulting in 2nd read that would avoid the packet filter processing, e.g.,
# to avoid crashes.
#
import sys
import os
import glob
import json
import argparse
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import aflPath
def main():
    parser = argparse.ArgumentParser(prog='crashCmp', description='Find common data in crashing inputs.')
    parser.add_argument('target', action='store', help='The target program')
    args = parser.parse_args()
    data_dict = {}
    crashes = aflPath.getTargetCrashes(args.target)
    for crash_file in crashes:
        with open(crash_file, 'rb') as fh:
            data = fh.read()
            for boffset in range(12):
                if boffset not in data_dict:
                    data_dict[boffset] = [] 
                if data[boffset] not in data_dict[boffset]:
                    data_dict[boffset].append(data[boffset])
    for offset in data_dict:
        print('entries at offset %d: %d' % (offset, len(data_dict[offset])))
        if len(data_dict[offset]) <= 2:
            for value in data_dict[offset]:
                print('\t value: 0x%x' % ord(value))
    

if __name__ == '__main__':
    sys.exit(main())
