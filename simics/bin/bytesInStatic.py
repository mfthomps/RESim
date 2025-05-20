#!/usr/bin/env python3
#
#  search for bytes in a file.
#  Support single wildcard reflecting high order nibble.
#  For example 12a*c2 would match 12a4c2
#  for x86 byte order should match simics "x" display order
#  for windows, subtract "Size of headers" from this,
#  and add to ImageBase plus address of text section
#
import sys
import os
import argparse
import ntpath
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils
import bytesInBin
import findProgram
import getStaticPaths

def main():
    parser = argparse.ArgumentParser(prog='bytesInStatic', description='Find path to a program.')
    parser.add_argument('ini', action='store', help='The RESim ini file.')
    parser.add_argument('bytestring', action='store', help='The byte string to search for.')
    parser.add_argument('static_list', action='store', help='The list of static DLLs')
    args = parser.parse_args()
    lgr = resimUtils.getLogger('bytesInStatic', '/tmp', level=None)
    args = parser.parse_args()
    if not os.path.isfile(args.static_list):
        print('No static list file at %s' % static_list)
        exit(1)
    root_dir = resimUtils.getIniTargetValue(args.ini, 'RESIM_ROOT_PREFIX')
    print('root dir %s' % root_dir)
    static_paths = getStaticPaths.getStaticPaths(args.static_list, root_dir, lgr)
    for item in static_paths:
        base = os.path.basename(item.path)
        #print('found path for %s is %s' % (base, item.path))
        bytesInBin.findBytes(item.path, item.load_addr, args.bytestring, lgr)

if __name__ == '__main__':
    sys.exit(main())
