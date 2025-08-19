#!/usr/bin/env python3
import os
import sys
import re
import argparse
resim_dir = os.getenv('RESIM_DIR')
resim_image = os.getenv('RESIM_IMAGE')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils
import winProg

def main():
    parser = argparse.ArgumentParser(prog='winProgHeader', description='Get program header info from a windows program file or dll')
    parser.add_argument('infile', action='store', help='Path to the program file or dll')
    args = parser.parse_args()
    lgr = resimUtils.getLogger('winProgSizes', '/tmp', level=None)
    if os.path.isfile(args.infile):
        fpath = args.infile
    else:
        fpath = os.path.join(resim_image, args.infile)
    if not os.path.isfile(fpath):
        print('no file at %s' % fpath)
        exit(1)
    size, machine, image_base, addr_of_text = winProg.getSizeAndMachine(fpath, lgr)
    print('size 0x%x' % (size))
    print('machine %s' % (machine))
    print('image_base %s' % (image_base))
    print('size 0x%x machine %s image_base 0x%x addr_of_text 0x%x' % (size, machine, image_base, addr_of_text))
if __name__ == '__main__':
    sys.exit(main())
