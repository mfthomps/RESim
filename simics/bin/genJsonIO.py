#!/usr/bin/env python3
import sys
import json
import binascii
import argparse

def doJson(inlist, outfile):
    pack_list = []
    for f in inlist:
        with open(f, 'rb') as fh:
            packet = fh.read()
            #pack_list.append(bytes.decode(packet, encoding='unicode-escape'))
            pack_list.append(str(binascii.hexlify(packet)))

    jout = json.dumps(pack_list)
    with open(outfile, 'w') as fh:
        fh.write(jout)

    print('Wrote files to %s\n' % outfile)

def main():
    parser = argparse.ArgumentParser(prog='genJsonIO.py', description='Generate a json file from a given set of input files.  Intended for use with drive-driver3.py to send multiple UDP packets from the driver to the target.  And more importantly, these files can be provided to injectIO when the prep inject snapshot is of the driver.')
    parser.add_argument('-n', '--namelist', nargs='+', default=[], action='store', help='List of input files names.')
    parser.add_argument('-o', '--output', action='store', help='Name of output file.')
    args = parser.parse_args()
    if args.output:
        outfile = args.output
    else:
        outfile = '/tmp/io.json'
    flist = []
    for f in args.namelist:
        flist.append(f)
    doJson(flist, outfile)

if __name__ == '__main__':
    sys.exit(main())
