#!/usr/bin/env python3
import sys
import os
import glob
import json
import argparse
parser = argparse.ArgumentParser(prog='writeChars', description='write characters to file')
parser.add_argument('count', action='store', type=int, help='the number of characters.')
parser.add_argument('chr', action='store', help='The characters.  A leading 0x will interpret the remainder as a hex value.')
args = parser.parse_args()
sys.stderr.write('args chr is %s\n' % args.chr)
if args.chr.startswith('0x'):
    value = int(args.chr, 16)
    wc = chr(value)
else:
    wc = args.chr

s = args.count*wc
sys.stdout.write(s)
