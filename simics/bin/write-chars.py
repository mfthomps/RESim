#!/usr/bin/env python3
import sys
import os
import glob
import json
import argparse
parser = argparse.ArgumentParser(prog='writeChars', description='write characters to file')
parser.add_argument('count', action='store', type=int, help='the number of characters.')
parser.add_argument('chr', action='store', help='the characters.')
args = parser.parse_args()

s = args.count*args.chr
sys.stdout.write(s)
