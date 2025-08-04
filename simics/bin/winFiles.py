#!/usr/bin/env python3
import os
import sys
import re
import argparse
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils
# parse to get file name from the likes of:
#oneFortyEight.trace:249460b9fe--tid:2240-2244 (INS.exe) CreateFile fname: \??\D:\HLD\charts\STDF_MAIN\UPDATES\MUPDATE fname_addr: 0xbe767d0 retval_addr: 0x13e098 access: 0x100001 (SYNCHRONIZE, STANDARD_RIGHTS_ALL, SPECIFIC_RIGHTS_ALL) file_attributes: 0x80 (FILE_ATTRIBUTE_NORMAL) share_access: 0x3 (FILE_SHARE_READ, FILE_SHARE_WRITE) create_disposition: 0x2 (FILE_CREATE)

def findFiles(infile, outfile, find, lgr):
    found = []
    size_map = {}

    if os.path.isfile(infile):
        with open(infile) as fh:
            for line in fh:
                if 'CreateFile fname:' in line:
                    go = re.search(find, line, re.M|re.I)
                    if go is not None:
                        rest = line.split('fname:')[1].strip()
                        fname = rest.split()[0]
                        if fname.startswith('\\??'):
                            fname = prog[4:]
                        if fname not in found:
                            print('fname %s' % fname)
                            found.append(fname)
        with open(outfile, 'w') as fh:
            for fname in found:
                fh.write('%s\n' % (fname))

    else:
        print('Failed to find input file %s' % infile)
def main():
    parser = argparse.ArgumentParser(prog='winProgSizes', description='Parse a trace file for file names containing a give regx pattern.  Record each match in a output file.')
    parser.add_argument('infile', action='store', help='Path to  the log file.')
    parser.add_argument('outfile', action='store', help='Name of the output file.')
    parser.add_argument('find', action='store', help='Regex to find.')
    args = parser.parse_args()
    lgr = resimUtils.getLogger('winProgSizes', '/tmp', level=None)
    findFiles(args.infile, args.outfile, args.find, lgr)
if __name__ == '__main__':
    sys.exit(main())
