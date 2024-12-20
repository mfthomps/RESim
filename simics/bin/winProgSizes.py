#!/usr/bin/env python3
import os
import sys
import argparse
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils
import winProg
def findProgs(root_dir, root_subdirs, infile, outfile, lgr):
    found = []
    size_map = {}
    if os.path.isfile(infile):
        with open(infile) as fh:
            for line in fh:
                if 'syscall CreateUserProces' in line:
                    prog = line.split('prog:')[1].strip()
                    if prog not in found:
                        print('prog %s' % prog)
                        found.append(prog)
        for prog in found:
            if prog.startswith('\\??'):
                prog = prog[4:]
            prog = prog.replace('\\', '/')
            path = os.path.join(root_dir, prog)
            full_insensitive = resimUtils.getfileInsensitive(path, root_dir, root_subdirs, lgr)
            if full_insensitive is None:
                print('No path for %s' % path)
            else:
                print('insensitive path %s' % full_insensitive) 
                size, machine, image_base, addr_of_text = winProg.getSizeAndMachine(full_insensitive, lgr)
                if 'I386' in machine:
                    word_size = 4
                else:
                    word_size = 8
                print('\t word size %d' % word_size)
                base = os.path.basename(full_insensitive)
                size_map[base] = word_size
        with open(outfile, 'w') as fh:
            for base in size_map:
                fh.write('%s %d\n' % (base, size_map[base]))

    else:
        print('Failed to find input file %s' % infile)
def main():
    parser = argparse.ArgumentParser(prog='winProgSizes', description='Parse a log file and generate a file reflecting word sizes of created prgrams.  For use with WORD_SIZES in the ini file.')
    parser.add_argument('ini', action='store', help='The RESim ini file.')
    parser.add_argument('infile', action='store', help='Path to  the log file.')
    parser.add_argument('outfile', action='store', help='Name of the output file.')
    args = parser.parse_args()
    root_dir = resimUtils.getIniTargetValue(args.ini, 'RESIM_ROOT_PREFIX')
    root_subdirs = []
    sub_dirs = resimUtils.getIniTargetValue(args.ini, 'RESIM_ROOT_SUBDIRS')
    parts = sub_dirs.split(';')
    for sd in parts:
        root_subdirs.append(sd.strip()) 
    lgr = resimUtils.getLogger('winProgSizes', '/tmp', level=None)
    findProgs(root_dir, root_subdirs, args.infile, args.outfile, lgr)
if __name__ == '__main__':
    sys.exit(main())
