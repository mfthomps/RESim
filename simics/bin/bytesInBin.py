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
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils
import winProg
lgr = resimUtils.getLogger('bytesInBin', '/tmp', level=None)

def findBytes(fname, load_addr, bstring, lgr):
    size, machine, image_base, addr_of_text = winProg.getSizeAndMachine(fname, lgr)
    if load_addr is None and image_base == 0x10000000:
        print('generic load address and no load_addr provided')
        return
    wildcard_offset = None
    wild_value = ''
    if '*' in bstring:
        wildcard_index = bstring.index('*') 
        wildcard_offset = int((wildcard_index - 1) / 2)
          
        #print('offset %d' % wildcard_offset)
        wildcard_high = bstring[wildcard_index-1]
        #print('wildcard_offset %d  wildcard_high %s' % (wildcard_offset, wildcard_high))
        replace = '%s*' % wildcard_high
        bstring = bstring.replace(replace, '00')
    byte_array = bytes.fromhex(bstring)
    location = None
    base = os.path.basename(fname)
    #end = image_base + addr_of_text + size
    end = load_addr + size
    with open(fname, 'rb') as fh:
        fbytes = fh.read()
        offset = 0
        foffset = 0
        for b in fbytes:
            if wildcard_offset is not None and offset == wildcard_offset:
                b_string = '%x' % b
                if b_string.startswith(wildcard_high):
                    offset = offset + 1
                    wild_value = 'wildcard value 0x%x' % b
                else:
                    offset = 0
                    wild_value = ''
            elif b == byte_array[offset]:
                offset = offset + 1
            else:
                offset = 0
                wild_value = ''
            location = foffset - offset + 1
            #addr = (location - 0x400) + image_base + addr_of_text
            addr = (location -0x400) + load_addr + addr_of_text
            if addr > end:
                break
            if offset == len(byte_array):
                print('Found it in %s offset 0x%x %s memory address 0x%x' % (base, location, wild_value, addr))
                #break
                offset = 0
                wild_value = ''
            foffset = foffset+1

def main():
    parser = argparse.ArgumentParser(prog='bytesInBin', description='Find a byte string in a binary.')
    parser.add_argument('bytestring', action='store', help='The byte string to search for.')
    parser.add_argument('prog', action='store', help='The target program')
    parser.add_argument('-l', 'load_addr', action='store', help='Optional load address')
    args = parser.parse_args()
    findBytes(args.prog, args.load_addr, args.bytestring, lgr)

if __name__ == '__main__':
    sys.exit(main())
