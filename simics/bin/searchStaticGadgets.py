#!/usr/bin/env python3
#
#  Search a json created by findGadets.py.
#  Manually edit this file to get it to search for
#  what you want, and then run it from IDA.
#
import json
import os
import sys
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import decode
import argparse
import ntpath
import resimUtils
import getStaticPaths
  
def checkMov(instruct, gname, reg):
    retval = False 
    mn = decode.getMn(instruct)
    op2, op1 = decode.getOperands(instruct)
    if op1 is not None and '[' in op1 and reg in op1:
        retval = True
    if mn == 'mov' and op1 == reg:
        if (op2.startswith('e') or '[' in op2):
            print('gadget 0x%x %s' % (gname, instruct))
            retval = True
        else:
            retval = True
    return retval

def checkMov2(instruct, gname, reg):
    retval = False 
    mn = decode.getMn(instruct)
    op2, op1 = decode.getOperands(instruct)
    if mn == 'mov' and op2 == reg:
        retval = True
    return retval

def checkMovExact(instruct, gname, reg1, reg2):
    retval = False 
    mn = decode.getMn(instruct)
    op2, op1 = decode.getOperands(instruct)
    #if op1 is not None and '[' in op1 and reg1 in op1:
    #    retval = True
    if mn == 'mov' and op1 == reg1: 
        if reg2 == op2:
            #print(instruct)
            #print('reg2 <%s> op2 <%s>' % (reg2, op2))
            print('gadget 0x%x %s' % (gname, instruct))
            retval = True
        
        #if reg2 in op2:
        #    print('gadget 0x%x %s' % (gname, instruct))
        #    retval = True
        #else:
    return retval

def checkIndMov(instruct, gname, reg):
    retval = False 
    mn = decode.getMn(instruct)
    op2, op1 = decode.getOperands(instruct)
    if op1 is not None and '[' in op1 and reg in op1:
        retval = True
    if mn == 'mov' and op1 == reg:
        if '[' in op2 and 'e' in op2:
            print('gadget 0x%x %s' % (gname, instruct))
            retval = True
        else:
            retval = True
    return retval

def checkAdd(instruct, gname):
    retval = False 
    mn = decode.getMn(instruct)
    op2, op1 = decode.getOperands(instruct)
    if op1 is not None and '[' in op1 and 'eax' in op1:
        retval = True
    if mn == 'leave':
        retval = True
    if (mn in ['mov', 'sub', 'lea', 'shl', 'shr'] ) and op1 == 'eax':
        retval = True
    #elif mn == 'add' and op1 == 'eax':
    elif mn == 'add' and op1.startswith('e') and op2.startswith('e'):
        print('gadget 0x%x %s' % (gname, instruct))
        retval = True
    return retval

def checkLEA(instruct, reg, gname):
    retval = False 
    mn = decode.getMn(instruct)
    op2, op1 = decode.getOperands(instruct)
    if mn == 'lea' and reg in op2 and 'sp' not in op1:
        print('gadget 0x%x %s' % (gname, instruct))
        return True
    return False

def findMemcpy(gadget_dict, gadget):
        gname = int(gadget)
        remain_instructs = []
        show_prev = None
        prev_instruct = None
        prev_count = 0
        got_one = False
        for instruct in reversed(gadget_dict[gadget]):
            if show_prev is not None:
                if prev_count < show_prev:
                    if prev_count == 0:
                        print('Gadget: 0x%x' % gname)
                    #print('\t'+instruct+'prev_count %d' % prev_count)
                    print('\t'+instruct)
                    prev_count = prev_count+1
                else:
                    #print('is greater')
                    #print(prev_instruct)
                    show_prev = None
                    prev_count = 0
                    break
            mn = decode.getMn(instruct)
            if mn == 'call' and 'memcpy' in instruct:
                got_one = True
                prev_instruct = instruct
                show_prev=4
                prev_count = 0
                remain_instructs.append(instruct)
            elif mn == 'call':
                break
            if mn == 'jmp':
                break
            #if mn == 'leave':
            #    break
            #if mn == 'mov' and 'esp, ebp' in instruct:
            #    break
            #if checkLEA(instruct, 'ebp', gname):
            #    break
            #if checkMov2(instruct, gname, 'esp'):
            #    break
            #if checkIndMov(instruct, gname, 'eax'):
            #    break
            #if checkAdd(instruct, gname):
            #    break
            #if checkMovExact(instruct, gname, 'edx', 'edi'):
            #if checkMovExact(instruct, gname, 'edx', 'edi'):
            #    got_one = True
            #    break
            if show_prev is None:
                remain_instructs.append(instruct)
        if got_one:
            for instruct in reversed(remain_instructs):
                print('\t'+instruct)

def findOther(gadget_dict, gadget):
        gname = int(gadget)
        got_one = False
        remain_instructs = []
        for instruct in reversed(gadget_dict[gadget]):
            mn = decode.getMn(instruct)
            if mn == 'call':
                break
            if mn == 'jmp':
                break
            #if mn == 'leave':
            #    break
            #if mn == 'mov' and 'esp, ebp' in instruct:
            #    break
            #if checkLEA(instruct, 'ebp', gname):
            #    break
            #if checkMov2(instruct, gname, 'esp'):
            #    break
            #if checkIndMov(instruct, gname, 'eax'):
            #    break
            #if checkAdd(instruct, gname):
            #    break
            #if checkMovExact(instruct, gname, 'edx', 'edi'):
            #if checkMovExact(instruct, gname, 'edx', 'edi'):
            #    got_one = True
            #    break
        if got_one:
            for instruct in reversed(remain_instructs):
                print('\t'+instruct)

def search(fname=None):
    if fname is None:
        #fname = idaversion.get_root_file_name()
        fname = os.getenv('ida_analysis_path')
        if fname is None:
            print('No ida_analysis_path defined')
            fname = idaversion.get_input_file_path()
    print('fname is %s' % fname)  
    gadget_dict = None
    gadget_fname = fname+'.gadgets'
    if not os.path.isfile(gadget_fname):
        return
    with open(gadget_fname, 'r') as fh:
        gadget_dict = json.load(fh) 
        print('%d gadgets' % len(gadget_dict))
    for gadget in gadget_dict:
        findMemcpy(gadget_dict, gadget)
        #findOther(gadget_dict, gadget)
    print('done')

def main():
    parser = argparse.ArgumentParser(prog='searchStaticGadgets', description='search all gadgets in libs in a static list')
    parser.add_argument('ini', action='store', help='The RESim ini file.')
    parser.add_argument('static_list', action='store', help='The list of static DLLs')
    args = parser.parse_args()
    lgr = resimUtils.getLogger('searchStaticGadgets', '/tmp', level=None)
    args = parser.parse_args()
    if not os.path.isfile(args.static_list):
        print('No static list file at %s' % args.static_list)
        exit(1)
    root_dir = resimUtils.getIniTargetValue(args.ini, 'RESIM_ROOT_PREFIX')
    analysis_root_dir = root_dir.replace('images', 'analysis')
    static_paths = getStaticPaths.getStaticPaths(args.static_list, root_dir, lgr)
    print('analysis_root dir %s' % analysis_root_dir)
    os.chdir(analysis_root_dir)
    for item in static_paths:
        base = os.path.basename(item.path)
        #print('found path for %s is %s' % (base, item.path))
        search(fname=item.path)

if __name__ == '__main__':
    sys.exit(main())
if __name__ == "__main__":
    search()
