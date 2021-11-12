import idaapi
import idc
import idautils 
#import hashlib
import json
import os
import glob
import sys
'''
Manage CGC function signatures
'''

def getBlockSig(block):
    hstring = ''
    for head in idautils.Heads(block.startEA, block.endEA):
        instruct = idc.GetDisasm(head)

        #print('head is %s instr: %s' % (str(head), str(instruct)))
        if instruct.startswith('call'):
            instruct = 'call'
        elif instruct.startswith('j'):
            instruct = idc.GetMnem(head)
        elif 'ds:' in instruct:
            instruct = instruct[:instruct.find(',')]
        elif instruct.startswith('lea') and instruct != 'leave':
            parts = instruct.split(',')
            try:
                if not parts[1].strip().startswith('['):
                    instruct = parts[0]
            except:
                print('trouble with %x %s' % (head, instruct))
                sys.exit(1)
        elif ';' in instruct:
            instruct = instruct.split(';')[0].strip()
        #print instruct
        hstring += '%s' % str(instruct).strip()
    a_hash = hash(hstring)
    h_string = '%x' % a_hash
    return h_string

def findBlock():
    a_hash = None
    ea = idc.get_screen_ea()
    print('get block for %x' % ea)
    f = idaapi.get_func(ea)
    fc = idaapi.FlowChart(f)
    for block in fc:
        if ea >= block.startEA and ea <= block.endEA:
            a_hash = getBlockSig(block)
            print('hash is %s' % a_hash) 
    return a_hash
    
def getFunSig(function_ea):
    fun_sig = {}
    f = idaapi.get_func(function_ea)
    fc = idaapi.FlowChart(f)
    for block in fc:
        h_string = getBlockSig(block)
        b_string = '%x' % block.startEA
        fun_sig[h_string] = b_string
        #print('%s %s' % (h_string, b_string))
    return fun_sig

def dumb(base_sigs, function_ea):
    fun_sig = getFunSig(function_ea)
    print('this')
    for block in fun_sig:
        print('0x%s  %s' % (fun_sig[block], block))

    print('base')
    fun_name = idc.GetFunctionName(function_ea)
    for block in base_sigs[fun_name]:
        print('0x%s  %s' % (base_sigs[fun_name][block], block))

def findMatch(base_sigs, function_ea, bar=0.85):
    '''
    Given a set of reference function signatures (base_sigs), see if the given function matches any of them.
    '''
    fun_sig = getFunSig(function_ea)
    #print('num base sigs is %d  num blocks in %x is %d' % (len(base_sigs), function_ea, len(fun_sig)))
    #for block in fun_sig:
    #    print('start: %s  %s' % (fun_sig[block], block))
    num_blocks_in_fun = len(fun_sig)
    done = False
    fun_name = idc.GetFunctionName(function_ea)
    print('look for match of fun name %s' % fun_name)
    best_match = 0
    best_fun = None
    got_it = False
    num_blocks_in_best = 0

    ''' look at each reference function '''
    for base_fun in base_sigs:
        #if base_fun != fun_name:
        #   continue
        #print('check %s' % base_fun)
        ''' skip functions with big difference in block counts '''
        num_blocks = len(base_sigs[base_fun])
        blocks_ratio = float(float(num_blocks)/float(num_blocks_in_fun))
        if num_blocks > 5 and (blocks_ratio < 0.5 or blocks_ratio > 1.5):  
            continue

        tot_count = 0
        found_count = 0
        for block_hash in base_sigs[base_fun]:
            #print('start: %s  %s' % (base_sigs[base_fun][block_hash], block_hash))
            if block_hash in fun_sig:
                found_count += 1 
            tot_count += 1
        #print('found %d of %d' % (found_count, tot_count)) 
        matched = float(float(found_count)/float(tot_count))
        if matched > best_match:
            best_match = matched
            best_fun = base_fun
            num_blocks_in_best = num_blocks
    if not got_it and best_match > 0.4:
        extra=''
        if best_match < 1.0:
            extra='******************** in rcb: %d in base: %d' % (num_blocks_in_fun, num_blocks_in_best)
        print('best match is %f, function is %s %s' % (best_match, best_fun, extra))
        if not best_fun.startswith('sub_'):
            idc.MakeNameEx(function_ea, str(best_fun), 0)
        #print('best match, called makename with 0x%x and %s' % (function_ea, best_fun))
    else:
        print('no match %f *****************' % best_match)

def genSignatures():

    ea = idc.get_screen_ea()
    sig_dir = '/tmp'
    fname = idaapi.get_root_filename() 
    print('file is %s' % fname)
    base_file = os.path.join(sig_dir, fname)+'.json'
    seg_start = idc.SegStart(ea)
    seg_end = idc.SegEnd(ea)
    print('seg start: %x  seg_end: %x' % (seg_start, seg_end))
    blocks = open(base_file, 'w')
    fun_sig = {}
    for function_ea in idautils.Functions(seg_start, seg_end):
        fun_name = idc.GetFunctionName(function_ea)
        fun_sig[fun_name] = getFunSig(function_ea)
    blocks.write(json.dumps(fun_sig))
    print('done creating %s' % base_file)
    blocks.flush()
    blocks.close()

def querySignatures():
    path = idaapi.get_input_file_path() 
    print('path is %s' % path)
    parts = path.split('/')
    index = 0
    cndex = 0
    sig_dir = '/tmp'
    if 'CBs' in parts:
        for p in parts:
            if p == 'CBs':
                cindex = index+1
                break
            else:
                index += 1
        common = path.split('/')[5]+"_01"
        common = parts[cindex]+"_01"
        rcb_file = os.path.join(sig_dir, common)+".json" 
    elif '_MG' in path:
        rcb = os.path.basename(path)
        parts = rcb.split('_')
        rebuild = parts[0]+'_'+parts[1]+'_'+parts[3]
        rcb_file = os.path.join(sig_dir, rebuild)+".json"
    else:
        rcb = os.path.basename(path)
        csid = rcb.split('-')[1]
        look_for = sig_dir+'/*%s*.json' % csid
        flist = glob.glob(look_for)
        if len(flist) == 0:
            print('no json found for %s' % look_for)
            sys.exit(1)
        for f in flist:
            print(f)
            rcb_file = f
            if f.startswith('CB'):
                break
        print('found json of %s' % rcb_file)

    with open(rcb_file) as fh:
        print('got blocks from %s' % rcb_file)
        base_json = json.load(fh)
        ea = idc.get_screen_ea()
        #print('find match for 0x%x' % ea) 
        #findMatch(base_json, idc.get_screen_ea())
        
        seg_start = idc.SegStart(ea)
        seg_end = idc.SegEnd(ea)
        print('%d functions in base' % len(base_json))
        print('seg_start/end %x %x' % (seg_start, seg_end))
        for function_ea in idautils.Functions(seg_start, seg_end):
            print('try %x' % function_ea)
            findMatch(base_json, function_ea)
       
        
       

if __name__ == '__main__':
    

    ea = idc.get_screen_ea()
    sig_dir = '/tmp'
    fname = idaapi.get_root_filename() 
    print('file is %s' % fname)
    if fname.startswith('CB') and not '_MG' in fname:
        genSignatures()
    else:
        querySignatures()
            

