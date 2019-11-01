import idaapi
import idc
import idautils 
#import hashlib
import json
import os
import glob
import functionSig

def difFun(base_sigs, function_ea):
    fun_sig = functionSig.getFunSig(function_ea)
    num_blocks_in_fun = len(fun_sig)
    done = False
    fun_name = idc.GetFunctionName(function_ea)
    print('look for match of fun name %s, num blocks is %d' % (fun_name, num_blocks_in_fun))
    if fun_name in base_sigs:
        base_blocks = base_sigs[fun_name]
    else:
        print('%s not in base blocks' % fun_name)
        sys.exit(1)
    
    for block_hash in base_blocks:
        if block_hash not in fun_sig:
            print('base function block %s with hash of %s missing from RCB' % (str(base_blocks[block_hash]), block_hash))
    for block_hash in fun_sig:
        if block_hash not in base_blocks:
            print('RCB function block %s with hash of %s missing from base' % (str(fun_sig[block_hash]), block_hash))
    
    

def difSignatures():
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
    else:
        rcb = os.path.basename(path)
        csid = rcb.split('-')[1]
        look_for = sig_dir+'/*%s*.json' % csid
        flist = glob.glob(look_for)
        if len(flist) == 0:
            print('no json found for %s' % look_for)
            exit(1)
        rcb_file = flist[0]
        print('found json of %s' % rcb_file)

    with open(rcb_file) as fh:
        print('got blocks from %s' % rcb_file)
        base_json = json.load(fh)
        ea = idc.get_screen_ea()
        #print('find match for 0x%x' % ea) 
        #findMatch(base_json, idc.get_screen_ea())
        print('try %x' % ea) 
        difFun(base_json, ea)
        print('%d functions in base' % len(base_json))
       
        
       

if __name__ == '__main__':
    

    ea = idc.get_screen_ea()
    sig_dir = '/tmp'
    fname = idaapi.get_root_filename() 
    print('file is %s' % fname)
    difSignatures()
            

