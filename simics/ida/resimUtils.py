import json
import idc
import idaapi
import idaversion
import idautils
def dumpFuns(fname=None):
    funs = {}
    #ea = get_screen_ea()
    #print 'ea is %x' % ea
    if fname is None:
        #fname = idaversion.get_root_file_name()
        fname = idaversion.get_input_file_path()
    print('dumpFuns inputfile %s' % fname)
    for ea in idautils.Segments():
        start = idaversion.get_segm_attr(ea, idc.SEGATTR_START)
        end = idaversion.get_segm_attr(ea, idc.SEGATTR_END)
        for function_ea in idautils.Functions(start,  end):
            funs[function_ea] = {}
            try:
                end = idc.get_func_attr(function_ea, idc.FUNCATTR_END)
                funs[function_ea]['start'] = function_ea
                funs[function_ea]['end'] = end
                funs[function_ea]['name'] = idaversion.get_func_name(function_ea)
            except KeyError:
                print('failed getting attribute for 0x%x' % function_ea)
                pass
    
    with open(fname+'.funs', "w") as fh:
        json.dump(funs, fh)
        print('Wrote functions to %s.funs' % fname)

def dumpBlocks():
    ''' create a file with one line per function containing a list of each of the function's 
        basic blocks
    '''
    fname = idaversion.get_input_file_path()
    funs_fh = open(fname+'.funs') 
    fun_json = json.load(funs_fh)
    blocks = {}
    for fun in fun_json:
        fun_addr = int(fun)
        print('name %s 0x%x' % (fun_json[fun]['name'], fun_addr))
        block_list = []
        f = idaapi.get_func(fun_addr)
        if f is not None:
            fc = idaapi.FlowChart(f)
            blocks[fun_addr] = {}
            blocks[fun_addr]['name'] = fun_json[fun]['name']
            blocks[fun_addr]['blocks'] = []
            for block in fc:
                #print 'block start is %x' % block.start_ea
                block_entry = {}
                block_entry['start_ea'] = block.start_ea
                block_entry['end_ea'] = block.end_ea
                block_entry['succs'] = []
                for s in block.succs():
                    block_entry['succs'].append(s.start_ea)
                blocks[fun_addr]['blocks'].append(block_entry)
        else:
            print('NO function found for name %s 0x%x' % (fun_json[fun]['name'], fun_addr))
    s = json.dumps(blocks, indent=4)
    with open(fname+'.blocks', 'w') as fh:
        fh.write(s)
    funs_fh.close()
    print('Wrote blocks to %s.blocks' % fname)
