import json
import idc
import idaapi
import idaversion
import idautils
def demangle(fname):
    mangle_map = {}
    for mangled in idautils.Functions():
        fun_name = str(idaapi.get_func_name(mangled))
        #print('fun %s' % fun_name)
        demangled = idc.demangle_name(
            fun_name,
            idc.get_inf_attr(idc.INF_SHORT_DN)
        )
     
        if demangled is not None:
            if fun_name.startswith('_'):
                fun_name = fun_name[1:]
            mangle_map[fun_name] = demangled
    s = json.dumps(mangle_map, indent=4)
    with open(fname+'.mangle', 'w') as fh:
        fh.write(s)
    print('Wrote mangle to %s.mangle' % fname)

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
            #unwind = idc.find_text(function_ea, 1, 0, 0, "unwind")
            try:
                fun_end = idc.get_func_attr(function_ea, idc.FUNCATTR_END)-1
                funs[function_ea]['start'] = function_ea
                funs[function_ea]['end'] = fun_end
                funs[function_ea]['name'] = idaversion.get_func_name(function_ea)
            except KeyError:
                print('failed getting attribute for 0x%x' % function_ea)
                pass
    
    with open(fname+'.funs', "w") as fh:
        json.dump(funs, fh)
        print('Wrote functions to %s.funs' % fname)
    demangle(fname)
    unwind(fname)

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

def getHex(s):
    retval = None
    hs = s
    if not hs.startswith('0x'):
        hs = '0x'+s
    try:
        retval = int(hs, 16)
    except:
        pass
    return retval

def unwind(fname):
    flag = idc.SEARCH_DOWN | idc.SEARCH_NEXT
    unwind_list = []
    count = 0
    prev_next = 0
    for ea in idautils.Segments():
        start = idaversion.get_segm_attr(ea, idc.SEGATTR_START)
        done = False
        while not done:
            next = idc.find_text(ea, flag, 0, 0, "unwind")
            if next == prev_next:
                break
            if next is None or next == 0:
                break
            if next not in unwind_list:
                unwind_list.append(next) 
            #print('unwind at 0x%x' % next)
            ea = next+8
            count = count + 1
            if count > 10000:
                break
            prev_next = next 
    s = json.dumps(unwind_list, indent=4)
    with open(fname+'.unwind', 'w') as fh:
        fh.write(s)
    print('Wrote unwind addresses to %s.unwind' % fname)
