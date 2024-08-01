import json
import idc
import ida_search
import idaapi
import idaversion
import idautils
import ida_segment
import ida_loader
import os
import sys
import logging
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import winProg
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
        fname = os.getenv('ida_analysis_path')
        if fname is None:
            print('No ida_analysis_path defined')
            fname = idaversion.get_input_file_path()
    image_base = os.getenv('target_image_base')
    if image_base is not None and len(image_base.strip())>0:
        image_base = int(image_base, 16)
        current_base = idaapi.get_imagebase()
        #current_base = idautils.peutils_t().imagebase
        delta = image_base - current_base 
        print('image base is 0x%x current_base is 0x%X, delta 0x%x' % (image_base, current_base, delta))
        if delta != 0:
            print('image base is 0x%x current_base is 0x%X, delta 0x%x' % (image_base, current_base, delta))
            ida_segment.rebase_program(delta, ida_segment.MSF_FIXONCE)
        else:
            print('image base is 0x%x current_base is 0x%X, no rebase needed' % (image_base, current_base))
        ida_loader.set_database_flag(ida_loader.DBFL_KILL)
    else:
        print('No image base found as env variable, using existing image_base')
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
                function_name = idaversion.get_func_name(function_ea)
                demangled = idc.demangle_name(
                    function_name,
                    idc.get_inf_attr(idc.INF_SHORT_DN)
                )
                if demangled is not None:
                    function_name = demangled
                funs[function_ea]['name'] = function_name
            except KeyError:
                print('failed getting attribute for 0x%x' % function_ea)
                pass
    
    with open(fname+'.funs', "w") as fh:
        json.dump(funs, fh)
        print('Wrote functions to %s.funs' % fname)
    demangle(fname)
    #unwind(fname)
    dumpImports(fname)

def dumpBlocks():
    ''' create a file with one line per function containing a list of each of the function's 
        basic blocks
    '''
    fname = os.getenv('ida_analysis_path')
    if fname is None:
        print('No ida_analysis_path defined')
        fname = idaversion.get_input_file_path()
    funs_fh = open(fname+'.funs') 
    fun_json = json.load(funs_fh)
    blocks = {}
    for fun in fun_json:
        fun_addr = int(fun)
        #print('name %s 0x%x' % (fun_json[fun]['name'], fun_addr))
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
    ''' TBD not used '''
    flag = idc.SEARCH_DOWN | idc.SEARCH_NEXT
    unwind_list = []
    count = 0
    prev_next = 0
    for ea in idautils.Segments():
        start = idaversion.get_segm_attr(ea, idc.SEGATTR_START)
        done = False
        while not done:
            print('ea is %s' % ea)
            print('ea is 0x%x' % ea)
            next = ida_search.find_text(ea, flag, 0, "unwind", 0)
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

class ImportNames():
    def __init__(self):
        self.imports = {} 

    def imp_cb(self, ea, name, ord):
        if not name:
            #print "%08x: ord#%d" % (ea, ord)
            pass
        else:
            demangled = idc.demangle_name(
                name,
                idc.get_inf_attr(idc.INF_SHORT_DN)
            )
            if demangled is None:
                self.imports[ea] = name 
                print('was NOT demangled %s ea: 0x%x ' % (name, ea))
            else:
                self.imports[ea] = demangled 
                print('was demangled %s to %s ea: 0x%x ' % (name, demangled, ea))
            # ad hoc pain
            if '@@' in name:
                name = name.split('@@')[0]
            #print "%08x: %s (ord#%d)" % (ea, name, ord)
        return True
    def printit(self):
        for ea in self.imports:
            print('0x%x %s' % (ea, self.imports[ea]))

    def dumpit(self, fname):
        with open(fname+'.imports', "w") as fh:
            json.dump(self.imports, fh)
            print('Wrote functions to %s.imports' % fname)

def dumpImports(fname):
    imports = {}
    nimps = idaapi.get_import_module_qty()

    print("Found %d import(s)..." % nimps)
    import_names = ImportNames()
    for i in range(0, nimps):
        name = idaapi.get_import_module_name(i)
        if not name:
            print("Failed to get import module name for #%d" % i)
            continue

        print("Walking-> %s" % name)
        idaapi.enum_import_names(i, import_names.imp_cb)
    import_names.printit()
    import_names.dumpit(fname)

def getString(ea):
    string_type = idc.get_str_type(idaapi.get_item_head(ea))

    if string_type is None:
        return None

    string = idc.get_strlit_contents(ea, strtype=string_type)
    if string is not None:
        return string.decode()
    else:
        return None

def findFunName(s):
    retval = None 
    if s is not None and ': START' in s:
        retval = s.split(':')[0].strip()
    elif s is not None and '::' in s:
        parts = s.split()
        for p in parts:
            if '::' in p:
                if p.endswith('()'):
                    sig = p[:-2]
                elif p.endswith('.') or p.endswith(':'):
                    sig = p[:-1]
                else:
                    sig = p
                if '(' in sig:
                    sig = sig.split('(')[0]
                if sig.startswith('<'):
                    sig = sig[1:-1]
                retval = sig
    return retval

def renameFromLogger():
    for ea in idautils.Segments():
        start = idaversion.get_segm_attr(ea, idc.SEGATTR_START)
        end = idaversion.get_segm_attr(ea, idc.SEGATTR_END)
        for function_ea in idautils.Functions(start,  end):
            fun_name = idaversion.get_func_name(function_ea)
            end = idc.get_func_attr(function_ea, idc.FUNCATTR_END)-1
            done = False
            for head in idautils.Heads(function_ea, end):
                refs = idautils.DataRefsFrom(head)
                for r in refs:
                    s = getString(r)
                    name = findFunName(s)
                    if name is not None:
                        print(name)
                        idaapi.set_name(function_ea, name, idaapi.SN_FORCE)
                        done = True
                        break
                if done:
                    break
                    
