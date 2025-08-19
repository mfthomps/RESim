import json
import idc
import ida_search
import idaapi
import idaversion
import idautils
import ida_segment
import ida_loader
import ida_bytes
import ida_funcs
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
        #fname = '/tmp/myanalysis'
        fname = os.getenv('ida_analysis_path')
        if fname is None:
            print('No ida_analysis_path defined')
            fname = idaversion.get_input_file_path()
    print('dumpFuns fname %s' % fname)
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
                print('try adjustStack fun %s fun ea 0x%x' % (function_name, function_ea))
                adjust_sp = adjustStack(function_name, function_ea)
                if adjust_sp is not None:
                    #print('function %s function_ea 0x%x will adjust 0x%x' % (function_name, function_ea, adjust_sp))
                    funs[function_ea]['adjust_sp'] = adjust_sp
            except KeyError:
                print('failed getting attribute for 0x%x' % function_ea)
                pass

    
    with open(fname+'.funs', "w") as fh:
        json.dump(funs, fh)
        print('Wrote functions to %s.funs' % fname)
    demangle(fname)
    #unwind(fname)
    dumpImports(fname)
    dumpExports(fname, funs)

def dumpBlocks():
    ''' create a file with one line per function containing a list of each of the function's 
        basic blocks
    '''
    fname = os.getenv('ida_analysis_path')
    #fname = '/tmp/myanalysis'
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
                #print('was NOT demangled %s ea: 0x%x ' % (name, ea))
            else:
                self.imports[ea] = demangled 
                #print('was demangled %s to %s ea: 0x%x ' % (name, demangled, ea))
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

    def armBlrXrefs(self, fname):
        # ARM64 BLR and BR calls that first load offsets of imports that we should know.
        arm_blr = {}
        for ea in self.imports:
            fun = self.imports[ea]
            #print('do xrefs ea 0x%x fun %s' % (ea, fun))
            refs = idautils.DataRefsTo(ea)
            for ref in refs:
                print('\timports for fun %s entry 0x%x found ref 0x%x' % (fun, ea, ref))
                fun_refs = idautils.DataRefsTo(ref)
                for fr in fun_refs:
                    fr_instruct = idc.GetDisasm(fr)
                    if fr_instruct.startswith('LDR'):
                        insn = idaapi.insn_t()
                        instruct_len = idaapi.decode_insn(insn, fr)
                        our_reg = insn.ops[0].reg            
                        next_pc = fr
                        print('\t\tfun ref 0x%x %s our_reg = %s' % (fr, fr_instruct, our_reg))
                        for i in range(8):
                            next_pc = next_pc + 4
                            instruct = idc.GetDisasm(next_pc)
                            if instruct.startswith('BLR') or instruct.startswith('BR'):
                                next_insn = idaapi.insn_t()
                                next_instruct_len = idaapi.decode_insn(next_insn, next_pc)
                                if our_reg == next_insn.ops[0].reg:
                                    print('\t\t\timports fun_ref 0x%x next instruct 0x%x %s' % (fr, next_pc, instruct))
                                    if next_pc not in arm_blr:
                                        arm_blr[next_pc] = fun
                                    break
        with open(fname+'.arm_blr', "w") as fh:
            json.dump(arm_blr, fh)

    def x86RegCallXrefs(self, fname):
        # x86 mov eax, ds:some_xref
        x86_call_reg = {}
        for ea in self.imports:
            fun = self.imports[ea]
            print('do xrefs ea 0x%x fun %s' % (ea, fun))
            refs = idautils.DataRefsTo(ea)
            for ref in refs:
                ref_instruct = idc.GetDisasm(ref)
                print('\timports for 0x%x found ref 0x%x instruct %s' % (ea, ref, ref_instruct))
                if ref_instruct.startswith('mov'): 
                    insn = idaapi.insn_t()
                    instruct_len = idaapi.decode_insn(insn, ref)
                    our_reg = insn.ops[0].reg            
                    print('\t len of mov is %d' % instruct_len)
                    next_pc = ref 
                    for index in range(4):
                        next_pc = next_pc + instruct_len
                        instruct = idc.GetDisasm(next_pc)
                        instruct_len = idaapi.decode_insn(insn, next_pc)
                        print('\t\t next_pc 0x%x instruct %s len is %d' % (next_pc, instruct, instruct_len))
                        if instruct.startswith('call'):
                            call_reg = insn.ops[0].reg
                            if call_reg == our_reg and next_pc not in x86_call_reg:
                                x86_call_reg[next_pc] = fun
                                print('\t\timports adding fun_ref 0x%x next instruct 0x%x %s' % (ref, next_pc, instruct))
                            break
                        #instruct_len = ida_bytes.get_item_size(next_pc)
                        insn = idaapi.insn_t()

        with open(fname+'.x86_call_reg', "w") as fh:
            json.dump(x86_call_reg, fh)
    

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
    #import_names.printit()
    import_names.dumpit(fname)
    import_names.armBlrXrefs(fname)
    import_names.x86RegCallXrefs(fname)

def dumpExports(fname, funs):
    # TBD, for now intended use is to catch export names that map to library functions.
    # Does not yet handle exports whose addresses do not appear in functions list.
    exports = {}
    export_list = list(idautils.Entries())
    for exp_i, exp_ord, exp_ea, exp_name in export_list:
        if exp_ea not in funs or funs[exp_ea]['name'] != exp_name:
            exports[exp_name] = {}
            fun_end = idc.get_func_attr(exp_ea, idc.FUNCATTR_END)-1
            exports[exp_name]['start'] = exp_ea
            exports[exp_name]['end'] = fun_end
            #print('try adjustStack fun %s fun ea 0x%x' % (function_name, function_ea))
            #adjust_sp = adjustStack(exp_ea)
            #if adjust_sp is not None:
            #    #print('function %s function_ea 0x%x will adjust 0x%x' % (exp_name, exp_ea, adjust_sp))
            #    exports[exp_ea]['adjust_sp'] = adjust_sp
        else:
            #print('funs NOT missing exported %s addr 0x%x' % (exp_name, exp_ea))
            pass
    with open(fname+'.exports', "w") as fh:
        json.dump(exports, fh)
        print('Wrote functions to %s.exports' % fname)


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
                    
def adjustStack(function_name, fun_ea):
    ''' Search end of function for indications of stack adjustment.  Used as an aide to stack tracing '''
    # TBD can't all architectures use pfn.points like PPC32?
    info = idaapi.get_inf_structure()
    if info.procname == 'PPC':
        pfn = ida_funcs.get_fchunk(fun_ea)
        if pfn.pntqty == 0:
            return 0
        adjust_total = 0
        for i in range(pfn.pntqty):
            adjust = pfn.points[i].spd * -1
            adjust_total = adjust_total + adjust 
            print('ppc adjust 0x%x (%s) index %d set to 0x%x total now 0x%x' % (fun_ea, function_name, i, adjust, adjust_total))
            if adjust_total > 0:
                # grows to large if all included.  strrchr for example.  are these adjustments that likely happen independently?
                break
        return adjust_total
    if info.is_32bit():
        word_size = 4
    else:
        word_size = 8
    ip_list = []
    for item_ea in idautils.FuncItems(fun_ea):
        ip_list.append(item_ea)
    count=0
    adjust = 0
    got_ret = False
    for item_ea in reversed(ip_list):
        ins = idautils.DecodeInstruction(item_ea)
        mn = ins.get_canon_mnem().lower()
        if not got_ret:
            if not mn.startswith('ret'):
                continue
            else:
                got_ret=True

        #if fun_ea == 0x688f1d30:
#
#            print('proc %s ea 0x%x mn is %s' % (info.procname, item_ea, mn))
#            op0 = idc.print_operand(item_ea, 0)
#            print('op0 is %s' % op0)
#            op1 = idc.print_operand(item_ea, 1)
#            print('op1 is %s' % op1)
#            op2 = idc.print_operand(item_ea, 2)
#            print('op2 is %s' % op2)


        if mn == 'add':
            op0 = idc.print_operand(item_ea, 0).lower()
            if 'sp' in op0:
                if info.procname.startswith('ARM'):
                    op2 = idaversion.get_operand_value(item_ea, 2)
                    #print('is SP, op2 value is 0x%x' % op2)
                    adjust = adjust+op2
                else:
                    op1 = idaversion.get_operand_value(item_ea, 1)
                    adjust = adjust+op1
                break
        elif info.procname == 'ARM' and mn.startswith('l'):
            #print('is arm item_ea 0x%x mn %s' % (item_ea, mn))
            if mn.startswith('ldp'):
                addr_op = idc.print_operand(item_ea, 2).lower()
            else: 
                addr_op = idc.print_operand(item_ea, 1).lower()
            #print('adr_op for 0x%x is %s' % (item_ea, addr_op))
            if addr_op.startswith('[sp'):
                print('fun_ea 0x%x addr_op is SP:  %s' % (fun_ea, addr_op))
                if '],' in addr_op:
                    parts = addr_op.split('],')
                    value = getValue(parts[-1])
                    adjust = adjust+value
                    print('value got 0x%x' % value)
                    break
        # WARNING x86 code may have pushes mid-code, cannot always rely on pops
        #elif info.procname == 'metapc' and mn.startswith('pop'):
        #    adjust = adjust + word_size
            
        count += 1
        if count > 10:
            break
    #if adjust is not None:
    #    print('adjust sp by 0x%x' % adjust)
    return adjust

def getValue(item):
    item = item.strip()
    value = None
    if item.startswith('#'):
        if item.startswith('#0x'):
            try:
                value = int(item[3:], 16)
            except:
                print('failed to get value from %s' % item)
                return None
        else:
            try:
                value = int(item[1:])
            except:
                print('failed to get value from %s' % item)
                return None
    else:
        try:
            value = int(item, 16)
        except:
            try:
                value = int(item)
            except:
                print('failed to get value from %s' % item)
    return value 
