import time
import idaapi
if idaapi.IDA_SDK_VERSION <= 699:
    import idc
 
else:
    import ida_idaapi
    import ida_dbg
    import ida_kernwin
    import ida_nalt
    import idc
    import ida_bytes
    import ida_funcs

def refresh_debugger_memory():
    if idaapi.IDA_SDK_VERSION <= 699:
        return idc.RefreshDebuggerMemory()
    else:
        return ida_dbg.refresh_debugger_memory()
   
def get_bpt_qty(): 
    if idaapi.IDA_SDK_VERSION <= 699:
        return idc.GetBptQty()
    else:
        return ida_dbg.get_bpt_qty()

def check_bpt(bptEA):
    if idaapi.IDA_SDK_VERSION <= 699:
        return idc.CheckBpt(bptEA)
    else:
        return ida_dbg.check_bpt(bptEA)

def add_bpt(bptEA):
    if idaapi.IDA_SDK_VERSION <= 699:
        return idc.AddBpt(bptEA)
    else:
        return ida_dbg.add_bpt(bptEA)

def wait_for_next_event(kind, flag):
    if idaapi.IDA_SDK_VERSION <= 699:
        event = idc.GetDebuggerEvent(kind, flag)
    else:
        event = ida_dbg.wait_for_next_event(kind, flag)

def ask_str(default, label, hist=0):
    if idaapi.IDA_SDK_VERSION <= 699:
        mark = idc.AskStr(default, label)
    else:
        mark = ida_kernwin.ask_str(default, hist, label)
    return mark

def getHighlight():
    if idaapi.IDA_SDK_VERSION <= 699:
        retval = idaapi.get_highlighted_identifier()
    else:
        v = ida_kernwin.get_current_viewer()
        t = ida_kernwin.get_highlight(v)
        retval = None
        if t is None:
            print('Nothing highlighted in viewer %s' % str(v))
        else:
            retval, flags = t 
    return retval

def get_reg_value(reg):
    retval = None
    if idaapi.IDA_SDK_VERSION <= 699:
        retval = idc.GetRegValue(reg)
    else:
        try:
            retval = idc.get_reg_value(reg)
        except:
            print('ERROR  failed getting value for reg %s' % reg)
    return retval

def getRegVarValue(reg):
    retval = None 
    if idaapi.IDA_SDK_VERSION <= 699:
        try:
            retval = get_reg_value(reg)
        except: 
            ''' reg is a symbol, get its value and read memory at that address '''
            x = idc.get_name_ea_simple(reg)
            retval = idc.read_dbg_dword(x)
    else:
        ea = idaapi.get_screen_ea()
        regvar_map = {}
        fn = ida_funcs.get_func(ea)
        if fn:
            for rv in fn.regvars:
                regvar_map[rv.user] = rv.canon
                #print('set regvar_map[%s] to %s' % (rv.user, rv.canon))
        if reg in regvar_map:
            reg = regvar_map[reg]
        else:
            print('%s not in map' % (reg))
        retval = idc.get_reg_value(reg)
    return retval


def get_full_flags(ea):
    if idaapi.IDA_SDK_VERSION <= 699:
        flags = idc.GetFlags(ea)
    else:
        flags = ida_bytes.get_full_flags(ea)
    return flags

def is_code(ea):
    if idaapi.IDA_SDK_VERSION <= 699:
        retval = idc.IsCode(ea)
    else:
        retval = ida_bytes.is_code(ea)
    return retval

def get_opinfo(ti, ea, zero, f):
    if idaapi.IDA_SDK_VERSION <= 699:
        print('NOT SUPPORTED ON IDA 6.8')
        retval = False
    else:
        retval = ida_bytes.get_opinfo(ti, ea, zero, f)
    return retval

def is_code(ea):
    if idaapi.IDA_SDK_VERSION <= 699:
        retval = idc.IsCode(ea)
    else:
        retval = ida_bytes.is_code(ea)
    return retval

def del_items(start, count):
    if idaapi.IDA_SDK_VERSION <= 699:
       idc.MakeUnknown()
    else:
       ida_bytes.del_items(start, count)


def refresh_idaview_anyway():
    if idaapi.IDA_SDK_VERSION <= 699:
        idc.RefreshIdaView()
    else: 
        ida_kernwin.refresh_idaview_anyway()

def refresh_choosers():
    if idaapi.IDA_SDK_VERSION <= 699:
        idc.RefreshLists()
    else: 
        ida_kernwin.refresh_choosers()

def get_input_file_path():
    if idaapi.IDA_SDK_VERSION <= 699:
        retval = idc.GetInputFilePath()
    else:
        retval = ida_nalt.get_input_file_path()
    return retval

def get_root_file_name():
    if idaapi.IDA_SDK_VERSION <= 699:
        retval = idc.GetRootFileName()
    else:
        retval = ida_nalt.get_root_filename()
    return retval

def ask_addr(value, prompt):
    if idaapi.IDA_SDK_VERSION <= 699:
        retval = idc.AskAddr(value, prompt)
    else:
        retval = ida_kernwin.ask_addr(value, prompt)
    return retval

def ask_long(value, prompt):
    if idaapi.IDA_SDK_VERSION <= 699:
        retval = idc.AskLong(value, prompt)
    else:
        retval = ida_kernwin.ask_long(value, prompt)
    return retval

def rebase_program(start_hex, offset):
    if idaapi.IDA_SDK_VERSION <= 699:
        idc.RebaseProgram(start_hex, offset)
    else:
        ida_segment.rebase_program(start_hex, offset) 


def add_func(fun, flag):
    if idaapi.IDA_SDK_VERSION <= 699:
        idc.AddFunc(fun, flag) 
    else:
        ida_funcs.add_func(fun, flag)


def find_widget(title):
    if idaapi.IDA_SDK_VERSION <= 699:
        form = idaapi.find_tform(title)
    else:
        form=ida_kernwin.find_widget(title)
    return form

def activate_widget(form, active):
    if idaapi.IDA_SDK_VERSION <= 699:
        idaapi.switchto_tform(form, active)
    else:
        ida_kernwin.activate_widget(form, active)

def get_current_widget():
    if idaapi.IDA_SDK_VERSION <= 699:
        form = idaapi.get_current_tform()
    else:
        form = ida_kernwin.get_current_widget()
    return form

def get_cust_viewer(title):
    retval = None
    form = find_widget(title)
    if form is not None:
        activate_widget(form, True)
        retval = ida_kernwin.get_current_viewer()
    return retval
        

def grab_focus(title):
    done = False
    limit = 10
    i=0
    while not done:
        form = find_widget(title)
        if form is None:
            print('No form titled %s' % title)
            break
        activate_widget(form, True)
        done=True
        '''
        TBD: get_current does not really get the current, it gets whatever was current when the script started
        cur_form = get_current_widget()
        if form == cur_form:
            done = True
        else:
            cur_form = ida_kernwin.get_current_viewer()
            if cur_form == form:
                print('**but the viewer matches?')
                done = True
            else:
                print('failed grab focus %s' % title)
                time.sleep(1)
                i = i+1
                if i > limit:
                    done = True
        '''

def get_widget_type(form):
    if idaapi.IDA_SDK_VERSION <= 699:
        retval = idaapi.get_tform_type(form) 
    else:
        retval = ida_kernwin.get_widget_type(form) 
    return retval

def get_segm_name(seg_ea):
    if idaapi.IDA_SDK_VERSION <= 699:
        retval = idc.SegName(seg_ea)
    else:
        retval = idc.get_segm_name(seg_ea)
    return retval

def get_segm_attr(seg_ea, attr):
    if idaapi.IDA_SDK_VERSION <= 699:
        retval = idc.GetSegmentAttr(seg_ea, attr)
    else:
        retval = idc.get_segm_attr(seg_ea, attr)
    return retval

def batch(num):
    if idaapi.IDA_SDK_VERSION <= 699:
        idc.Batch(num)
    else:
        idc.batch(num)

def prev_head(curAddr):
    if idaapi.IDA_SDK_VERSION <= 699:
        prev_eip = idc.PrevHead(curAddr)
    else:
        prev_eip = idc.prev_head(curAddr)
    return prev_eip

def next_head(curAddr):
    if idaapi.IDA_SDK_VERSION <= 699:
        next_eip = idc.NextHead(curAddr)
    else:
        next_eip = idc.next_head(curAddr)
    return next_eip

def set_reg_value(reg, value):
    if idaapi.IDA_SDK_VERSION <= 699:
        idc.SetRegValue(reg, value)
    else:
        try:
            idc.set_reg_value(value, reg)
        except:
            print('ERROR setting reg %s' % reg)

def get_screen_ea():
    if idaapi.IDA_SDK_VERSION <= 699:
        cursor = idc.GetScreenEA()
    else:
        cursor = idc.get_screen_ea()
    return cursor

def get_operand_value(ea, opnum):
    if idaapi.IDA_SDK_VERSION <= 699:
        offset = idc.GetOperandValue(ea, opnum)
    else:
        offset = idc.get_operand_value(ea, opnum)
    return offset

def get_operand_type(ea, opnum):
    if idaapi.IDA_SDK_VERSION <= 699:
        offset = idc.GetOpType(ea, opnum)
    else:
        offset = idc.get_operand_type(ea, opnum)
    return offset

def get_func_name(ea):
    if idaapi.IDA_SDK_VERSION <= 699:
        fun = idc.GetFunctionName(ea)
    else:
        fun = idc.get_func_name(ea)
    return fun


def get_prev_offset(sid, cur_offset):
    if idaapi.IDA_SDK_VERSION <= 699:
        prev = idc.GetStrucPrevOff(sid, cur_offset)
    else:
        prev = idc.get_prev_offset(sid, cur_offset)
    return prev

def get_member_name(sid, cur_offset):
    if idaapi.IDA_SDK_VERSION <= 699:
        mn = idc.GetMemberName(sid, cur_offset)
    else:
        mn = idc.get_member_name(sid, cur_offset)
    return mn

def get_member_name(sid, cur_offset):
    if idaapi.IDA_SDK_VERSION <= 699:
        mn = idc.GetMemberName(sid, cur_offset)
    else:
        mn = idc.get_member_name(sid, cur_offset)
    return mn

def get_next_offset(sid, cur_offset):
    if idaapi.IDA_SDK_VERSION <= 699:
        mn = idc.GetStrucNextOff(sid, cur_offset)
    else:
        mn = idc.next_offset(sid, cur_offset)
    return mn

def get_last_member(sid):
    if idaapi.IDA_SDK_VERSION <= 699:
        id = idc.GetLastMember(sid)
    else:
        id = idc.last_member(sid)
    return id

def get_wide_dword(addr):
    if idaapi.IDA_SDK_VERSION <= 699:
        retval = idc.Word(addr)
    else:
        retval = idc.get_wide_dword(addr)
    return retval

def get_wide_byte(addr):
    if idaapi.IDA_SDK_VERSION <= 699:
        retval = idc.Bytes(addr)
    else:
        retval = idc.get_wide_byte(addr)
    return retval

def get_bpt_ea(i):
    if idaapi.IDA_SDK_VERSION <= 699:
        bpt_ea = idc.GetBptEA(i)
    else:
        bpt_ea = idc.get_bpt_ea(i)
    return bpt_ea

def make_code(eip):
    if idaapi.IDA_SDK_VERSION <= 699:
        idc.MakeCode(eip)
    else:
        idc.create_insn(eip)

def step_into():
    if idaapi.IDA_SDK_VERSION <= 699:
        idc.StepInto()
    else:
        ida_dbg.step_into()

def step_over():
    if idaapi.IDA_SDK_VERSION <= 699:
        idc.StepOver()
    else:
        ida_dbg.step_over()
