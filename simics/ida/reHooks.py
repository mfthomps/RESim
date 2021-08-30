import idaapi
import idautils
import idaversion
import time
if idaapi.IDA_SDK_VERSION <= 699:
    from idaapi import Form
    from idaapi import UI_Hooks
else:
    from ida_kernwin import Form
    from ida_kernwin import UI_Hooks
import idc
import gdbProt
import regFu
import getAddrCount
import setAddrValue
import setAddrString



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

def getRegOffset(eax, reg, opnum):
    reg_val = idaversion.getRegVarValue(reg)
    #except: 
    #    ''' reg is a symbol, get its value and read memory at that address '''
    #    x = idc.get_name_ea_simple(reg)
    #    reg_val = idc.read_dbg_dword(x)
    #    print('reg %s is symbol, got x of 0x%x, read that to get 0x%x' % (reg, x, reg_val))
    offset = idaversion.get_operand_value(eax, opnum)
    retval = reg_val+offset
    return retval 

def getRefAddr():
    ''' Get address from the operand currently under the cursor.
        If just a register, use that.  If calculated within brackets,
        try decoding that.
    '''
    retval = None
    ea = idaversion.get_screen_ea()
    flags = idaversion.get_full_flags(ea)
    if idaversion.is_code(flags):
        opnum = idaapi.get_opnum()
        op_type = idaversion.get_operand_type(ea, opnum)
        op = idc.print_operand(ea, opnum)
        print('is code, type %d op %s' % (op_type, op))
        #if op_type == idc.o_disp:
        if op_type == 4:
            ''' displacement from reg address '''
            val = op.split('[', 1)[1].split(']')[0]
            if ',' in val:
                reg = val.split(',')[0]
                retval = getRegOffset(ea, reg, opnum)
            elif '+' in val:
                reg = val.split('+')[0]
                retval = getRegOffset(ea, reg, opnum)
            else:
                try:
                    retval = idaversion.getRegVarValue(val)
                except: 
                   print('%s not a reg' % reg)
        elif op_type == 3:
            retval = idaversion.get_operand_value(ea, opnum)
        elif op_type == 1:
            retval = idaversion.getRegVarValue(op)
        else:
            print('Op type %d not handled' % op_type)
    else:
        return ea
    return retval
   

def getFieldName(ea, offset):
    '''
    Get an IDA Structure field for a given offset into a structure at a given
    field.  Display as full element name, qualified with array indices as appropriate.

    We assume that "offset" is into the sid alone, not relative to the start of the
    parent structure.  First get the sid of the top-level struct as given by ea.
    Then loop:
       get name of struct at current offset into current sid
       if name is none, we are in an array, and past the first element
           get last member of current sid
           get the next offset after the last member
           assume that offset is the size of the array elements
           use MOD to get offset into element strcture
           get name can continue; if no name, bail
    '''
    print('getFieldName 0x%x' % ea)
    full_name = None        
    ti = idaapi.opinfo_t()
    f = idaversion.get_full_flags(ea)
    if idaversion.get_opinfo(ti, ea, 0, f):
       #print ("tid=%08x - %s" % (ti.tid, idaversion.get_struc_name(ti.tid)))
       sid = ti.tid
       full_name = idaversion.get_struc_name(sid)
       cur_offset = offset
       while True:
           element = None
           prev = idaversion.get_prev_offset(sid, cur_offset)
           #print('prev is %d ' % (prev))
           mn = idaversion.get_member_name(sid, cur_offset)
           #print('get_member_name sid 0x%x offset %d got %s' % (sid, cur_offset, mn))
           if mn is None:
               #print('mn none')
               last = idaversion.get_last_member(sid)
               over = idaversion.get_next_offset(sid, last)
               #print('last %d  over %d' % (last, over))
               element = int(cur_offset / over)
               cur_offset = cur_offset % over
               mn = idaversion.get_member_name(sid, cur_offset)
               #print('in array get_member_name sid 0x%x offset %d got %s array element %d' % (sid, cur_offset, mn, element))
               if mn is None:
                   break
           mem_off = idaversion.get_member_offset(sid, mn)
           #print('mn now %s offset %d' % (mn, mem_off))
           if element is None:
               full_name = full_name+'.'+mn
           else:
               full_name = '%s[%d].%s' % (full_name, element, mn)
           sid = idaversion.get_member_strid(sid, cur_offset)
           #print('new sid 0x%x cur_offset %d' % (sid, cur_offset))
           cur_offset = cur_offset - mem_off

           if sid < 0:
               #print('sid bad')
               break
       #print('full name: %s' % full_name)

    else:
       print('failed to get opinfo for 0x%x' % ea)
    return full_name

class RevToHandler(idaapi.action_handler_t):
        def __init__(self, isim):
            idaapi.action_handler_t.__init__(self)
            self.isim = isim
        # reverse to the highlighted address
        def activate(self, ctx):
            highlighted = idaversion.getHighlight()
            addr = getHex(highlighted)
            command = '@cgc.revToAddr(0x%x, extra_back=0)' % (addr)
            print('cmd: %s' % command)
            simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
            eip = gdbProt.getEIPWhenStopped()
            self.isim.signalClient()
            return 1

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

class ModRegHandler(idaapi.action_handler_t):
        def __init__(self, isim):
            idaapi.action_handler_t.__init__(self)
            self.isim = isim
        def activate(self, ctx):
            highlighted = idaversion.getHighlight()
            current = idaversion.getRegVarValue(highlighted)
            default = '%x' % current
            print('default %s' % default)
            #prompt = 'Value to write to %s (in hex, no prefix)' % highlighted
            #print('prompt is %s' % prompt)
            #enc = prompt.encode('utf-8')
            value = idc.AskStr(default, 'reg value ?')
            if value is None:
                return
            reg_param = "'%s'" % highlighted
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.writeRegValue(%s, 0x%s)");' % (reg_param, value)) 

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

class DataWatchHandler(idaapi.action_handler_t):
        def __init__(self, isim):
            self.isim = isim
            idaapi.action_handler_t.__init__(self)
            self.last_data_watch_count = 32
        def activate(self, ctx):
            highlighted = idaversion.getHighlight()
            addr = getHex(highlighted)
            count = self.last_data_watch_count

            gac = getAddrCount.GetAddrCount()
            gac.Compile()
            gac.iAddr.value = addr 
            gac.iRawHex.value = count
            ok = gac.Execute()
            if ok != 1:
                return
            count = gac.iRawHex.value
            addr = gac.iAddr.value

            print('watch %d bytes from 0x%x' % (count, addr))
            self.last_data_watch_count = count
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.watchData(0x%x, %d)");' % (addr, count)) 
            eip = gdbProt.getEIPWhenStopped()
            self.isim.signalClient()
            self.isim.showSimicsMessage()

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

class AddDataWatchHandler(idaapi.action_handler_t):
        def __init__(self, isim):
            self.isim = isim
            idaapi.action_handler_t.__init__(self)
            self.last_data_watch_count = 32
        def activate(self, ctx):
            highlighted = idaversion.getHighlight()
            addr = getHex(highlighted)
            count = self.last_data_watch_count

            gac = getAddrCount.GetAddrCount()
            gac.Compile()
            gac.iAddr.value = addr 
            gac.iRawHex.value = count
            ok = gac.Execute()
            if ok != 1:
                return
            count = gac.iRawHex.value
            addr = gac.iAddr.value

            self.last_data_watch_count = count
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.addDataWatch(0x%x, %d)");' % (addr, count)) 
            print('add watch of %d bytes from 0x%x' % (count, addr))

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS


class RevCursorHandler(idaapi.action_handler_t):
        def __init__(self, isim):
            idaapi.action_handler_t.__init__(self)
            self.isim = isim

        # reverse to cursor
        def activate(self, ctx):
            self.isim.doRevToCursor()
            return 1

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

class RevDataHandler(idaapi.action_handler_t):
        def __init__(self, isim):
            idaapi.action_handler_t.__init__(self)
            self.isim = isim

        # reverse to cursor
        def activate(self, ctx):
            self.isim.trackAddressPrompt()
            return 1

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

class DisHandler(idaapi.action_handler_t):
        def __init__(self, isim):
            idaapi.action_handler_t.__init__(self)
            self.isim = isim

        # Disassemble SO
        def activate(self, ctx):
            eip = idaversion.get_screen_ea()
            fun_eip = self.isim.getOrigAnalysis().origFun(eip)
               
            return 1

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

class ModMemoryHandler(idaapi.action_handler_t):
        def __init__(self, isim):
            idaapi.action_handler_t.__init__(self)
            self.isim = isim
            self.last_data_mem_set = 0

        # Modify memory
        def activate(self, ctx):
            addr = getRefAddr()
            if addr is None:
                highlighted = idaversion.getHighlight()
                addr = getHex(highlighted)
            '''
            if regFu.isHighlightedEffective():
                addr = regFu.getOffset()
            else:
                highlighted = idaversion.getHighlight()
                addr = getHex(highlighted)
            '''

            sas = setAddrValue.SetAddrValue()
            sas.Compile()
            sas.iAddr.value = addr 
            sas.iOffset.value = 0 
            sas.iRawHex.value = idaversion.get_wide_dword(sas.iAddr.value)
            ok = sas.Execute()
            if ok != 1:
                return
            val = sas.iRawHex.value
            addr = sas.iAddr.value
            offset = sas.iOffset.value
            new_addr = addr+offset
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.writeWord(0x%x, 0x%x)");' % (new_addr, val)) 
            time.sleep(2)
            self.isim.updateBookmarkView()
            self.isim.updateDataWatch()
            idaversion.refresh_debugger_memory()
            idaversion.refresh_idaview_anyway()
            idaversion.refresh_choosers()
            print('Bookmarks cleared -- select origin bookmark to return to this cycle')
            print('Note: data watches previous to this point are retained, but associated bookmarks are deleted')

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

class StringMemoryHandler(idaapi.action_handler_t):
        def __init__(self, isim):
            idaapi.action_handler_t.__init__(self)
            self.isim = isim

        # Modify memory
        def activate(self, ctx):
            if regFu.isHighlightedEffective():
                addr = regFu.getOffset()
            else:
                highlighted = idaversion.getHighlight()
                addr = getHex(highlighted)
                if addr is None:
                    print('ModMemoryHandler unable to parse hex from %s' % highlighted)
                    return

            sas = setAddrString.SetAddrString()
            sas.Compile()
            sas.iAddr.value = addr 
            val = ''
            for i in range(8):
                c = idaversion.get_wide_byte(addr+i)
                if c >= 0x20 and c <= 0x7e:
                    val = val+chr(c)
                else:
                    val = val+'.'
            sas.iStr1.value = val
            ok = sas.Execute()
            if ok != 1:
                return
            self.last_data_mem_set = sas.iStr1.value
            #sparm = "'%s'" % sas.iStr1.value
            sparm = "'%s'" % str(sas.iStr1.value).strip()
            dog = 'SendGDBMonitor("@cgc.writeString(0x%x, %s)");' % (sas.iAddr.value, sparm)
            print('string is <%s>' % dog)
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.writeString(0x%x, %s)");' % (sas.iAddr.value, sparm))
            time.sleep(2)
            self.isim.updateBookmarkView()
            self.isim.updateDataWatch()
            idaversion.refresh_debugger_memory()
            idaversion.refresh_idaview_anyway()
            idaversion.refresh_choosers()
            print('Bookmarks cleared -- select origin bookmark to return to this cycle')
            print('Note: data watches previous to this point are retained, but associated bookmarks are deleted')

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

class StructFieldHandler(idaapi.action_handler_t):
        def __init__(self, isim):
            idaapi.action_handler_t.__init__(self)
            self.isim = isim

    
        def activate(self, ctx):
            ref_addr = getRefAddr()
            print('Structure field ref_addr 0x%x' % ref_addr)
            if ref_addr is not None:

                heads = idautils.Heads(0,ref_addr)
                h = None
                for h in heads:
                    pass
                if h is None:
                    print('No heads between zero and ref_addr 0x%x?' % ref_addr)
                    return
                offset = ref_addr - h
                print('call getFieldName h 0x%x offset 0%d' % (h, offset))
                field = getFieldName(h, offset)
                if field is not None:
                    print('Field offset %d from 0x%x is %s' % (offset, h, field))
            else:
                print('Did not get reference address')
          

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

def register(isim):
    rev_to_action_desc = idaapi.action_desc_t(
       'rev:action',
       'Reverse to address',
       RevToHandler(isim)
       )
    dis_action_desc = idaapi.action_desc_t(
       'dis:action',
       'analysis',
       DisHandler(isim)
       )
    rev_cursor_action_desc = idaapi.action_desc_t(
       'revCursor:action',
       'reverse to cursor',
       RevCursorHandler(isim)
       )
    mod_reg_action_desc = idaapi.action_desc_t(
       'modReg:action',
       'modify register',
       ModRegHandler(isim)
       )
    data_watch_action_desc = idaapi.action_desc_t(
       'dataWatch:action',
       'data watch',
       DataWatchHandler(isim)
       )
    add_data_watch_action_desc = idaapi.action_desc_t(
       'addDataWatch:action',
       'add data watch',
       AddDataWatchHandler(isim)
       )
    rev_addr_action_desc = idaapi.action_desc_t(
       'revData:action',
       'reverse track data',
       RevDataHandler(isim)
       )
    mod_memory_action_desc = idaapi.action_desc_t(
       'modMemory:action',
       'modify memory',
       ModMemoryHandler(isim)
       )
    string_memory_action_desc = idaapi.action_desc_t(
       'stringMemory:action',
       'modify memory (string)',
       StringMemoryHandler(isim)
       )
    struct_field_action_desc = idaapi.action_desc_t(
       'structField:action',
       'Structure field',
       StructFieldHandler(isim)
       )
    idaapi.register_action(rev_to_action_desc)
    idaapi.register_action(dis_action_desc)
    idaapi.register_action(rev_cursor_action_desc)
    idaapi.register_action(mod_reg_action_desc)
    idaapi.register_action(data_watch_action_desc)
    idaapi.register_action(add_data_watch_action_desc)
    idaapi.register_action(rev_addr_action_desc)
    idaapi.register_action(mod_memory_action_desc)
    idaapi.register_action(string_memory_action_desc)
    idaapi.register_action(struct_field_action_desc)

class Hooks(UI_Hooks):
        def populating_widget_popup(self, form, popup):
            # You can attach here.
            pass

        def finish_populating_widget_popup(self, form, popup):
            # Or here, after the popup is done being populated by its owner.

            # We will attach our action to the context menu
            # for the 'Functions window' widget.
            # The action will be be inserted in a submenu of
            # the context menu, named 'Others'.
            if idaversion.get_widget_type(form) == idaapi.BWN_CALL_STACK:
                #line = form.GetCurrentLine()
                pass
            elif idaversion.get_widget_type(form) == idaapi.BWN_DISASM or \
                 idaversion.get_widget_type(form) == idaapi.BWN_DUMP:
                #regs =['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'ax', 'bx', 'cx', 'dx', 'ah', 'al', 'bh', 'bl', 'ch', 'cl', 'dh', 'dl']


                regs = idaapi.ph_get_regnames()
                idaapi.attach_action_to_popup(form, popup, "revCursor:action", 'RESim/')
                idaapi.attach_action_to_popup(form, popup, "dis:action", 'RESim/')

                highlighted = idaversion.getHighlight()
                if highlighted is not None:
                    if highlighted in regs:
                        idaapi.attach_action_to_popup(form, popup, "modReg:action", 'RESim/')
                    else:
                        addr = getHex(highlighted)
                        if addr is not None or regFu.isHighlightedEffective():
                            idaapi.attach_action_to_popup(form, popup, "rev:action", 'RESim/')
                            idaapi.attach_action_to_popup(form, popup, "dataWatch:action", 'RESim/')
                            idaapi.attach_action_to_popup(form, popup, "addDataWatch:action", 'RESim/')
                            idaapi.attach_action_to_popup(form, popup, "revData:action", 'RESim/')
                            idaapi.attach_action_to_popup(form, popup, "modMemory:action", 'RESim/')
                            idaapi.attach_action_to_popup(form, popup, "stringMemory:action", 'RESim/')
                opnum = idaapi.get_opnum()
                if opnum >= 0:
                    idaapi.attach_action_to_popup(form, popup, "structField:action", 'RESim/')
                            

#register()
#hooks = Hooks()
#hooks.hook()

#register()
#hook()
