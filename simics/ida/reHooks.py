import idaapi
import time
from idaapi import Form
import idc
import gdbProt
import regFu
last_data_watch_count = '32'
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

class RevToHandler(idaapi.action_handler_t):
        def __init__(self, isim):
            idaapi.action_handler_t.__init__(self)
            self.isim = isim
        # reverse to the highlighted address
        def activate(self, ctx):
            highlighted = idaapi.get_highlighted_identifier()
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
            highlighted = idaapi.get_highlighted_identifier()
            current = idc.GetRegValue(highlighted)
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
        def activate(self, ctx):
            highlighted = idaapi.get_highlighted_identifier()
            addr = getHex(highlighted)
            count = idc.AskStr(last_data_watch_count, 'number of bytes to watch?')
            if count is None:
                return
            print('watch %s bytes from 0x%x' % (count, addr))
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.watchData(0x%x, 0x%s)");' % (addr, count)) 
            eip = gdbProt.getEIPWhenStopped()
            self.isim.signalClient()
            self.isim.showSimicsMessage()

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
            eip = idc.ScreenEA()
            fun_eip = self.isim.getOrigAnalysis().origFun(eip)
               
            return 1

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

class ModMemoryHandler(idaapi.action_handler_t):
        def __init__(self, isim):
            idaapi.action_handler_t.__init__(self)
            self.isim = isim

        # Modify memory
        def activate(self, ctx):
            if regFu.isHighlightedEffective():
                addr = regFu.getOffset()
                simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.getMemoryValue(0x%x)");' % addr) 
                print('effective addr 0x%x value %s' % (addr, simicsString))
                value = getHex(simicsString)
            else:
                highlighted = idaapi.get_highlighted_identifier()
                addr = getHex(highlighted)
                if addr is None:
                    print('ModMemoryHandler unable to parse hex from %s' % highlighted)
                    return
                simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.getMemoryValue(0x%x)");' % addr) 
                print('addr 0x%x value %s' % (addr, simicsString))
                value = getHex(simicsString)

            # Sample form from kernwin.hpp
            s = """Modify memory
            Address: %$
            <~E~nter value:S:32:16::>
            """
            num = Form.NumericArgument('N', value=value)
            ok = idaapi.AskUsingForm(s,
                    Form.NumericArgument('$', addr).arg,
                    num.arg)
            if ok == 1:
                print("You entered: %x" % num.value)
                simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.writeWord(0x%x, 0x%x)");' % (addr, num.value)) 
                time.sleep(1)
                idc.RefreshDebuggerMemory()

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
                simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.getMemoryValue(0x%x)");' % addr) 
                print('effective addr 0x%x value %s' % (addr, simicsString))
                value = simicsString
            else:
                highlighted = idaapi.get_highlighted_identifier()
                addr = getHex(highlighted)
                if addr is None:
                    print('ModMemoryHandler unable to parse hex from %s' % highlighted)
                    return
                simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.getMemoryValue(0x%x)");' % addr) 
                print('addr 0x%x value %s' % (addr, simicsString))
                value = simicsString

            # Sample form from kernwin.hpp
            s = """Modify memory
            Address: %$
            <~E~nter value:t40:80:50::>
            """
            ti = idaapi.textctrl_info_t(value)
            ok = idaapi.AskUsingForm(s, Form.NumericArgument('$', addr).arg, idaapi.pointer(idaapi.c_void_p.from_address(ti.clink_ptr)))
            '''
            string = Form.StringArgument(value)
            ok = idaapi.AskUsingForm(s,
                    Form.NumericArgument('$', addr).arg,
                    string.arg)
            '''
            if ok == 1:
                arg = "'%s'" % ti.text.strip()
                print("You entered: %s <%s>" % (ti.text, arg))
                cmd = "@cgc.writeString(0x%x, %s)" % (addr, arg) 
                print cmd
                simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % (cmd)) 
                time.sleep(1)
                idc.RefreshDebuggerMemory()

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
    idaapi.register_action(rev_to_action_desc)
    idaapi.register_action(dis_action_desc)
    idaapi.register_action(rev_cursor_action_desc)
    idaapi.register_action(mod_reg_action_desc)
    idaapi.register_action(data_watch_action_desc)
    idaapi.register_action(rev_addr_action_desc)
    idaapi.register_action(mod_memory_action_desc)
    idaapi.register_action(string_memory_action_desc)

class Hooks(idaapi.UI_Hooks):
        def populating_tform_popup(self, form, popup):
            # You can attach here.
            pass

        def finish_populating_tform_popup(self, form, popup):
            # Or here, after the popup is done being populated by its owner.

            # We will attach our action to the context menu
            # for the 'Functions window' widget.
            # The action will be be inserted in a submenu of
            # the context menu, named 'Others'.
            if idaapi.get_tform_type(form) == idaapi.BWN_CALL_STACK:
                #line = form.GetCurrentLine()
                pass
            elif idaapi.get_tform_type(form) == idaapi.BWN_DISASM or \
                 idaapi.get_tform_type(form) == idaapi.BWN_DUMP:
                #regs =['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'ax', 'bx', 'cx', 'dx', 'ah', 'al', 'bh', 'bl', 'ch', 'cl', 'dh', 'dl']
                regs = idaapi.ph_get_regnames()
                idaapi.attach_action_to_popup(form, popup, "revCursor:action", 'RESim/')
                idaapi.attach_action_to_popup(form, popup, "dis:action", 'RESim/')

                highlighted = idaapi.get_highlighted_identifier()
                if highlighted is not None:
                    if highlighted in regs:
                        idaapi.attach_action_to_popup(form, popup, "modReg:action", 'RESim/')
                    else:
                        addr = getHex(highlighted)
                        if addr is not None or regFu.isHighlightedEffective():
                            idaapi.attach_action_to_popup(form, popup, "rev:action", 'RESim/')
                            idaapi.attach_action_to_popup(form, popup, "dataWatch:action", 'RESim/')
                            idaapi.attach_action_to_popup(form, popup, "revData:action", 'RESim/')
                            idaapi.attach_action_to_popup(form, popup, "modMemory:action", 'RESim/')
                            idaapi.attach_action_to_popup(form, popup, "stringMemory:action", 'RESim/')
                            

#register()
#hooks = Hooks()
#hooks.hook()

#register()
#hook()
