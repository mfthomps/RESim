import idaapi
import idc
import gdbProt
import rev
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
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        # reverse to the highlighted address
        def activate(self, ctx):
            highlighted = idaapi.get_highlighted_identifier()
            addr = getHex(highlighted)
            command = '@cgc.revToAddr(0x%x, extra_back=0)' % (addr)
            print('cmd: %s' % command)
            simicsString = gdbProt.Evalx('SendGDBMonitor("%s");' % command)
            eip = gdbProt.getEIPWhenStopped()
            rev.signalClient()
            return 1

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

class ModRegHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)
        def activate(self, ctx):
            highlighted = idaapi.get_highlighted_identifier()
            current = idc.GetRegValue(highlighted)
            default = '%x' % current
            print('default %s' % default)
            #prompt = 'Value to write to %s (in hex, no prefix)' % highlighted
            #print('prompt is %s' % prompt)
            #enc = prompt.encode('utf-8')
            value = idc.AskStr(default, 'reg value ?')
            reg_param = "'%s'" % highlighted
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.writeRegValue(%s, 0x%s)");' % (reg_param, value)) 

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

class DataWatchHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)
        def activate(self, ctx):
            highlighted = idaapi.get_highlighted_identifier()
            addr = getHex(highlighted)
            count = idc.AskStr(last_data_watch_count, 'number of bytes to watch?')
            print('watch %s bytes from 0x%x' % (count, addr))
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.dataWatch(0x%x, 0x%s)");' % (addr, count)) 

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS


class RevCursorHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        # reverse to cursor
        def activate(self, ctx):
            rev.doRevToCursor()
            return 1

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
class DisHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        # Disassemble SO
        def activate(self, ctx):
            eip = idc.ScreenEA()
            simicsString = gdbProt.Evalx('SendGDBMonitor("@cgc.getSO(0x%x)");' % eip) 
            print('will analyze: %s' % simicsString)
            sofile, start_end = simicsString.rsplit(':', 1)
            start, end = start_end.split('-')
            start_h = int(start, 16)
            end_h = int(end, 16)
            idaapi.auto_mark_range(start_h, end_h, 25)
            idaapi.autoWait()
            return 1

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

def register():
    rev_to_action_desc = idaapi.action_desc_t(
       'rev:action',
       'Reverse to',
       RevToHandler()
       )
    dis_action_desc = idaapi.action_desc_t(
       'dis:action',
       'analysis',
       DisHandler()
       )
    rev_cursor_action_desc = idaapi.action_desc_t(
       'revCursor:action',
       'reverse to cursor',
       RevCursorHandler()
       )
    mod_reg_action_desc = idaapi.action_desc_t(
       'modReg:action',
       'modify register',
       ModRegHandler()
       )
    data_watch_action_desc = idaapi.action_desc_t(
       'dataWatch:action',
       'data watch',
       DataWatchHandler()
       )
    idaapi.register_action(rev_to_action_desc)
    idaapi.register_action(dis_action_desc)
    idaapi.register_action(rev_cursor_action_desc)
    idaapi.register_action(mod_reg_action_desc)
    idaapi.register_action(data_watch_action_desc)

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
            elif idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
                regs =['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'ax', 'bx', 'cx', 'dx', 'ah', 'al', 'bh', 'bl', 'ch', 'cl', 'dh', 'dl']
                idaapi.attach_action_to_popup(form, popup, "revCursor:action", 'RESim/')
                idaapi.attach_action_to_popup(form, popup, "dis:action", 'RESim/')

                highlighted = idaapi.get_highlighted_identifier()
                if highlighted is not None:
                    if highlighted in regs:
                        idaapi.attach_action_to_popup(form, popup, "modReg:action", 'RESim/')
                    else:
                        addr = getHex(highlighted)
                        if addr is not None:
                            idaapi.attach_action_to_popup(form, popup, "rev:action", 'RESim/')
                            idaapi.attach_action_to_popup(form, popup, "dataWatch:action", 'RESim/')
                            

#register()
#hooks = Hooks()
#hooks.hook()

#register()
#hook()
