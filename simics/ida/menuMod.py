import idaapi
import ida_nalt
import idaversion
import colorBlocks
import os
import ida_kernwin
'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.

'''
'''
Define action handlers for RESim menu extensions.
'''
class ShowCycleHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim

    def activate(self, ctx):
        self.isim.showCycle()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class RebaseHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim

    def activate(self, ctx):
        self.isim.reBase()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
class DoReverseHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim

    def activate(self, ctx):
        self.isim.doReverse()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DoRevStepOverHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim

    def activate(self, ctx):
        self.isim.doRevStepOver()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DoStepIntoHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.doStepInto()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DoStepOverHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.doStepOver()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class DoRevStepIntoHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.doRevStepInto()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DoRevFinishHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.doRevFinish()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DoRevCursorHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.doRevToCursor()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DoRunCursorHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.doRunToCursor()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DoWroteToSPHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.wroteToSP()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DoWroteToAddressHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.wroteToAddressPrompt()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class TrackAddressHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.trackAddressPrompt()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class TrackAddressByteHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        prompt = 'Run backwards to find source of byte at this address'
        self.isim.trackAddressPrompt(prompt=prompt, num_bytes=1)
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class WroteToRegisterHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.wroteToRegister()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class TrackRegisterHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.trackRegister()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class SatisfyConditionHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.satisfyCondition()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class RunToUserSpaceHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.runToUserSpace()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class RunToSyscallHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.runToSyscall()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class ResynchHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.resynch()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class WatchDataHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.watchData()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class RunToIOHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.runToIO()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class RunToBindHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.runToBind()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class RunToTextHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.runToText()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class RevToTextHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.revToText()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class RunToHandler(idaapi.action_handler_t):
    def __init__(self, isim_fun):
        idaapi.action_handler_t.__init__(self)
        self.isim_fun = isim_fun
    def activate(self, ctx):
        self.isim_fun()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class ContinueForwardHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.continueForward()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class TrackIOHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.trackIO()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
class RetrackHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.retrack()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class RunToAcceptHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        self.isim.runToAccept()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class GoToHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    def activate(self, ctx):
        prompt = 'Go to address (less program base)'
        target_addr = idaversion.ask_addr(0, prompt)
        if target_addr is not None:
            info = idaapi.get_inf_structure()
            if info.is_dll():
                offset = ida_nalt.get_imagebase()
                target_addr = target_addr + offset
            idaapi.jumpto(target_addr)
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ColorBlocksHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim
    def activate(self, ctx):
        colorBlocks.colorBlocks()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def register(isim):
    do_show_cycle_action = idaapi.action_desc_t(
        'do_show_cycle:action',
        'show cycle', 
        ShowCycleHandler(isim),
        'Alt+Shift+C')

    do_rebase_action = idaapi.action_desc_t(
        'do_rebase:action',
        'rebase library', 
        RebaseHandler(isim),
        'Alt+Shift+R')

    do_reverse_action = idaapi.action_desc_t(
        'do_reverse:action',
        '^ Reverse continue process', 
        DoReverseHandler(isim),
        'Alt+Shift+F9')

    do_rev_step_over_action = idaapi.action_desc_t(
        'do_rev_step_over:action',
        '^ Rev step over', 
        DoRevStepOverHandler(isim),
        'Alt+Shift+F8')

    do_step_over_action = idaapi.action_desc_t(
        'do_step_over:action',
        'Step over (RESim)', 
        DoStepOverHandler(isim),
        'F8')

    do_step_into_action = idaapi.action_desc_t(
        'do_step_into:action',
        'Step into (RESim)', 
        DoStepIntoHandler(isim),
        'F7')

    do_rev_step_into_action = idaapi.action_desc_t(
        'do_rev_step_into:action',
        '^ Rev step into', 
        DoRevStepIntoHandler(isim),
        'Alt+Shift+F7')

    do_rev_finish_action = idaapi.action_desc_t(
        'do_rev_finish:action',
        '^ Rev until call', 
        DoRevFinishHandler(isim),
        'Alt+F6')

    do_rev_cursor_action = idaapi.action_desc_t(
        'do_rev_cursor:action',
        '^ Rev to cursor', 
        DoRevCursorHandler(isim),
        'Alt+Shift+f4')

    do_run_cursor_action = idaapi.action_desc_t(
        'do_run_cursor:action',
        'Run to cursor', 
        DoRunCursorHandler(isim),
        'Shift+f4')

    do_wrote_to_sp_action = idaapi.action_desc_t(
        'do_wrote_to_sp:action',
        '^ Wrote to SP', 
        DoWroteToSPHandler(isim),
        'Alt+Shift+s')

    do_wrote_to_address_action = idaapi.action_desc_t(
        'do_wrote_to_address:action',
        '^ Wrote to address', 
        DoWroteToAddressHandler(isim),
        'Alt+Shift+a')

    track_address_action = idaapi.action_desc_t(
        'track_address:action',
        '^ track address', 
        TrackAddressHandler(isim),
        'Ctrl+Shift+a')

    track_address_byte_action = idaapi.action_desc_t(
        'track_address_byte:action',
        '^ track byte at address', 
        TrackAddressByteHandler(isim),
        'Ctrl+Shift+a')

    wrote_register_action = idaapi.action_desc_t(
        'wrote_register:action',
        '^ Wrote to register', 
        WroteToRegisterHandler(isim),
        'Alt+Shift+r')

    track_register_action = idaapi.action_desc_t(
        'track_register:action',
        '^ track register', 
        TrackRegisterHandler(isim),
        'Ctrl+Shift+r')

    satisfy_condition_action = idaapi.action_desc_t(
        'satisfy_condition:action',
        '^ satisfy condition', 
        SatisfyConditionHandler(isim),
        'Ctrl+Shift+c')

    run_to_user_action = idaapi.action_desc_t(
        'run_to_user:action',
        'Run to user space', 
        RunToUserSpaceHandler(isim),
        'Alt+Shift+u')

    run_to_syscall_action = idaapi.action_desc_t(
        'run_to_syscall:action',
        'Run to syscall', 
        RunToSyscallHandler(isim),
        'Alt+c')

    resynch_action = idaapi.action_desc_t(
        'resynch:action',
        'Resynch with server', 
        ResynchHandler(isim))

    watch_data_action = idaapi.action_desc_t(
        'watch_data:action',
        'Watch data read', 
        WatchDataHandler(isim))

    run_to_io_action = idaapi.action_desc_t(
        'run_to_io:action',
        'Run to IO', 
        RunToIOHandler(isim))

    run_to_bind_action = idaapi.action_desc_t(
        'run_to_bind:action',
        'Run to bind', 
        RunToHandler(isim.runToBind))

    run_to_connect_action = idaapi.action_desc_t(
        'run_to_connect:action',
        'Run to connect', 
        RunToHandler(isim.runToConnect))

    run_to_text_action = idaapi.action_desc_t(
        'run_to_text:action',
        'Run to Text segment', 
        RunToTextHandler(isim))

    rev_to_text_action = idaapi.action_desc_t(
        'rev_to_text:action',
        'Rev to Text segment', 
        RevToTextHandler(isim))

    track_io_action = idaapi.action_desc_t(
        'track_io:action',
        'Track IO', 
        TrackIOHandler(isim))

    retrack_action = idaapi.action_desc_t(
        'retrack:action',
        'Retrack', 
        RetrackHandler(isim))

    run_to_accept_action = idaapi.action_desc_t(
        'run_to_accept:action',
        'Run to accept', 
        RunToAcceptHandler(isim))

    go_to_action = idaapi.action_desc_t(
        'go_to_action:action',
        '^ Rev until call', 
        GoToHandler(),
        'Ctrl+Shift+g')

    color_blocks_action = idaapi.action_desc_t(
        'color_blocks:action',
        'Recolor blocks', 
        ColorBlocksHandler(isim))

    this_dir = os.path.dirname(os.path.realpath(__file__))
    play_icon = os.path.join(this_dir, "play.png")
    continue_forward_action = idaapi.action_desc_t(
        'continue_forward:action',
        'Continue process(RESim)', 
        ContinueForwardHandler(isim),
        'F9', 'Continue', idaapi.load_custom_icon(file_name=play_icon, format="png"))

    #idaapi.unregister_action("ThreadStepOver")
    #idaapi.unregister_action("ThreadStepInto")
    idaapi.register_action(do_show_cycle_action)
    idaapi.register_action(do_rebase_action)
    idaapi.register_action(do_reverse_action)
    idaapi.register_action(do_rev_step_over_action)
    idaapi.register_action(do_step_into_action)
    idaapi.register_action(do_step_over_action)
    idaapi.register_action(do_rev_step_into_action)
    idaapi.register_action(do_rev_finish_action)
    idaapi.register_action(do_rev_cursor_action)
    idaapi.register_action(do_run_cursor_action)
    idaapi.register_action(do_wrote_to_sp_action)
    idaapi.register_action(do_wrote_to_address_action)
    idaapi.register_action(track_address_action)
    idaapi.register_action(track_address_byte_action)
    idaapi.register_action(wrote_register_action)
    idaapi.register_action(track_register_action)
    idaapi.register_action(satisfy_condition_action)
    idaapi.register_action(run_to_user_action)
    idaapi.register_action(run_to_syscall_action)
    idaapi.register_action(resynch_action)
    idaapi.register_action(watch_data_action)
    idaapi.register_action(run_to_io_action)
    idaapi.register_action(run_to_bind_action)
    idaapi.register_action(run_to_connect_action)
    idaapi.register_action(run_to_text_action)
    idaapi.register_action(rev_to_text_action)
    idaapi.register_action(continue_forward_action)
    idaapi.register_action(track_io_action)
    idaapi.register_action(retrack_action)
    idaapi.register_action(run_to_accept_action)
    idaapi.register_action(go_to_action)
    idaapi.register_action(color_blocks_action)


def attach():
    ''' Determines where entry appears in menu '''
    idaapi.attach_action_to_menu(
        'Debugger/Step into',
        'do_step_into:action',
        idaapi.SETMENU_APP) 

    idaapi.attach_action_to_menu(
        'Debugger/Step into (RESim)',
        'do_step_over:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/Step over (RESim)',
        'do_rev_step_into:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/^Rev step into',
        'do_rev_step_over:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/Run until return',
        'do_rev_finish:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/Run to Cursor',
        'do_rev_cursor:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/Run to Cursor',
        'do_run_cursor:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/^ Rev to Cursor',
        'run_to_user:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/Continue process',
        'resynch:action',
        idaapi.SETMENU_APP) 
    '''
    RESim submenu
    '''
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/',
        'watch_data:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/',
        'track_io:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/',
        'retrack:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/runTo/',
        'run_to_io:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/runTo/',
        'run_to_bind:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/runTo/',
        'run_to_accept:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/runTo/',
        'run_to_connect:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/runTo/',
        'run_to_text:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/runTo/',
        'rev_to_text:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/backtrack/',
        'do_wrote_to_sp:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/backtrack/',
        'do_wrote_to_address:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/backtrack/',
        'track_address:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/backtrack/',
        'track_address_byte:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/backtrack/',
        'wrote_register:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/backtrack/',
        'track_register:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/backtrack/',
        'satisfy_condition:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/',
        'do_show_cycle:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/',
        'do_rebase:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/',
        'color_blocks:action',
        idaapi.SETMENU_APP) 

    idaapi.attach_action_to_menu(
        'Debugger/Continue process', 
        'continue_forward:action',
        idaapi.SETMENU_APP) 

    #if idaapi.IDA_SDK_VERSION >= 740:
    #    idaapi.unregister_action("ProcessStart")
    idaapi.attach_action_to_toolbar("DebugToolBar", "continue_forward:action")
    idaapi.attach_action_to_menu(
        'Debugger/Continue process(RESim)', 
        'do_reverse:action',
        idaapi.SETMENU_APP) 
    
