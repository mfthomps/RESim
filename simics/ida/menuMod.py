import idaapi
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
class DoReverseHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim

    def activate(self, ctx):
        self.isim.doReverse()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DoReverseHandler(idaapi.action_handler_t):
    def __init__(self, isim):
        idaapi.action_handler_t.__init__(self)
        self.isim = isim

    def activate(self, ctx):
        self.isim.doRevStepOver()
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
        self.isim.trackToRegister()
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

def register(isim):
    do_reverse_action = idaapi.action_desc_t(
        'do_reverse:action',
        '^ Reverse continue process', 
        DoReverseHandler(isim),
        'Alt+Shift+F9')

    do_rev_step_over_action = idaapi.action_desc_t(
        'do_rev_step_over:action',
        '^ Rev step over', 
        DoReverseHandler(isim),
        'Alt+F8')

    do_step_over_action = idaapi.action_desc_t(
        'do_step_over:action',
        'Step over (reSim)', 
        DoStepOverHandler(isim),
        'F8')

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

    run_to_text_action = idaapi.action_desc_t(
        'run_to_text:action',
        'Run to Text segment', 
        RunToTextHandler(isim))

    rev_to_text_action = idaapi.action_desc_t(
        'rev_to_text:action',
        'Rev to Text segment', 
        RevToTextHandler(isim))

    idaapi.unregister_action("ThreadStepOver")
    idaapi.register_action(do_reverse_action)
    idaapi.register_action(do_rev_step_over_action)
    idaapi.register_action(do_step_over_action)
    idaapi.register_action(do_rev_step_into_action)
    idaapi.register_action(do_rev_finish_action)
    idaapi.register_action(do_rev_cursor_action)
    idaapi.register_action(do_wrote_to_sp_action)
    idaapi.register_action(do_wrote_to_address_action)
    idaapi.register_action(track_address_action)
    idaapi.register_action(wrote_register_action)
    idaapi.register_action(track_register_action)
    idaapi.register_action(run_to_user_action)
    idaapi.register_action(run_to_syscall_action)
    idaapi.register_action(resynch_action)
    idaapi.register_action(watch_data_action)
    idaapi.register_action(run_to_io_action)
    idaapi.register_action(run_to_text_action)
    idaapi.register_action(rev_to_text_action)


def attach():
    idaapi.attach_action_to_menu(
        'Debugger/Run to cursor',
        'do_reverse:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/Run to cursor',
        'do_rev_step_over:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/Step over',
        'do_step_over:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/Step into',
        'do_rev_step_into:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/Run to Cursor',
        'do_rev_finish:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/Run to Cursor',
        'do_rev_cursor:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/^ Rev to Cursor',
        'do_wrote_to_sp:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/^ Rev to Cursor',
        'do_wrote_to_address:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/^ Rev to Cursor',
        'track_address:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/^ Rev to Cursor',
        'wrote_register:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/^ Rev to Cursor',
        'track_register:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/^ Rev to Cursor',
        'run_to_user:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/',
        'run_to_syscall:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/',
        'resynch:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/',
        'watch_data:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/',
        'run_to_io:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/',
        'run_to_text:action',
        idaapi.SETMENU_APP) 
    idaapi.attach_action_to_menu(
        'Debugger/ReSIM/',
        'rev_to_text:action',
        idaapi.SETMENU_APP) 
