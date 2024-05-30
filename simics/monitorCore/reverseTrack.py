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
import dataWatch
from simics import *
class ReverseTrack():
    def __init__(self, top, dataWatch, context_manager, mem_utils, reverse_to_call, lgr):
        self.dataWatch = dataWatch
        self.mem_utils = mem_utils
        self.reverse_to_call = reverse_to_call
        self.context_manager = context_manager
        self.top = top
        self.bookmarks = None
        self.lgr = lgr
        self.cpu = None
        self.memsomething = None
        self.reg = None
        self.value = None
        self.top_command_callback = None

    def revTaintReg(self, reg, bookmarks, kernel=False, no_increments=False):
        ''' back track the value in a given register '''
        #TBD why store this? would it change?
        self.top_command_callback = self.top.getCommandCallback()

        self.bookmarks = bookmarks
        reg = reg.lower()
        self.reg = reg
        tid, cpu = self.context_manager.getDebugTid() 
        self.cpu = cpu
        value = self.mem_utils.getRegValue(cpu, reg)
        self.value = value
        self.lgr.debug('revTaintReg tid:%s for %s value 0x%x' % (tid, reg, value))
        if self.top.reverseEnabled():
            #st = self.top.getStackTraceQuiet(max_frames=20, max_bytes=1000)
            #if st is None:
            #    self.lgr.debug('revTaintReg stack trace is None, wrong tid?')
            #    return
            #frames = st.getFrames(20)
            #mem_stuff = self.dataWatch.memsomething(frames, dataWatch.mem_funs)
            #if mem_stuff is not None:
            #    self.mem_something = dataWatch.MemSomething(mem_stuff.fun, mem_stuff.fun_addr, None, mem_stuff.ret_addr, None, None, None, 
            #          mem_stuff.called_from_ip, None, None, None, ret_addr_addr = mem_stuff.ret_addr_addr)
            #    call_ip = mem_stuff.called_from_ip
            #    self.lgr.debug('revTaintReg mem_stuff.fun is %s' % mem_stuff.fun)
            #    self.top.setCommandCallback(self.handleCall)
            #    self.top.revToAddr(call_ip)
            #else:
            # TBD what the heck was that?
            if True:
                self.top.removeDebugBreaks()
                cell_name = self.top.getTopComponentName(cpu)
                eip = self.top.getEIP(cpu)
                instruct = SIM_disassemble_address(cpu, eip, 1, 0)
                reg_num = cpu.iface.int_register.get_number(reg)
                value = cpu.iface.int_register.read(reg_num)
                self.lgr.debug('revTaintReg for reg value %x' % value)
                track_num = self.bookmarks.setTrackNum()
                bm='backtrack START:%d 0x%x inst:"%s" track_reg:%s track_value:0x%x' % (track_num, eip, instruct[1], reg, value)
                self.bookmarks.setDebugBookmark(bm)
                self.context_manager.setIdaMessage('')
                self.reverse_to_call.doRevToModReg(reg, taint=True, kernel=kernel, no_increments=no_increments)
        else:
            print('reverse execution disabled')
            self.top.skipAndMail()

    def handleCall(self, dumb):
        self.lgr.debug('reverseTrack handleCall')
        sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        if self.mem_something.fun == 'memcpy' or self.mem_something.fun == 'memmove' or self.mem_something.fun == 'mempcpy' or self.mem_something.fun == 'j_memcpy': 
                
            self.mem_something.dest, self.mem_something.src, dumb = self.dataWatch.getCallParams(sp)
            if self.cpu.architecture == 'arm':
                self.mem_something.count = self.mem_utils.getRegValue(self.cpu, 'r2')
            else:
                if self.mem_something.fun == 'mempcpy':
                    eip = self.top.getEIP(self.cpu)
                    so_file = self.top.getSOFile(eip)
                    if so_file is not None and 'libc' in so_file.lower():
                        count_addr = self.mem_utils.readPtr(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
                        self.mem_something.count = self.mem_utils.readWord32(self.cpu, count_addr)
                        self.lgr.debug('mempcy but is libc count_addr 0x%x, count %d' % (count_addr, self.mem_something.count))
                    else:
                        self.mem_something.count = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
                        self.lgr.debug('mempcy but not libc, so file %s  count %d' % (so_file, self.mem_something.count))
                else:
                    self.mem_something.count = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
            self.lgr.debug('getMemParams memcpy-ish dest 0x%x  src 0x%x count 0x%x' % (self.mem_something.dest, self.mem_something.src, 
                        self.mem_something.count))
            bm =  'reg %s value 0x%x came from %s.  Src: 0x%x  Dest: 0x%x Count: 0x%x' % (self.reg, self.value, self.mem_something.fun,
                 self.mem_something.src, self.mem_something.dest, self.mem_something.count)
            self.bookmarks.setDebugBookmark(bm)
        else:
            self.lgr.warning('reverseTrack not handling function %s' % self.mem_something.fun)
        if self.top_command_callback is not None:
            self.top.setCommandCallback(self.top_command_callback)
            self.top.skipAndMail()
