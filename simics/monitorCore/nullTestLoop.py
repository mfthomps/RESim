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
Is the code at the current data watch a loop checking for null?
Currently wired for x86 with test; jnz...
'''
from simics import *
class NullTestLoop():
    def __init__(self, top, cpu, data_watch, context_manager, watch_marks, mem_utils, decode, eip, addr, instruct, lgr):
        self.cpu = cpu
        self.data_watch = data_watch
        self.context_manager = context_manager
        self.watch_marks = watch_marks
        self.mem_utils = mem_utils
        self.decode = decode
        self.top = top
        self.eip = eip
        self.lgr = lgr
        self.addr = addr
        self.instruct = instruct
        self.exit_hap = None
        self.our_reg = None

    def checkForLoop(self):
        retval = False
        if self.instruct[1].startswith('mov'):
            op2, op1 = self.decode.getOperands(self.instruct[1])
            #self.lgr.debug('nullTestLoop is mov op1: %s op2: %s' % (op1, op2))
            if self.decode.regLen(op1) == 1: 
                self.our_reg = op2.split('[', 1)[1].split(']')[0]
                self.lgr.debug('nullTestLoop is 1 byte op1 %s op2 %s' % (op1, op2))
                next_eip = self.eip + self.instruct[0]
                next_instruct = self.top.disassembleAddress(self.cpu, next_eip)
                if next_instruct[1].startswith('inc ') and next_instruct[1].endswith(self.our_reg):
                    self.lgr.debug('nullTestLoop next is inc %s' % next_instruct[1])
                else:
                    self.lgr.debug('nullTestLoop next is NOT inc %s' % next_instruct[1])
                    return retval
                next_eip = next_eip + next_instruct[0]
                next_instruct = self.top.disassembleAddress(self.cpu, next_eip)
                if next_instruct[1].startswith('test'):
                    next_op2, next_op1 = self.decode.getOperands(next_instruct[1])
                    if next_op1 == op1 and next_op2 == op1:
                        self.lgr.debug('nullTestLoop is test %s' % next_instruct[1])
                        next_eip = next_eip + next_instruct[0]
                        next_instruct = self.top.disassembleAddress(self.cpu, next_eip)
                        if next_instruct[1].startswith('jne'):
                            self.lgr.debug('nullTestLoop is jump %s' % next_instruct[1])
                            next_op2, next_op1 = self.decode.getOperands(next_instruct[1])
                            try:
                                op1_addr = int(next_op1, 16)
                            except:
                                return retval
                            if op1_addr == self.eip:
                                loop_exit = next_eip + next_instruct[0] 
                                self.lgr.debug('nullTestLoop is loop.  Exit addr is 0x%x'  % loop_exit)
                                self.setExitBreak(loop_exit)
                                self.data_watch.stopWatch()
                                retval = True
                            else:
                                return retval
        return retval

    def setExitBreak(self, loop_exit):
        proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, loop_exit, 1, 0)
        self.exit_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, None, proc_break, 'null_test_loop_exit')
                             
    def exitHap(self, dumb, an_object, the_breakpoint, memory):
        if self.exit_hap is None:
            return
        curr_addr = self.mem_utils.getRegValue(self.cpu, self.our_reg)
        self.watch_marks.nullTestLoop(self.addr, curr_addr)
        self.lgr.debug('nullTestLoop exitHap')
        self.rmExitBreak()
        self.data_watch.watch()
        
    def rmExitBreak(self):
        if self.exit_hap is not None:
            hap = self.exit_hap
            self.context_manager.genDeleteHap(hap, immediate=False)
            self.exit_hap = None
