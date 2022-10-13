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
Intended for use with trackIO to track input read by a function, e.g., recvUntil
'''
from simics import *
import memUtils
import os
class ReadLibTrack():
    def __init__(self, cpu, mem_utils, context_manager, dataWatch, top, lgr):
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.write_hap = []
        self.write_bytes = 0
        self.fun = None
        self.buffer_offset = None
        self.fun_entry_hap = None
        self.fun_exit_hap = None
        self.ret_addr = None 
        self.dataWatch = dataWatch 
        self.top = top 
        self.lgr = lgr 
        self.fname = 'readlib.track'
        self.context_manager = context_manager
         
        self.loadFuns()

    def loadFuns(self):
        if os.path.isfile(self.fname):
            with open(self.fname) as fh:
                for line in fh:
                    if line.strip().startswith('#'):
                        continue
                    parts = line.strip().split()
                    if len(parts) == 2:
                        self.fun = parts[0]
                        try:
                            self.buffer_offset = int(parts[1])
                        except:
                            self.lgr.error('Failed getting buffer offset from %s' % line)
                            return
                        break
                    else:
                        self.lgr.error('Could not load fun entry %s' % line)
                        return
        else:
            self.lgr.debug('readLibTrack, no functions defined in %s' % self.fname)

    def trackReadLib(self, ida_funs):
        if self.fun is None:
            self.lgr.debug('readLibTrack no fun, do nothing')
            return
        elif ida_funs is None:
            self.lgr.error('readLibTrack funs defined, but no ida functions')
            return
        start, end = ida_funs.getAddr(self.fun)
        if start is None:
            self.lgr.error('readLibTrack, no function found: %s' % self.fun)         
            return
        self.lgr.debug('readLibTrack %s start 0x%x' % (self.fun, start))
        eip = self.mem_utils.getRegValue(self.cpu, 'pc') 
        cur_fun = ida_funs.getFun(eip)
        if cur_fun == start:
            ''' TBD need to be be prior to call to record return address '''
            self.lgr.error('readLibTrack starting in the function %s -- rev to prior' % self.fun)
            return
        else:
            ''' set break on function entry '''
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, start, 1, 0)
            self.fun_entry_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.funEnterHap, None, 
                proc_break, 'track-fun-write-entry')

        self.lgr.debug('readLibTrack for %s 0x%x' % (self.fun, start))

    def stopTrack(self):
        if self.fun_entry_hap is not None:
            self.context_manager.genDeleteHap(self.fun_entry_hap)
            self.fun_entry_hap = None

    def funEnterHap(self, dumb, third, forth, memory):
        pid = self.top.getPID()
        self.lgr.debug('readLibTrack funEnterHap pid:%d' % pid)
        if self.fun_entry_hap is None:
            return
        if self.fun_exit_hap is not None:
            self.lgr.debug('readLibTrack funEnter hap, but waiting on exit???')
            return
        #self.context_manager.genDeleteHap(self.fun_entry_hap)
        #self.fun_entry_hap = None 
        self.write_bytes = 0
        if self.cpu.architecture == 'arm':
            self.ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr') 
            self.lgr.error('readLibTrack, no support for arm yet')
        else:
            esp = self.mem_utils.getRegValue(self.cpu, 'esp') 
            self.lgr.debug('readLibTrack funEnterHap sp 0x%x buffer offset %d' % (esp, self.buffer_offset))
            self.ret_addr = self.mem_utils.readPtr(self.cpu, esp)
            self.buf_addr = self.mem_utils.readPtr(self.cpu, esp+self.buffer_offset)
            self.lgr.debug('readLibTrack funEnterHap ret 0x%x buff_addr: 0x%x' % (self.ret_addr, self.buf_addr))

            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, 
                       Sim_Access_Execute, self.ret_addr, 1, 0)
            self.fun_exit_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.funExitHap, None, 
                proc_break, 'track-fun-write-exit')
            

        write_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, self.buf_addr, 1, 0)
        hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeHap, None, 
            write_break, 'track-fun-write')
        self.write_hap.append(hap)

    def writeHap(self, dumb, third, forth, memory):
        if len(self.write_hap) == 0:
            return
        length = memory.size
        self.write_bytes = self.write_bytes + length
        self.lgr.debug('readLibTrack writeHap addr 0x%x len %d' % (memory.logical_address, memory.size))
        write_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, memory.logical_address+1, 1, 0)
        hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.writeHap, None, 
            write_break, 'track-fun-write')
        self.write_hap.append(hap)
       
    def rmWriteHapsAlone(self, haplist): 
        for hap in haplist:
            self.context_manager.genDeleteHap(hap)

    def funExitHap(self, dumb, third, forth, memory):
        if self.fun_exit_hap is None:
            return
        self.context_manager.genDeleteHap(self.fun_exit_hap)
        self.fun_exit_hap = None 
        self.lgr.debug('readLibTrack funExitHap buf is 0x%x, len is %d' % (self.buf_addr, self.write_bytes))
        haplist = list(self.write_hap)
        SIM_run_alone(self.rmWriteHapsAlone, haplist) 
        self.write_hap = []
        if self.write_bytes > 0:
            trace_msg = '%d bytes of input read from %s' % (self.write_bytes, self.fun)
            self.dataWatch.setRange(self.buf_addr, self.write_bytes, msg=trace_msg, 
                               recv_addr=self.buf_addr, is_lib=True)
        else:
            self.lgr.debug('readLibTrack funExitHap, nothing read')
        #if self.write_bytes == 0:
        #    SIM_break_simulation('no bytes')
       
    def inFun(self):
        if self.fun_exit_hap is None:
            self.lgr.debug('readLibTrack inFun return False')
            return False
        else:
            self.lgr.debug('readLibTrack inFun return True')
            return True 
