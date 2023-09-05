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
Use buffer trace files to identify output buffers (e.g., debug buffers that may not in practice
generate output) and record entries made to them.
'''
from simics import *
import os
class BufferInfo():
    def __init__(self, kind, reg, outfile):
        self.kind = kind
        self.reg = reg
        out_path = os.path.join('./logs', 'trace_buffer', outfile)
        try:
            os.mkdir(os.path.dirname(out_path))
        except:
            pass
        try:
            self.fh = open(out_path, 'a')
        except:
            self.fh = None 
        buf_addr = None
        
class TraceBuffer():
    def __init__(self, top, cpu, mem_utils, context_manager, lgr, msg=None):
        self.lgr = lgr
        self.top = top
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.addr_info = {}
        self.buf_haps = []
        self.return_hap = None
        buffer_file = os.getenv('TRACE_BUFFERS')
        if buffer_file is not None:
            if os.path.isfile(buffer_file):
                with open(buffer_file) as fh:
                    self.lgr.debug('TraceBuffer loading from %s' % buffer_file)
                    for line in fh:
                        if line.startswith ('#'):
                            continue
                        if line.startswith('call_reg') or line.startswith('string_reg'):
                            parts = line.strip().split()
                            if len(parts) != 4:
                                self.lgr.error('TraceBuffer bad entry %s in %s' % (line, buffer_file))
                                return
                            try:
                                addr = int(parts[1], 16)
                            except:
                                self.lgr.error('TraceBuffer bad entry %s in %s' % (line, buffer_file))
                                return
                            reg = parts[2]
                            outfile = parts[3]
                            info = BufferInfo(parts[0], reg, outfile)
                            if info.fh is None:
                                self.lgr.error('TraceBuffer unable to open outfile %s from %s' % (outfile, buffer_file))
                                return
                            if msg is not None:
                                info.fh.write(msg+'\n')
                                info.fh.flush()
                                self.lgr.debug('TraceBuffer wrote %s to trace info' % msg)
                            self.addr_info[addr] = info
                          
                    self.doBreaks() 
            else:
                self.lgr.error('TraceBuffer no such file: %s' % buffer_file)

    def doBreaks(self):
        for addr in self.addr_info:  
            self.lgr.debug('TraceBuffer doBreaks addr: 0x%x current context %s' % (addr, self.cpu.current_context))
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
            self.lgr.debug('TraceBuffer doBreaks addr: 0x%x break %d' % (addr, proc_break))
            hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.bufferHap, addr, proc_break, 'trace_buffer_hap')
            self.buf_haps.append(hap)

    def bufferHap(self, addr, third, forth, memory):
        if addr not in self.addr_info:
            self.lgr.error('TraceBuffer bufferHap addr 0x%x not in dict' % addr)
        info = self.addr_info[addr]
        reg_value = self.mem_utils.getRegValue(self.cpu, info.reg) 
        if reg_value is None:
            self.lgr.error('TraceBuffer failed to read from reg %s' % info.reg)
            SIM_break_simulation('TraceBuffer error')
            return
        self.lgr.debug('TraceBuffer bufferHap addr: 0x%x reg: %s contains: 0x%x' % (addr, info.reg, reg_value))
        if info.kind == 'call_reg':
            info.buf_addr = reg_value
            eip = self.top.getEIP(cpu = self.cpu)
            instruct = SIM_disassemble_address(self.cpu, addr, 1, 0)
            next_addr = addr + instruct[0]
            proc_break = self.context_manager.genBreakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, next_addr, 1, 0)
            self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.returnHap, addr, proc_break, 'trace_buffer_return_hap')
            self.lgr.debug('TraceBuffer bufferHap set returnHap on 0x%x context %s cycle: 0x%x' % (next_addr, str(self.cpu.current_context), self.cpu.cycles))
        elif info.kind == 'string_reg':
            buf = self.mem_utils.readString(self.cpu, reg_value, 256)
            self.lgr.debug('TraceBuffer bufferHap string_reg read: %s' % buf)
            info.fh.write(buf+'\n')
            info.fh.flush()
            
        else:
            self.lgr.error('TraceBuffer bufferHap unknown kind: %s' % info.kind)

    def rmHap(self, hap):
        self.context_manager.genDeleteHap(hap)

    def rmAllHaps(self):
        for hap in self.buf_haps:
            self.rmHap(hap)
        self.buf_haps = []
        if self.return_hap is not None:
            hap = self.return_hap
            self.rmHap(hap)
            self.return_hap = None    

    def returnHap(self, addr, third, forth, memory):
        if self.return_hap is None:
            return
        self.lgr.debug('TraceBuffer returnHap instruct addr: 0x%x cycle: 0x%x' % (addr, self.cpu.cycles))
        info = self.addr_info[addr]
        buf = self.mem_utils.readString(self.cpu, info.buf_addr, 256)
        self.lgr.debug('TraceBuffer returnHap read: %s' % buf)
        info.fh.write(buf+'\n')
        info.fh.flush()
        hap = self.return_hap
        SIM_run_alone(self.rmHap, hap)
        self.return_hap = None
        #SIM_break_simulation('remove this info.buf_addr 0x%x' % info.buf_addr)

    def msg(self, msg):
        for addr in self.addr_info: 
            self.addr_info[addr].fh.write(msg+'\n')
