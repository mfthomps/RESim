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
        self.lib = None
        self.addr = None
        self.image_base = None
        self.hap = None
        self.phys_addr = None
        
class TraceBuffer():
    def __init__(self, top, buffer_file, cpu, cell_name, mem_utils, context_manager, so_map, lgr, msg=None):
        self.lgr = lgr
        self.top = top
        self.cpu = cpu
        self.cell_name = cell_name
        self.mem_utils = mem_utils
        self.so_map = so_map
        self.context_manager = context_manager
        self.addr_info = {}
        self.pending_libs = {}
        self.pending_pages = {}
        self.return_hap = None
        self.did_files = []
        self.buffer_list = []
        ''' for including buffer traces in watch marks '''
        self.dataWatch = None
        if buffer_file is not None:
            if os.path.isfile(buffer_file) and buffer_file not in self.did_files:
                self.did_files.append(buffer_file)
                with open(buffer_file) as fh:
                    self.lgr.debug('traceBuffer loading from %s msg %s %s' % (buffer_file, msg, str(self.did_files)))
                    for line in fh:
                        if line.startswith ('#') or len(line.strip())==0:
                            continue
                        if line.startswith('call_reg') or line.startswith('string_reg'):
                            parts = line.strip().split()
                            if len(parts) != 4:
                                self.lgr.error('traceBuffer bad entry %s in %s' % (line, buffer_file))
                                return
                            try:
                                lib_addr = parts[1]
                            except:
                                self.lgr.error('traceBuffer bad address entry %s in %s' % (line, buffer_file))
                                return
                            reg = parts[2]
                            outfile = parts[3]
                            trace_info = BufferInfo(parts[0], reg, outfile)
                            self.buffer_list.append(trace_info)
                            if trace_info.fh is None:
                                self.lgr.error('traceBuffer unable to open outfile %s from %s' % (outfile, buffer_file))
                                return
                            else:
                                self.lgr.debug('traceBuffer output file will be %s' % outfile)
                            if msg is not None:
                                trace_info.fh.write(msg+'\n')
                                trace_info.fh.flush()
                                self.lgr.debug('traceBuffer wrote %s to trace info' % msg)
                            self.handleTraceEntry(lib_addr, trace_info)
                          
                    #self.doBreaks() 
            else:
                self.lgr.error('traceBuffer no such file: %s' % buffer_file)

    def handleTraceEntry(self, lib_addr, trace_info):
        ''' parse the library name and address, add them to trace_info and try to get the image base and physical address'''
        self.lgr.debug('traceBuffer handleTraceEntry lib_addr %s' % lib_addr)
        retval = True
        lib = None
        addr = None
        if ':' not in lib_addr:
            self.lgr.error('traceBuffer handleTraceEntry bad format %s, missing colon' % lib_addr)
            retval = False
        else:
            try:
                lib, addr = lib_addr.split(':')
            except:
                self.lgr.error('traceBuffer handleTraceEntry bad format %s' % lib_addr)
                retval = False
        if retval:
            trace_info.lib = lib
            try:
                trace_info.addr = int(addr, 16)
            except:
                 self.lgr.error('traceBuffer handleTraceEntry bad addr %s' % addr)
                 return
            trace_info.lib_addr = lib_addr
            image_base = self.so_map.getImageBase(lib)
            if image_base is None:
                # No process has loaded this image.  Set a callback for each load of the library
                self.lgr.debug('traceBuffer handleTraceEntry no process has image loaded, set SO watch callback for %s' % lib_addr)
                self.so_map.addSOWatch(trace_info.lib, self.libLoadCallback, name=lib_addr)
                self.pending_libs[lib_addr] = trace_info
            else:
                # Library loaded by someone.  Get list of pids
                trace_info.image_base = image_base
                loaded_pids = self.so_map.getSOPidList(lib)
                if len(loaded_pids) == 0:
                    self.lgr.error('traceBuffer handleTraceEntry expected at least one pid for %s' % lib)
                    return
                self.lgr.debug('traceBuffer handleTraceEntry has %d pids with lib loaded' % len(loaded_pids))
                phys = None
                for pid in loaded_pids:
                    load_addr = self.so_map.getLoadAddr(lib, tid=str(pid))
                    if load_addr is not None:
                        self.lgr.debug('traceBuffer handleTraceEntry pid %s load addr 0x%x, call getPhys' % (pid, load_addr))
                        phys = self.getPhys(trace_info, load_addr, pid)
                        if phys is not None and phys != 0:
                            self.setBreak(trace_info, phys)

    def libLoadCallback(self, load_addr, lib_addr):
        self.lgr.debug('traceBuffer libLoadCallback for %s load_addr 0x%x' % (lib_addr, load_addr))
        if lib_addr in self.pending_libs:
            trace_info = self.pending_libs[lib_addr]
            if trace_info.image_base is None:
                trace_info.image_base = self.so_map.getImageBase(trace_info.lib)
            tid = self.top.getTID(target=self.cell_name)
            phys = self.getPhys(trace_info, load_addr, str(tid))
            if phys is not None and phys != 0:
                self.setBreak(trace_info, phys)
            else:
                offset = load_addr - trace_info.image_base
                linear = trace_info.addr + offset
                self.lgr.debug('traceBuffer libLoadCallback for load_addr 0x%x image_base 0x%x offset 0x%x linear 0x%x' % (load_addr, trace_info.image_base, offset, linear))
                self.pending_pages[trace_info.lib_addr] = trace_info
                self.top.pageCallback(linear, self.pagedIn, name=trace_info.lib_addr)
        else:
            self.lgr.error('traceBuffer libLoadCallback for %s, but not in pending_libs' % lib_addr)

    def pagedIn(self, linear, name):
        if name not in self.pending_pages:
            self.lgr.error('traceBuffer pagedIn name %s not in pending_pages' % name)
            return
        trace_info = self.pending_pages[name]
        tid = self.top.getTID(target=self.cell_name)
        load_addr = self.so_map.getLoadAddr(trace_info.lib, tid)
        if load_addr is not None:
            self.lgr.debug('traceBuffer paged_in load_addr 0x%x name %s linear 0x%x' % (load_addr, name, linear))
            phys = self.getPhys(trace_info, load_addr, None)
            if phys is not None and phys != 0:
                self.setBreak(self.pending_pages[name], phys)
        else:
            self.lgr.error('traceBuffer paged_in load_addr None name %s linear 0x%x' % (name, linear))


    def getPhys(self, trace_info, load_addr, pid):
        offset = load_addr - trace_info.image_base
        linear = trace_info.addr + offset
        phys_addr = self.mem_utils.v2p(self.cpu, linear, use_pid=pid)
        self.lgr.debug('traceBuffer getPhys load_addr 0x%x image_base 0x%x offset 0x%x, linear 0x%x pid:%s' % (load_addr, trace_info.image_base, offset, linear, pid))
        #if phys_addr is not None:
        #    # Cancel callbacks
        #    self.so_map.cancelSOWatch(trace_info.lib, trace_info.lib_addr)
        if phys_addr is None:
            self.pending_pages[trace_info.lib_addr] = trace_info
            self.top.pageCallback(linear, self.pagedIn, name=trace_info.lib_addr, use_pid=pid)
        return phys_addr

    def setBreak(self, trace_info, phys_addr):
        self.lgr.debug('traceBuffer setBreak phys_addr 0x%x for %s' % (phys_addr, trace_info.lib_addr))

        proc_break = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_addr, 1, 0)
        hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.bufferHap, trace_info, proc_break, name='trace_buffer', disable_forward=False)
        trace_info.phys_addr = phys_addr
        trace_info.hap = hap
    
    class ReturnInfo():
        def __init__(self, trace_info, buf_addr):
            self.trace_info = trace_info               
            self.buf_addr = buf_addr               

    def bufferHap(self, trace_info, third, forth, memory):
        if trace_info.hap is None:
            return
        phys = memory.physical_address
        reg_value = self.mem_utils.getRegValue(self.cpu, trace_info.reg) 
        if reg_value is None:
            self.lgr.error('traceBuffer failed to read from reg %s' % info.reg)
            SIM_break_simulation('traceBuffer error')
            return
        self.lgr.debug('traceBuffer bufferHap phys: 0x%x addr: 0x%x reg: %s contains: 0x%x' % (phys, trace_info.addr, trace_info.reg, reg_value))
        if trace_info.kind == 'call_reg':
            eip = self.top.getEIP(cpu = self.cpu)
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            next_addr = eip + instruct[0]
            proc_break = self.context_manager.genBreakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, next_addr, 1, 0)
            return_info = self.ReturnInfo(trace_info, reg_value)
            self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.returnHap, return_info, proc_break, 'trace_buffer_return_hap')
            self.lgr.debug('traceBuffer bufferHap set returnHap on 0x%x context %s cycle: 0x%x' % (next_addr, str(self.cpu.current_context), self.cpu.cycles))
        elif trace_info.kind == 'string_reg':
            buf = self.mem_utils.readString(self.cpu, reg_value, 256)
            self.lgr.debug('traceBuffer bufferHap string_reg read: %s' % buf)
            trace_info.fh.write(buf+'\n')
            trace_info.fh.flush()
            if self.dataWatch is not None:
                self.dataWatch.markLog(buf, os.path.basename(trace_info.lib))
            
        else:
            self.lgr.error('traceBuffer bufferHap unknown kind: %s' % trace_info.kind)
 
    def msg(self, msg):
        if len(self.buffer_list) > 0:
            trace_info = self.buffer_list[0]
            trace_info.fh.write(msg+'\n')
            trace_info.fh.flush()
        if len(self.buffer_list) > 1:
            self.lgr.debug('traceBuffer only wrote msg to first trace_info buffer.  TBD')

    def rmHap(self, hap, immediate=False):
        self.context_manager.genDeleteHap(hap, immediate=immediate)

    def rmAllHaps(self, immediate=False):
        self.lgr.debug('traceBuffer rmAllHaps')
        for entry in self.buffer_list:
            if entry.hap is not None:
                self.rmHap(entry.hap, immediate=immediate)
                entry.hap = None
        if self.return_hap is not None:
            hap = self.return_hap
            self.rmHap(hap, immediate=immediate)
            self.return_hap = None    

    def restoreHaps(self):
        self.lgr.debug('traceBuffer restoreHaps')
        for entry in self.buffer_list:
            if entry.phys_addr is not None:
                self.setBreak(entry, entry.phys_addr)

    def returnHap(self, return_info, third, forth, memory):
        if self.return_hap is None:
            return
        self.lgr.debug('traceBuffer returnHap instruct addr: 0x%x cycle: 0x%x' % (memory.logical_address, self.cpu.cycles))
        buf = self.mem_utils.readString(self.cpu, return_info.buf_addr, 256)
        self.lgr.debug('traceBuffer returnHap read: %s' % buf)
        return_info.trace_info.fh.write(buf+'\n')
        return_info.trace_info.fh.flush()
        if self.dataWatch is not None:
            self.dataWatch.markLog(buf, os.path.basename(return_info.trace_info.lib))
        hap = self.return_hap
        SIM_run_alone(self.rmHap, hap)
        self.return_hap = None

    #def msg(self, msg):
    #    for addr in self.addr_info: 
    #        self.addr_info[addr].fh.write(msg+'\n')

    def markLogs(self, dataWatch):
        self.dataWatch = dataWatch
        self.lgr.debug('traceBuffer dataWatch set to include buffer traces in watch marks.')
