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
Manage dynamic setting of a register value based on execution of a
memory address.  This is controlled by a
"regSet" file.  There should be no more than one such file
per target.  The format of the file is:
    comm addr reg value
Where "comm" is the process comm name; addr is the address; reg is a
register name and value is the value to load into the register.

To handle snapshots, the module keeps a list of each comm/address pairs
and pickles that.  Those entries are then skipped when the snapshot 
is restored.
'''
from simics import *
from resimHaps import *
import os
import pickle
import binascii
class BreakRec():
    def __init__(self, addr, comm, reg, value, hap):
        self.addr = addr
        self.comm = comm
        self.hap = hap
        self.reg = reg
        self.value = value

class RegSet():
    def __init__(self, top, cpu, cell_name, fname, lgr, snapshot=None):
        self.cpu = cpu
        self.cell_name = cell_name
        self.top = top
        self.lgr = lgr
        self.breakmap = {}
        if not os.path.isfile(fname):
            self.lgr.error('RegSet: Could not find RegSet file %s' % fname)
            return
        with open (fname) as fh:
            for line in fh:
                if line.strip().startswith('#'):
                    continue 
                parts = line.strip().split()
                if len(parts) != 4:
                    self.lgr.error('RegSet: Could not make sense of %s' % line)
                    return
                comm = parts[0]
                try:
                    addr = int(parts[1], 16)
                except:
                    self.lgr.error('RegSet: bad addr in %s' % line)
                    return
                ''' Set break unless comm/addr pair appears in the pickled list '''
                comm_addr = '%s:0x%x' % (comm, addr)
                reg = parts[2]
                try:
                    value = int(parts[3], 16)
                except:
                    self.lgr.error('RegSet: bad value in %s' % line)
                    self.top.quit()
                self.addBreak(addr, comm, reg, value)
        self.lgr.debug('RegSet: set %d breaks' % len(self.breakmap))

    def addBreak(self, addr, comm, reg, value):
                breakpt = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
                self.lgr.debug('RegSet addBreak %d addr 0x%x comm: %s context %s' % (breakpt, addr, comm, self.cpu.current_context))
                hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.executeHap, None, breakpt)
                self.breakmap[breakpt] = BreakRec(addr, comm.strip(), reg, value, hap)
         
    def executeHap(self, dumb, context, break_num, memory):
        if break_num not in self.breakmap:
            self.lgr.error('RegSet syscallHap break %d not in breakmap' % break_num)
            return
        cpu, comm, pid = self.top.getCurrentProc(target_cpu=self.cpu) 
        if not self.breakmap[break_num].comm.startswith(comm):
            self.lgr.debug('RegSet: syscallHap wrong process, expected %s got %s' % (self.breakmap[break_num].comm, comm))
        else:
            self.lgr.debug('RegSet comm %s hit 0x%x would update reg %s to 0x%x' % (comm, memory.logical_address, self.breakmap[break_num].reg, self.breakmap[break_num].value)) 
            self.top.writeRegValue(self.breakmap[break_num].reg, self.breakmap[break_num].value, target_cpu=self.cpu)
            #SIM_break_simulation('remove me')
            done = '%s:0x%x' % (self.breakmap[break_num].comm, self.breakmap[break_num].addr)
            #SIM_run_alone(self.rmHap, break_num)

    def rmHap(self, break_num):
        if break_num in self.breakmap:
            RES_delete_breakpoint(break_num)
            RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.breakmap[break_num].hap)
            del self.breakmap[break_num]

    def swapContext(self):
        cpu, comm, pid = self.top.getCurrentProc(target_cpu=self.cpu) 
        self.lgr.debug('RegSet swapContext, current comm %s' % comm)
        swap_list = []
        for break_num in self.breakmap:
            if self.breakmap[break_num].comm.startswith(comm):
                swap_list.append(break_num)
        for break_num in swap_list:
            self.lgr.debug('RegSet swapContext for comm %s current context %s' % (self.breakmap[break_num].comm, self.cpu.current_context))
            self.addBreak(self.breakmap[break_num].addr, self.breakmap[break_num].comm, self.breakmap[break_num].reg, self.breakmap[break_num].value)
            SIM_run_alone(self.rmHap, break_num)
