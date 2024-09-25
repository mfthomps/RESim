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
def nextLine(fh):
   retval = None
   while retval is None:
       line = fh.readline()
       if line is None or len(line) == 0:
           break
       if line.startswith('#'):
           continue
       if len(line.strip()) == 0:
           continue
       retval = line.strip('\n')
   return retval
def getKeyValue(item):
    key = None
    value = None
    if '=' in item:
        parts = item.split('=', 1)
        key = parts[0].strip()
        value = parts[1].strip()
    return key, value
class BreakRec():
    def __init__(self, addr, comm, reg, value, hap, jmp, indirect, break_on_it):
        self.addr = addr
        self.comm = comm
        self.hap = hap
        self.reg = reg
        # hex string
        self.value = value
        self.jmp = jmp
        self.indirect = indirect
        self.break_on_it = break_on_it
    def toString(self):
        if self.indirect:
            retval = 'addr 0x%x comm: %s reg: %s hexstring: %s jmp: %s indirect: %r break_on_it: %r' % (self.addr, self.comm, self.reg, self.value, self.jmp, self.indirect, self.break_on_it)
        else:
            retval = 'addr 0x%x comm: %s reg: %s value: 0x%x jmp: %s indirect: %r break_on_it: %r' % (self.addr, self.comm, self.reg, self.value, self.jmp, self.indirect, self.break_on_it)
        return retval

class RegSet():
    def __init__(self, top, cpu, cell_name, fname, mem_utils, so_map, lgr, snapshot=None):
        self.cpu = cpu
        self.cell_name = cell_name
        self.top = top
        self.lgr = lgr
        self.mem_utils = mem_utils
        self.so_map = so_map
        self.breakmap = {}
        if not os.path.isfile(fname):
            self.lgr.error('RegSet: Could not find RegSet file %s' % fname)
            return
        with open (fname) as fh:
            for line in fh:
                if line.strip().startswith('#'):
                    continue 
                parts = line.strip().split()
                if '=' not in line and len(parts) != 4:
                    self.lgr.error('RegSet: Could not make sense of %s' % line)
                    return
                comm = parts[0]
                load_addr = self.so_map.getLoadAddr(comm)
                if load_addr is None:
                    #TBD add load/page callback for regSet
                    self.lgr.debug('RegSet failed to get load addr for %s' % comm)
                    return
                prog_addr = None
                try:
                    prog_addr = int(parts[1], 16)
                except:
                    self.lgr.error('RegSet: bad addr in %s' % line)
                    return
                ''' Set break unless comm/addr pair appears in the pickled list '''
                addr = prog_addr + load_addr
                comm_addr = '%s:0x%x' % (comm, addr)
                indirect = False
                jmp = None
                break_on_it = False
                if '=' in parts[2]:
                    for item in parts[2:]:
                        key, value = getKeyValue(item)
                        if key == 'reg':
                            reg = value
                        elif key == 'reg_indirect':
                            indirect = True 
                            reg = value
                        elif key == 'value':
                            try:
                                new_value = int(value, 16)
                            except:
                                self.lgr.error('RegSet: bad value in %s' % line)
                                return
                        elif key == 'hexstring':
                            new_value = value
                        elif key == 'jmp':
                            jmp = value
                            self.lgr.debug('RegSet: jmp is %s' % jmp)
                        elif key == 'break':
                            if value.lower() == 'true': 
                                break_on_it = True
                            self.lgr.debug('RegSet: jmp is %s' % jmp)
                else:
                    reg = parts[2]
                    try:
                        new_value = int(parts[3], 16)
                    except:
                        self.lgr.error('RegSet: bad value in %s' % line)
                        self.top.quit()
                
                self.addBreak(addr, comm, reg, new_value, jmp, indirect, break_on_it)
        self.lgr.debug('RegSet: set %d breaks' % len(self.breakmap))

    def addBreak(self, addr, comm, reg, value, jmp, indirect, break_on_it):
                breakpt = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
                hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.executeHap, None, breakpt)
                self.breakmap[breakpt] = BreakRec(addr, comm.strip(), reg, value, hap, jmp, indirect, break_on_it)
                self.lgr.debug('RegSet addBreak %d addr 0x%x comm: %s context %s rec %s' % (breakpt, addr, comm, self.cpu.current_context, self.breakmap[breakpt].toString()))
         
    def executeHap(self, dumb, context, break_num, memory):
        if break_num not in self.breakmap:
            self.lgr.error('RegSet syscallHap break %d not in breakmap' % break_num)
            return
        cpu, comm, pid = self.top.getCurrentProc(target_cpu=self.cpu) 
        item = self.breakmap[break_num]
        if not item.comm == 'any' and not item.comm.startswith(comm):
            self.lgr.debug('RegSet: syscallHap wrong process, expected %s got %s' % (item.comm, comm))
        else:
            if item.indirect:
                self.lgr.debug('RegSet comm %s hit 0x%x will replace content of address in reg %s to %s' % (comm, memory.logical_address, item.reg, item.value)) 
                addr = self.mem_utils.getRegValue(self.cpu, item.reg)
                bstring = binascii.unhexlify(item.value.encode())
                #self.top.writeString(addr, bstring, target_cpu=self.cpu)
                self.top.writeBytes(self.cpu, addr, bstring)
                self.lgr.debug('RegSet indirect wrote %s to 0x%x' % (item.value, addr))
            else:
                self.lgr.debug('RegSet comm %s hit 0x%x would update reg %s to 0x%x' % (comm, memory.logical_address, item.reg, item.value)) 
                self.top.writeRegValue(item.reg, item.value, target_cpu=self.cpu)
            if item.jmp is not None:
                if item.jmp == 'lr':
                    addr = self.mem_utils.getRegValue(self.cpu, 'lr')
                    self.top.writeRegValue('pc', addr, target_cpu=self.cpu)
                    self.lgr.debug('RegSet jmp to lr 0x%x' % addr)
                     
                else:
                    addr = int(item.jmp, 16)
                    self.top.writeRegValue('pc', addr, target_cpu=self.cpu)
                    self.lgr.debug('RegSet jmp to 0x%x' % addr)
            if item.break_on_it:
                SIM_break_simulation('regset break on it')
                self.lgr.debug('RegSet break on it')
           
           
            #SIM_break_simulation('remove me')
            #done = '%s:0x%x' % (item.comm, item.addr)
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
            if self.breakmap[break_num].comm.startswith(comm) or self.breakmap[break_num].comm == 'any':
                swap_list.append(break_num)
        for break_num in swap_list:
            self.lgr.debug('RegSet swapContext for comm %s current context %s' % (self.breakmap[break_num].comm, self.cpu.current_context))
            item = self.breakmap[break_num]
            self.addBreak(item.addr, item.comm, item.reg, item.value, item.jmp, item.indirect, item.break_on_it)
            SIM_run_alone(self.rmHap, break_num)
