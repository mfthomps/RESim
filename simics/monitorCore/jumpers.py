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
Manage execution jumpers to cause execution to jump to a selcted destination address
when a given source address is hit. The module attempts to set breakpoints on 
physical addresses.  If not mapped, a break is set on the page table with a callback
to set the jumper break when the code is mapped.

Format has two forms.  Each includes an optional comm paramter that names the process,
which is intended to differentiate processes that share a library containing the jump 
addresses. Each format also includes an optional 'break' keyword that causes the
simulation to stop at the destination address. The break keyword must come last.

Provide load addresses (implies you know the load address of source and destination)
    addr addr [comm] [break]
Provide original addresses (i.e., per the binary file).  Provide "prog" as either the
program name or the SO/DLL basename and the addr as the original address.
    prog:addr addr [comm] [break]
You can see original addresses via the cgc.getSO(addr, show_orig=True)

'''
from simics import *
import os
import ntpath
import winProg

class Jumpers():
    def __init__(self, top, context_manager, so_map, mem_utils, cpu, lgr):
        self.top = top
        self.lgr = lgr
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.cell_name = self.top.getTopComponentName(cpu)
        self.context_manager = context_manager
        self.so_map = so_map
        self.fromto = {}
        self.comm_name = {}
        self.temp = []
        self.hap = {}
        self.breakpoints = {}
        self.reverse_enabled = None
        ''' The simulation would stop at destinations corresponding to these source addresses.  '''
        self.break_simulation = []
        self.pending_libs = {}

    def setJumper(self, from_addr, to_addr, comm=None):
        self.fromto[from_addr] = to_addr
        if comm is not None:
            self.comm_name[from_addr] = comm
        self.setOneBreak(from_addr)

    def setOneBreak(self, addr):
        #phys_block = self.cpu.iface.processor_info.logical_to_physical(addr, Sim_Access_Execute)
        phys_addr = self.mem_utils.v2p(self.cpu, addr)
        #if phys_block.address == 0 or phys_block.address is None:
        if phys_addr is None or phys_addr == 0:
            #proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
            #self.hap[addr] = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.doJump, addr, proc_break, 'jumper')
            #self.lgr.debug('jumper setBreaks set break on linear addr 0x%x' % addr)
            #self.want_phys.append(addr)
            self.lgr.debug('jumper setOneBreak call pageCallback for addr 0x%x' % addr)
            self.top.pageCallback(addr, self.pagedIn)
        else:
            self.breakpoints[addr] = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_addr, 1, 0)
            self.hap[addr] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.doJump, addr, self.breakpoints[addr])
            self.lgr.debug('jumper setBreaks set phys break on addr 0x%x (phys 0x%x)' % (addr, phys_addr))

    def pagedIn(self, addr):
        self.lgr.debug('jumpers pagedIn addr 0x%x' % addr)
        self.setOneBreak(addr)

    def setBreaks(self):
        for f in self.fromto:
            self.setOneBreak(f)
    
    def doJump(self, addr, an_object, break_num, memory):
        #print('doJump')
        #self.lgr.debug('doJump')
        ''' callback when jumper breakpoint is hit'''
        #curr_addr = memory.logical_address 
        self.lgr.debug('doJump addr is 0x%x current_context (not that it effects this phys break) is %s' % (addr, self.cpu.current_context))
        if addr not in self.hap:
            self.lgr.debug('jumper doJump addr 0x%x not in haps' % addr)
            return
        if addr in self.comm_name:
            cpu, comm, pid = self.top.getCurrentProc(target_cpu=self.cpu)
            if comm != self.comm_name[addr]:
                self.lgr.debug('doJump comm %s does not match jumper comm of %s' % (comm, self.comm_name[addr]))
                return
        if self.reverse_enabled is None:
            self.reverse_enabled = self.top.reverseEnabled()
            self.lgr.debug('jumpers doJump setting reverse_enabled to %r' % self.reverse_enabled)
        self.top.writeRegValue('pc', self.fromto[addr], alone=True, target_cpu=self.cpu)
        self.lgr.debug('jumper doJump wrote 0x%x to pc' % (self.fromto[addr]))
        if addr in self.comm_name:
            self.lgr.debug('jumper doJump from 0x%x to 0x%x in comm %s' % (addr, self.fromto[addr], self.comm_name[addr]))
        else:
            self.lgr.debug('jumper doJump from 0x%x to 0x%x' % (addr, self.fromto[addr]))
        eip = self.top.getReg('pc', self.cpu)
        if addr in self.break_simulation:
            SIM_break_simulation('Jumper request')
            self.lgr.debug('jumper doJump did break_simulation')
        self.lgr.debug('jumper doJump did it, eip now 0x%x' % eip)

    def removeOneBreak(self, addr, immediate=False):
        self.lgr.debug('Jumpers removeOneBreak 0x%x' % addr)
        if addr not in self.hap:
            self.lgr.debug('jumpers removeOneBreak but addr 0x%x not in dict.' % addr)
            return
        SIM_delete_breakpoint(self.breakpoints[addr])
        SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.hap[addr])

    def removeBreaks(self, immediate=False):
        self.lgr.debug('Jumpers removeBreaks')
        for f in self.fromto:
            self.removeOneBreak(f, immediate=immediate)
        self.hap = {}
        self.breakpoints = {}

    def loadJumpers(self, fname):
        from_addr = None
        to_addr = None
        self.lgr.debug('jumpers loadJumper')
        if not os.path.isfile(fname):
            self.lgr.error('No jumper file found at %s' % fname)
        else:
            print('Loading jumpers from %s' % fname)
            with open(fname) as fh:
                for line in fh:
                    if line.strip().startswith('#'):
                        continue
                    if len(line.strip()) == 0:
                        continue
                    if ':' in line:
                        if not self.handleOrigAddrs(line):
                            return
                    else:
                        if not self.handleLoadAddrs(line):
                            return

    def handleLoadAddrs(self, line):
        retval = True
        parts = line.strip().split()
        if len(parts) < 2:
            self.lgr.error("jumpers Error reading %s from %s, bad jumper" % (line, fname))
            raise Exception("jumpers Error reading %s from %s, bad jumper" % (line, fname))
            return False
        try:
            from_addr = int(parts[0], 16)
            to_addr = int(parts[1], 16)
        except:
            self.lgr.error("jumpers Error reading %s from %s, bad jumper" % (line, fname))
            raise Exception("jumpers Error reading %s from %s, bad jumper" % (line, fname))
            return False
        comm = None
        if len(parts) == 3 and parts[2] == 'break':
            self.break_simulation.append(from_addr)
        elif len(parts) > 2:
            comm = parts[2]
        if len(parts) > 3 and parts[3] == 'break':
            self.break_simulation.append(from_addr)
        self.setJumper(from_addr, to_addr, comm) 
        return retval

    def handleOrigAddrs(self, line):
        self.lgr.debug('jumpers handleOrig')
        retval = True
        parts = line.strip().split()
        if len(parts) < 2:
            self.lgr.error("jumpers Error reading %s from %s, bad jumper" % (line, fname))
            raise Exception("jumpers Error reading %s from %s, bad jumper" % (line, fname))
            return False
        if ':' not in line:
            raise Exception("jumpers Error reading %s from %s, bad jumper expected colon" % (line, fname))
            return False
        prog = addr = to_addr = None
        try:
            prog, addr = parts[0].split(':') 
        except:
            self.lgr.error("jumpers Error reading %s from %s, bad jumper, expected only one colon" % (line, fname))
            raise Exception("jumpers Error reading %s from %s, bad jumper" % (line, fname))
            return False
        
        try:
            from_addr = int(addr, 16)
            to_addr = int(parts[1], 16)
        except:
            self.lgr.error("jumpers Error reading %s from %s, bad jumper" % (line, fname))
            raise Exception("jumpers Error reading %s from %s, bad jumper" % (line, fname))
            return False

        comm = None
        break_at_dest = False
        if len(parts) == 3 and parts[2] == 'break':
            break_at_dest = True
        elif len(parts) > 2:
            comm = parts[2]
        if len(parts) > 3 and parts[3] == 'break':
            break_at_dest = True

        cpu, this_comm, pid = self.top.getCurrentProc(target_cpu=self.cpu)
        prog_info = self.so_map.getSOAddr(prog, pid)
        if prog_info is None:
            self.lgr.debug('jumpers handleOrig, no prog info for %s, set callback with soMap' % prog)
            jump_rec = self.JumperRec(prog, from_addr, to_addr, comm, break_at_dest) 
            self.pending_libs[prog] = jump_rec
            self.so_map.addSOWatch(prog, self.libLoadCallback)
        else:
            offset = prog_info.offset
            self.lgr.debug('jumpers handleOrig, got prog info for %s, do breaks for orig addrs' % prog)
            self.doOrigBreaks(offset, from_addr, to_addr, comm, break_at_dest)
        return retval

    def libLoadCallback(self, section):
        ''' TBD fix and test for Linux '''
        self.lgr.debug('jumpers libLoadCallback')
        basename = ntpath.basename(section.fname)
        if basename in self.pending_libs:
            if section.image_base is None:
                self.lgr.debug('jumpers loadLibCallback no image base defined for %s, get it' % section.fname)
                full_path = self.top.getFullPath(fname=section.fname)
                self.lgr.debug('jumpers loadLibCallback got %s from getFullPath' % full_path)
                size, machine, section.image_base, section.text_offset = winProg.getSizeAndMachine(full_path, self.lgr)
            delta = (section.addr - section.image_base) 
            offset = delta + section.text_offset
            from_addr = self.pending_libs[basename].from_addr 
            to_addr = self.pending_libs[basename].to_addr
            comm = self.pending_libs[basename].comm
            break_at_dest = self.pending_libs[basename].break_at_dest
            self.lgr.debug('jumpers libLoadCallback basename %s offset 0x%x from 0x%x to 0x%x' % (basename, offset, from_addr, to_addr))
            self.doOrigBreaks(offset, from_addr, to_addr, comm, break_at_dest)
        
    def doOrigBreaks(self, offset, from_addr_in, to_addr_in, comm, break_at_dest):
        self.lgr.debug('jumpers doOrigBreaks offset 0x%x from_add 0x%x to_addr 0x%x' % (offset, from_addr_in, to_addr_in))
        from_addr = from_addr_in + offset 
        to_addr = to_addr_in + offset 
        self.setJumper(from_addr, to_addr, comm) 
        if break_at_dest:
            self.break_simulation.append(from_addr) 

    def disableBreaks(self):
        self.lgr.debug('Jumpers disableBreaks')
        for addr in self.breakpoints:
            SIM_disable_breakpoint(self.breakpoints[addr])
 
    def enableBreaks(self):
        self.lgr.debug('Jumpers enableBreaks')
        for addr in self.breakpoints:
            SIM_enable_breakpoint(self.breakpoints[addr])
 
    class JumperRec():
        def __init__(self, prog, from_addr, to_addr, comm, break_at_dest):
            self.prog = prog
            self.from_addr = from_addr
            self.to_addr = to_addr
            self.comm = comm
            self.break_at_dest = break_at_dest

