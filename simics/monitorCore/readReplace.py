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
Manage dynamic replacement of memory content triggered by the
first read of the memory address.  This is controlled by a
"readReplace" file.  There should be no more than one such file
per target.  The format of the file is:
    lib:addr value [comm]
Where lib is the name of a program or shared object and value
is a hexidecimal string that will be unhexified and written to the given
address the first time the address is read.  
The comm value is optional.  If given, the replace will only occur if the
current thread matches the comm when the address is read.

To handle snapshots, the module keeps a list of each lib/address pair
and pickles that.  Those entries are then skipped when the snapshot 
is restored.
'''
from simics import *
from resimHaps import *
import os
import pickle
import binascii
class BreakRec():
    def __init__(self, addr, comm, hexstring, hap):
        self.addr = addr
        self.comm = comm
        self.hap = hap
        self.hexstring = hexstring

class ReplaceEntry():
    def __init__(self, lib, addr, value, comm, lib_addr):
        self.lib = lib
        self.addr = addr
        self.value = value
        self.comm = comm
        self.lib_addr = lib_addr
        self.image_base = None
        self.hap = None
        self.phys_addr = None
        self.linear_addr = None

class ReadReplace():
    def __init__(self, top, cpu, cell_name, fname, so_map, mem_utils, lgr, snapshot=None):
        self.cpu = cpu
        self.cell_name = cell_name
        self.top = top
        self.so_map = so_map
        self.mem_utils = mem_utils
        self.lgr = lgr

        self.breakpoints = {}
        self.hap = {}
        self.breakmap = {}
        self.pending_libs = {}
        self.done_list = []
        if not os.path.isfile(fname):
            self.lgr.error('readReplace: Could not find readReplace file %s' % fname)
            return
        if snapshot is not None:
            self.pickleLoad(snapshot)
        with open (fname) as fh:
            lib_addr = None
            comm = None
            for line in fh:
                if line.strip().startswith('#') or len(line.strip())==0:
                    continue 
                parts = line.strip().split()
                if len(parts) < 2:
                    self.lgr.error('readReplace: not enough fields in %s' % line)
                    return
                if len(parts) > 2:
                    comm = parts[2]
                if ':' in parts[0]:
                    lib_addr = parts[0]
                    lib, addr_s = parts[0].split(':', 1)
                    try:
                        addr = int(addr_s,16)
                    except:
                        self.lgr.error('readReplace: Could not make sense of  addr 0x%x in %s' % (addr_s, line))
                        return
                else:
                    self.lgr.error('readReplace: Could not make sense of %s' % line)
                    return
                ''' Set break unless lib/addr pair appears in the pickled list '''
                if lib_addr not in self.done_list:
                    hexstring = parts[1]
                    self.handleEntry(addr, lib, hexstring, comm, lib_addr)
        self.lgr.debug('readReplace: set %d breaks' % len(self.breakmap))

    def handleEntry(self, addr, lib, hexstring, comm, lib_addr):
        self.lgr.debug('readReplace handleEntry addr 0x%x lib %s hexstring %s' % (addr, lib, hexstring))
        image_base = self.so_map.getImageBase(lib)
        replace_entry = ReplaceEntry(lib, addr, hexstring, comm, lib_addr)
        if image_base is None:
            # No process has loaded this image.  Set a callback for each load of the library
            self.lgr.debug('readReplace handleEntry no process has image loaded, set SO watch callback for %s' % lib_addr)
            self.so_map.addSOWatch(lib, self.libLoadCallback, name=lib_addr)
            self.pending_libs[lib_addr] = replace_entry
        else:
            # Library loaded by someone.  Get list of pids
            replace_entry.image_base = image_base
            loaded_pids = self.so_map.getSOPidList(lib)
            if len(loaded_pids) == 0:
                self.lgr.error('readReplace handleEntry expected at least one pid for %s' % lib)
                return
            self.lgr.debug('readReplace handleEntry has %d pids with lib loaded' % len(loaded_pids))
            phys = None
            for pid in loaded_pids:
                load_addr = self.so_map.getLoadAddr(lib, tid=str(pid))
                if load_addr is not None:
                    self.lgr.debug('readReplace handleEntry pid %s load addr 0x%x, call getPhys' % (pid, load_addr))
                    phys = self.getPhys(replace_entry, load_addr, pid)
                    if phys is not None and phys != 0:
                        self.setBreak(replace_entry, phys)

    def getPhys(self, replace_entry, load_addr, pid):
        offset = load_addr - replace_entry.image_base
        linear = replace_entry.addr + offset
        phys_addr = self.mem_utils.v2p(self.cpu, linear, use_pid=pid)
        self.lgr.debug('readReplace getPhys load_addr 0x%x image_base 0x%x offset 0x%x, linear 0x%x pid:%s' % (load_addr, replace_entry.image_base, offset, linear, pid))
        #if phys_addr is not None:
        #    # Cancel callbacks
        #    self.so_map.cancelSOWatch(trace_info.lib, trace_info.lib_addr)
        if phys_addr is None:
            self.top.pageCallback(linear, self.pagedIn, name=replace_entry.lib_addr, use_pid=pid)
        else:
            replace_entry.linear_addr =  linear
        return phys_addr

    def setBreak(self, replace_entry, phys_addr):
        self.lgr.debug('readReplace setBreak phys_addr 0x%x for %s' % (phys_addr, replace_entry.lib_addr))
        breakpt = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_addr, 1, 0)
        self.breakpoints[replace_entry.lib_addr] = breakpt
        hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.readHap, replace_entry, self.breakpoints[replace_entry.lib_addr])

        self.hap[replace_entry.lib_addr] = hap
        replace_entry.hap = hap
        replace_entry.phys_addr = phys_addr
        self.breakmap[breakpt] = replace_entry


    #def addBreak(self, addr, comm, hexstring):
    #            breakpt = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Read, addr, 1, 0)
    #            self.lgr.debug('readReplace addBreak %d addr 0x%x context %s' % (breakpt, addr, self.cpu.current_context))
    #            hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.readHap, None, breakpt)
    #            self.breakmap[breakpt] = BreakRec(addr, comm, hexstring, hap)
        
    def getProg(self, break_num):
        cpu, comm, tid = self.top.getCurrentProc(target_cpu=self.cpu) 
        entry_comm = self.breakmap[break_num].comm
        if entry_comm is not None and len(entry_comm) > 15:
            full_prog = self.top.getProgName(tid)
            if full_prog is not None:
                prog = os.path.basename(full_prog)
        else:
            prog = comm
        return prog
 
    def readHap(self, replace_entry, context, break_num, memory):
        if break_num not in self.breakmap:
            self.lgr.error('readReplace syscallHap break %d not in breakmap' % break_num)
            return
        prog = self.getProg(break_num)
        if replace_entry.comm is not None and prog != self.breakmap[break_num].comm:
            self.lgr.debug('readReplace: syscallHap wrong process, expected %s got %s' % (self.breakmap[break_num].comm, prog))
        else:
            bstring = binascii.unhexlify(bytes(self.breakmap[break_num].value.encode())) 
            self.lgr.debug('readReplace comm %s would write %s to phys 0x%x, linear addr of interest is 0x%x' % (prog, bstring, memory.physical_address, self.breakmap[break_num].linear_addr)) 
            self.top.writeString(self.breakmap[break_num].linear_addr, bstring, target_cpu=self.cpu)
            #SIM_break_simulation('remove me')
            done = '%s:0x%x' % (self.breakmap[break_num].comm, self.breakmap[break_num].addr)
            self.done_list.append(done) 
            SIM_run_alone(self.rmHap, break_num)

    def rmHap(self, break_num):
        if break_num in self.breakmap:
            RES_delete_breakpoint(break_num)
            RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.breakmap[break_num].hap)
            del self.breakmap[break_num]

    def pickleit(self, name):
        done_file = os.path.join('./', name, self.cell_name, 'read_replace.pickle')
        fd = open(done_file, "wb") 
        pickle.dump( self.done_list, fd)
        self.lgr.debug('readReplace done_list pickleit to %s ' % (done_file))

    def pickleLoad(self, name):
        done_file = os.path.join('./', name, self.cell_name, 'read_replace.pickle')
        if os.path.isfile(done_file):
            self.done_list = pickle.load( open(done_file, 'rb') ) 

    def disableBreaks(self):
        self.lgr.debug('readReplace disableBreaks')
        for break_num in self.breakmap: 
            SIM_disable_breakpoint(break_num)

    def enableBreaks(self):
        self.lgr.debug('readReplace enableBreaks')
        for break_num in self.breakmap: 
            SIM_enable_breakpoint(break_num)

    def libLoadCallback(self, load_addr, lib_addr):
        self.lgr.debug('readReplace libLoadCallback for %s load_addr 0x%x' % (lib_addr, load_addr))
        if lib_addr in self.pending_libs:
            replace_entry = self.pending_libs[lib_addr]
            if replace_entry.image_base is None:
                replace_entry.image_base = self.so_map.getImageBase(replace_entry.lib)
            tid = self.top.getTID(target=self.cell_name)
            phys = self.getPhys(replace_entry, load_addr, str(tid))
            if phys is not None and phys != 0:
                self.setBreak(replace_entry, phys)
            else:
                offset = load_addr - replace_entry.image_base
                linear = replace_entry.addr + offset
                self.lgr.debug('readReplace libLoadCallback for load_addr 0x%x image_base 0x%x offset 0x%x linear 0x%x' % (load_addr, replace_entry.image_base, offset, linear))
                self.pending_pages[replace_entry.lib_addr] = replace_entry
                self.top.pageCallback(linear, self.pagedIn, name=replace_entry.lib_addr)
        else:
            self.lgr.error('readReplace libLoadCallback for %s, but not in pending_libs' % lib_addr)

    def pagedIn(self, linear, name):
        if name not in self.pending_pages:
            self.lgr.error('readReplace pagedIn name %s not in pending_pages' % name)
            return
        replace_entry = self.pending_pages[name]
        load_addr = self.so_map.getLoadAddr(replace_entry.lib)
        self.lgr.debug('readReplace paged_in load_addr 0x%x name %s linear 0x%x' % (load_addr, name, linear))
        phys = self.getPhys(replace_entry, load_addr, None)
        if phys is not None and phys != 0:
            self.setBreak(self.pending_pages[name], phys)
