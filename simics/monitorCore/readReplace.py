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
    operator lib:addr value [comm]

Where operator is either code or data.  If code, then the target
address is determined by dereferencing a pointer in the instruction
at the given address when it is reached.  If data, then the target
address is the given address. 
The lib field is the name of a program or shared object and value
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
import decode
import decodeArm
import decodePPC32
import resimUtils
import memUtils
import os
import pickle
import binascii
class ReplaceEntry():
    def __init__(self, lib, addr, value, comm, lib_addr, operation, fname, writable):
        self.lib = lib
        self.addr = addr
        # value is a hexstring
        self.value = value
        self.comm = None
        self.comm_addr = None
        if comm is not None:
            if ':' in comm:
                # TBD support relocatable code
                self.comm, addr_string = comm.split(':')
                try:
                    self.comm_addr = int(addr_string, 16)
                except:
                    print('ERROR, bad comm:addr in %s' % fname)
                    self.addr = None
            else:
                self.comm = comm
        else:
            self.comm = None
        self.lib_addr = lib_addr
        self.operation = operation
        self.image_base = None
        self.hap = None
        self.phys_addr = None
        self.linear_addr = None
        self.fname = fname
        self.writable = writable

class ReadReplace():
    def __init__(self, top, cpu, cell_name, fname, so_map, mem_utils, lgr, snapshot=None):
        self.cpu = cpu
        self.cell_name = cell_name
        self.top = top
        self.so_map = so_map
        self.mem_utils = mem_utils
        self.lgr = lgr
        if cpu.architecture.startswith('arm'):
            self.decode = decodeArm
        elif cpu.architecture == 'ppc32':
            self.decode = decodePPC32
        else:
            self.decode = decode

        self.breakpoints = {}
        self.hap = {}
        self.breakmap = {}
        self.pending_libs = {}
        self.pending_pages = {}
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
                if len(parts) < 3:
                    self.lgr.error('readReplace: not enough fields in %s' % line)
                    return
                if len(parts) > 3:
                    comm = parts[3]
                if len(parts) > 4:
                    writable = resimUtils.yesNoTrueFalse(parts[4])
                else:
                    writable = False
                if ':' in parts[1]:
                    lib_addr = parts[1]
                    lib, addr_s = parts[1].split(':', 1)
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
                    hexstring = parts[2]
                    operation = parts[0]
                    self.handleEntry(addr, lib, hexstring, comm, lib_addr, operation, fname, writable)
        self.lgr.debug('readReplace: set %d breaks' % len(self.breakmap))

    def handleEntry(self, addr, lib, hexstring, comm, lib_addr, operation, fname, writable):
        self.lgr.debug('readReplace handleEntry addr 0x%x lib %s hexstring %s' % (addr, lib, hexstring))
        image_base = self.so_map.getImageBase(lib)
        replace_entry = ReplaceEntry(lib, addr, hexstring, comm, lib_addr, operation, fname, writable)
        if replace_entry.addr is None:
            self.lgr.error('readReplace handleEntry bad entry in %s' % fname)
            self.top.quit()
        did_write = False
        # See if this snapshot was created after the replace was done.  If so, do the replace immediately.
        # TBD this is incomplete.  Pre-supposes program of interest is scheduled.
        # See jumpers.py for strategy to split entry handling between SO and programs.
        mod_fname = self.getModFname(replace_entry)
        if os.path.isfile(mod_fname) and resimUtils.isSO(lib):
            with open(mod_fname) as fh:
                line = fh.read()
                parts = line.split()
                if len(parts) != 2:
                    self.lgr.error('readReplace handleEntry bad line in %s %s' % (mod_fname, line))
                    return
                if ':' in parts[0]:
                    prog, addr_s = parts[0].split(':')
                    try:
                        addr = int(addr_s, 16)
                    except:
                        self.lgr.error('readReplace handleEntry bad addr %s in %s' % (addr_s, line))
                        return
                    hexstring = parts[1]
                    phys_addr = self.mem_utils.v2p(self.cpu, addr)
                    if phys_addr is not None and phys_addr != 0:
                        bstring = binascii.unhexlify(hexstring.encode())
                        self.top.writeString(addr, bstring, target_cpu=self.cpu)
                        did_write = True
                        self.lgr.debug('readReplace handleEntry did write of %s to addr 0x%x' % (hexstring, addr))
                    else:
                        self.lgr.debug('readReplace handleEntry addr 0x%x not yet mapped' % addr)
        if not did_write:             
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
        if phys_addr is None or phys_addr == 0:
            self.lgr.debug('readReplace getPhys got None or zero, call pageCallback')
            self.top.pageCallback(linear, self.pagedIn, name=replace_entry.lib_addr, use_pid=pid)
            self.pending_pages[replace_entry.lib_addr] = replace_entry
        else:
            replace_entry.linear_addr =  linear
        return phys_addr

    def setBreak(self, replace_entry, phys_addr):
        ''' Either set the break on the address, or do the replace if operator is immediate '''
        if replace_entry.operation == 'immediate':
            self.doReplace(replace_entry, replace_entry.comm)
        else:
            if replace_entry.operation == 'code':
                access = Sim_Access_Execute
            elif replace_entry.operation == 'write':
                access = Sim_Access_Write
            else:
                access = Sim_Access_Read
            self.lgr.debug('readReplace setBreak phys_addr 0x%x for %s cycle: 0x%x' % (phys_addr, replace_entry.lib_addr, self.cpu.cycles))
            breakpt = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, access, phys_addr, 1, 0)
            self.breakpoints[replace_entry.lib_addr] = breakpt
            hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.readHap, replace_entry, self.breakpoints[replace_entry.lib_addr])
    
            self.hap[replace_entry.lib_addr] = hap
            replace_entry.hap = hap
            replace_entry.phys_addr = phys_addr
            self.breakmap[breakpt] = replace_entry

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
        ''' The data or code address has been hit.  If data, may be a write '''
        if break_num not in self.breakmap:
            self.lgr.debug('readReplace readHap break %d not in breakmap' % break_num)
            return
        prog = self.getProg(break_num)
        eip = self.top.getEIP()
        phys = memory.physical_address
        if replace_entry.comm is not None and (prog != self.breakmap[break_num].comm or \
                         self.breakmap[break_num].comm_addr is not None and self.breakmap[break_num].comm_addr != eip):
            if prog != self.breakmap[break_num].comm:
                self.lgr.debug('readReplace: readHap read phys: 0x%x wrong process, expected %s got %s cycles: 0x%x' % (phys, self.breakmap[break_num].comm, prog, self.cpu.cycles))
            else:
                self.lgr.debug('readReplace: readHap read phys: 0x%x correct process %s but eip 0x%x and wanted 0x%x cycle: 0x%x' % (phys, self.breakmap[break_num].comm, eip, self.breakmap[break_num].comm_addr, self.cpu.cycles))
           
        else:
            self.lgr.debug('readReplace: readHap GOT IT')

            op_type = SIM_get_mem_op_type(memory)
            if op_type != Sim_Trans_Load:
                # is a write, patch up the memory transaction
                if replace_entry.operation != 'write':
                    self.lgr.error('readReplace readHap is write, but operation is %s' % replace_entry.operation)
                    return
                new_value = memUtils.memoryValue(self.cpu, memory)
                our_value = int(replace_entry.value, 16)
                self.lgr.debug('readReplace readHap IS WRITE transaction value is 0x%x, replace that with 0x%x' % (new_value, our_value))
                memUtils.setMemoryValue(self.cpu, memory, our_value)
                mod_addr = replace_entry.linear_addr
                #SIM_run_alone(self.top.clearBookmarks, None)
                SIM_run_alone(self.top.resetOriginIfReversing, None)
            else:
                mod_addr = self.doReplace(replace_entry, prog)

            SIM_run_alone(self.rmHap, break_num)
            del self.breakmap[break_num]
            #SIM_run_alone(self.rmAllHap, None)
            mod_fname = self.getModFname(replace_entry)
            line = '%s:0x%x %s' % (prog, mod_addr, replace_entry.value)
            with open(mod_fname, 'w') as fh:
                fh.write(line)

    def doReplace(self, replace_entry, prog):
        bstring = binascii.unhexlify(bytes(replace_entry.value.encode())) 
        if replace_entry.operation == 'code':
            ins_addr = replace_entry.linear_addr
            instruct = SIM_disassemble_address(self.cpu, ins_addr, 1, 0)
            op2, op1 = self.decode.getOperands(instruct[1])
            mod_addr = None
            if '[' in op1:
                mod_addr = self.decode.getAddressFromOperand(self.cpu, op1, self.lgr)
            elif '[' in op2:
                mod_addr = self.decode.getAddressFromOperand(self.cpu, op2, self.lgr)
            if mod_addr is None:
                self.lgr.error('readReplace doReplace readHap failed to get modify address from %s' % instruct[1])
                return
            self.lgr.debug('readReplace doReplace comm %s would write %s to  0x%x cycle: 0x%x' % (prog, bstring, mod_addr, self.cpu.cycles))
        else:
            mod_addr = replace_entry.linear_addr
            phys = self.mem_utils.v2p(self.cpu, mod_addr)
            self.lgr.debug('readReplace doReplace comm %s would write %s to linear addr of interest is 0x%x phys: 0x%x cycle: 0x%x' % (prog, bstring, mod_addr, phys, self.cpu.cycles))

        # actually writing bytes
        self.top.writeString(mod_addr, bstring, target_cpu=self.cpu)
        #SIM_break_simulation('remove me')
        done = '%s:0x%x' % (replace_entry.comm, replace_entry.addr)
        self.done_list.append(done) 
        return mod_addr

    def getModFname(self, replace_entry):
        mod_fname = '%s.%s.0x%x' % (replace_entry.fname, replace_entry.lib, replace_entry.addr)
        return mod_fname
 
    def rmAllHap(self, dumb):
        map_copy = list(self.breakmap.keys())
        for break_num in map_copy:
            self.rmHap(break_num)
        self.breakmap = []

    def rmHap(self, break_num):
        if break_num in self.breakmap:
            RES_delete_breakpoint(break_num)
            RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.breakmap[break_num].hap)

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
        #self.lgr.debug('readReplace disableBreaks')
        for break_num in self.breakmap: 
            SIM_disable_breakpoint(break_num)

    def enableBreaks(self):
        #self.lgr.debug('readReplace enableBreaks')
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
        tid = self.top.getTID(target=self.cell_name)
        load_addr = self.so_map.getLoadAddr(replace_entry.lib, tid)
        self.lgr.debug('readReplace pagedIn load_addr 0x%x name %s linear 0x%x' % (load_addr, name, linear))
        phys = self.getPhys(replace_entry, load_addr, None)
        if phys is not None and phys != 0:
            self.setBreak(self.pending_pages[name], phys)
