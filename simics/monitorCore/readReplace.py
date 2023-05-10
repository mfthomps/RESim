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
    comm addr hexstring
Where "comm" is the process comm name; addr is the address; and hexstring
is a hexidecimal string that will be unhexified and written to the given
address the first time the address is read.

To handle snapshots, the module keeps a list of each comm/address pair
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

class ReadReplace():
    def __init__(self, top, cpu, cell_name, fname, lgr, snapshot=None):
        self.cpu = cpu
        self.cell_name = cell_name
        self.top = top
        self.lgr = lgr
        self.breakmap = {}
        self.done_list = []
        if not os.path.isfile(fname):
            self.lgr.error('ReadReplace: Could not find readReplace file %s' % fname)
            return
        if snapshot is not None:
            self.pickleLoad(snapshot)
        with open (fname) as fh:
            for line in fh:
                if line.strip().startswith('#'):
                    continue 
                parts = line.strip().split()
                if len(parts) != 3:
                    self.lgr.error('ReadReplace: Could not make sense of %s' % line)
                    return
                comm = parts[0]
                try:
                    addr = int(parts[1], 16)
                except:
                    self.lgr.error('ReadReplace: bad addr in %s' % line)
                    return
                ''' Set break unless comm/addr pair appears in the pickled list '''
                comm_addr = '%s:0x%x' % (comm, addr)
                if comm_addr not in self.done_list:
                    hexstring = parts[2]
                    self.addBreak(addr, comm, hexstring)
        self.lgr.debug('ReadReplace: set %d breaks' % len(self.breakmap))

    def addBreak(self, addr, comm, hexstring):
                breakpt = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Read, addr, 1, 0)
                self.lgr.debug('readReplace addBreak %d addr 0x%x context %s' % (breakpt, addr, self.cpu.current_context))
                hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.readHap, None, breakpt)
                self.breakmap[breakpt] = BreakRec(addr, comm, hexstring, hap)
         
    def readHap(self, dumb, context, break_num, memory):
        if break_num not in self.breakmap:
            self.lgr.error('ReadReplace syscallHap break %d not in breakmap' % break_num)
            return
        cpu, comm, pid = self.top.getCurrentProc(target_cpu=self.cpu) 
        if comm != self.breakmap[break_num].comm:
            self.lgr.debug('ReadReplace: syscallHap wrong process, expected %s got %s' % (self.breakmap[break_num].comm, comm))
        else:
            bstring = binascii.unhexlify(bytes(self.breakmap[break_num].hexstring.encode())) 
            self.lgr.debug('ReadReplace comm %s would write %s to 0x%x' % (comm, bstring, memory.logical_address)) 
            self.top.writeString(memory.logical_address, bstring, target_cpu=self.cpu)
            #SIM_break_simulation('remove me')
            done = '%s:0x%x' % (self.breakmap[break_num].comm, self.breakmap[break_num].addr)
            self.done_list.append(done) 
            SIM_run_alone(self.rmHap, break_num)

    def rmHap(self, break_num):
        if break_num in self.breakmap:
            RES_delete_breakpoint(break_num)
            RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.breakmap[break_num].hap)
            del self.breakmap[break_num]

    def swapContext(self):
        cpu, comm, pid = self.top.getCurrentProc(target_cpu=self.cpu) 
        swap_list = []
        for break_num in self.breakmap:
            if self.breakmap[break_num].comm == comm:
                swap_list.append(break_num)
        for break_num in swap_list:
            self.lgr.debug('readReplace swapContext for comm %s current context %s' % (self.breakmap[break_num].comm, self.cpu.current_context))
            self.addBreak(self.breakmap[break_num].addr, self.breakmap[break_num].comm, self.breakmap[break_num].hexstring)
            SIM_run_alone(self.rmHap, break_num)
             
    def pickleit(self, name):
        done_file = os.path.join('./', name, self.cell_name, 'read_replace.pickle')
        fd = open(done_file, "wb") 
        pickle.dump( self.done_list, fd)
        self.lgr.debug('ReadReplace done_list pickleit to %s ' % (done_file))

    def pickleLoad(self, name):
        done_file = os.path.join('./', name, self.cell_name, 'read_replace.pickle')
        if os.path.isfile(done_file):
            self.done_list = pickle.load( open(done_file, 'rb') ) 
