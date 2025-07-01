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
import resimUtils

class Jumpers():
    def __init__(self, top, context_manager, so_map, mem_utils, task_utils, cpu, lgr):
        self.top = top
        self.lgr = lgr
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.cell_name = self.top.getTopComponentName(cpu)
        self.context_manager = context_manager
        self.so_map = so_map
        self.fromto = {}
        self.comm_name = {}
        self.temp = []
        self.hap = {}
        self.breakpoints = {}
        self.reverse_enabled = None
        self.pending_libs = {}
        self.pending_pages = {}
        self.pending_progs = []
        #brute force avoid reloading if called twice 
        self.did_lines = []
        self.prev_dest_eip = None
        # Program jumpers waiting to be set once the program is scheduled
        self.prog_jumpers =  {}

    def removeOneBreak(self, lib_addr, immediate=False):
        self.lgr.debug('Jumpers removeOneBreak %s' % lib_addr)
        if lib_addr not in self.hap:
            self.lgr.debug('jumpers removeOneBreak but lib_addr %s not in dict.' % lib_addr)
            return
        SIM_delete_breakpoint(self.breakpoints[lib_addr])
        SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.hap[lib_addr])

    def removeBreaks(self, immediate=False):
        self.lgr.debug('Jumpers removeBreaks')
        for lib_addr in self.breakpoints:
            self.removeOneBreak(lib_addr, immediate=immediate)
        self.hap = {}
        self.breakpoints = {}

    def loadJumpers(self, fname_in):
        cpu, comm, tid = self.top.curThread(target_cpu=self.cpu)
        self.lgr.debug('jumpers loadJumpers fname_in: %s Current tid:%s (%s)' % (fname_in, tid, comm))
        if ';' in fname_in:
            fname_list = fname_in.split(';')
        else:
            fname_list = [fname_in]
        for fname in fname_list:
            if not os.path.isfile(fname):
                self.lgr.error('No jumper file found at %s' % fname)
            else:
                print('Loading jumpers from %s' % fname)
                self.lgr.debug('jumper loadJumpers Loading jumpers from %s' % fname)
                with open(fname) as fh:
                    for line in fh:
                        if line.strip().startswith('#'):
                            continue
                        if len(line.strip()) == 0:
                            continue
                        if ':' in line:
                            if not self.handleJumperEntry(line, fname):
                                self.lgr.error('Failed handling jumper entry %s' % line)
                                return
                        else:
                            self.lgr.error('jumpers loadJumper expected colon, e.g., lib:addr in %s' % line)
                            return


    def handleJumperEntry(self, line, fname):
        retval = True
        if line in self.did_lines:
            return retval
        self.did_lines.append(line)
        self.lgr.debug('jumpers handleJumperEntry %s %s' % (fname, line))
        parts = line.strip().split()
        if len(parts) < 2:
            self.lgr.error("jumpers Error reading %s from %s, bad jumper" % (line, fname))
            raise Exception("jumpers Error reading %s from %s, bad jumper" % (line, fname))
            return False
        if ':' not in line:
            raise Exception("jumpers Error reading %s from %s, bad jumper expected colon" % (line, fname))
            return False
        lib_addr = parts[0]
        prog = addr = to_addr = None
        try:
            prog, addr = lib_addr.split(':') 
        except:
            self.lgr.error("jumpers Error reading %s from %s, bad jumper, expected only one colon after prog" % (line, fname))
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
        break_at_load = False
        patch = False
        replace = False
        break_options = ['break', 'break_load']
        if '=' in line:
            for item in parts[2:]:
                key, value = resimUtils.getKeyValue(item)
                if key is None:
                    self.lgr.error('jumpers do not not what to do with %s in %s' (item, fname)) 
                    self.top.quit()
                if key == 'comm':
                    comm = value 
                elif key == 'patch': 
                     patch = resimUtils.yesNoTrueFalse(value)
                elif key == 'replace': 
                     replace = resimUtils.yesNoTrueFalse(value)
                elif key == 'break': 
                     break_at_dest = resimUtils.yesNoTrueFalse(value)
                elif key == 'break_load': 
                     break_at_load = resimUtils.yesNoTrueFalse(value)
        else: 
            # TBD incomplete, only here for backward compatability, use key/value
            if len(parts) == 3 and parts[2] == 'patch':
                patch = True
            elif len(parts) == 3 and parts[2] == 'replace':
                replace = True
            elif len(parts) == 3 and parts[2] in break_options:
                if parts[2] == 'break':
                    break_at_dest = True
                else:
                    break_at_load = True
            elif len(parts) > 2:
                comm = parts[2]
            if len(parts) > 3 and parts[3] in break_options:
                if parts[3] == 'break':
                    break_at_dest = True
                else:
                    break_at_load = True

        jump_rec = self.JumperRec(prog, comm, from_addr, to_addr, break_at_dest, break_at_load, patch, replace) 
        if resimUtils.isSO(prog):
            self.handleSO(jump_rec)
        else:
            prog_comm = self.task_utils.progComm(prog)
            handle = '%s:0x%x' % (prog_comm, from_addr)
            self.prog_jumpers[handle] = jump_rec
            self.handleProg(jump_rec=jump_rec)

        return True


    def handleProg(self, jump_rec):
        ''' Handle program jumpers.  May be called via a callback once program is scheduled, which may pass a string we do not want '''
        if jump_rec is not None and type(jump_rec) is str:
            jump_rec = None
        cpu, comm, tid = self.top.curThread(target_cpu=self.cpu)
        self.lgr.debug('jumper handleProg tid:%s (%s)' % (tid, comm))
        if jump_rec is None:
            # Via a callback indicating the program is now scheduled
            # process every jump_rec for this prog
            for handle in self.prog_jumpers:
                 if handle.startswith(comm+':'):
                     self.setProgJumpersIfMapped(self.prog_jumpers[handle])
            if comm in self.pending_progs:
                self.pending_progs.remove(comm)
        else:
            # Called from handleJumperEntry, if program not scheduled, use a callback
            prog_comm = self.task_utils.progComm(jump_rec.prog)
            if prog_comm != comm:
                if prog_comm not in self.pending_progs:
                    self.pending_progs.append(prog_comm)
                    self.lgr.debug('jumper handleProg prog %s not current running (%s is), set callback when scheduled' % (jump_rec.prog, comm))

                    tid_list = self.task_utils.getTidsForComm(prog_comm)
                    if len(tid_list) == 0:
                        self.lgr.debug('jumper handleProg prog %s not running, set callback first created' % (jump_rec.prog))
                        self.context_manager.callWhenFirstScheduled(prog_comm, self.handleProg)
                    else:
                        self.lgr.debug('jumper handleProg prog %s running, set callback for when next scheduled' % (jump_rec.prog))
                        self.context_manager.catchTid(tid_list[0], self.handleProg)
                else:
                    self.lgr.debug('jumper handleProg program %s already pending' % prog_comm)
            else:
                self.lgr.debug('jumper handleProg prog %s running, set prog jumper' % (jump_rec.prog))
                self.setProgJumpersIfMapped(jump_rec)

    def fixAddr(self, addr, prog): 
        retval = addr
        if self.cpu.architecture != 'ppc32':
            load_addr = self.so_map.getLoadAddr(jump_rec.prog)
            if load_addr is None:
                self.lgr.error('jumpers fixAddr load_addr is none for prog %s' % prog)
                return
            retval = addr + load_addr
        return retval

    def setProgJumpersIfMapped(self, jump_rec):
        ''' Assumes program is scheduled. Set program jumpers, unless from_addr is not yet mapped, in which case use a pageCallback. '''
        cpu, comm, tid = self.top.curThread(target_cpu=self.cpu)
        phys_addr = self.mem_utils.v2p(self.cpu, jump_rec.from_addr)
        if phys_addr is not None and phys_addr != 0:
            self.lgr.debug('jumpers setProgJumpersIfMapped, has phys addr, call setProgJumpers for %s' % jump_rec.prog)
            self.setProgJumpers(jump_rec.from_addr)
        else:
            self.lgr.debug('jumpers setProgJumpersIfMapped, NOT MAPPED, call pageCallback for %s addr: 0x%x' % (jump_rec.prog, jump_rec.from_addr))
            self.top.pageCallback(jump_rec.from_addr, self.setProgJumpers)

    def setProgJumpers(self, from_addr):
        ''' Set program jumpers assuming we are now running the program and the from_addr of the jump rec is mapped. 
            May have been via a callback
        '''
        cpu, comm, tid = self.top.curThread(target_cpu=self.cpu)
        self.lgr.debug('jumper setProgJumpers tid:%s (%s)' % (tid, comm))
        handle = '%s:0x%x' % (comm, from_addr)
        if handle not in self.prog_jumpers:
            self.lgr.error('jumpers setProgJumpers handle %s not in prog_jumpers' % handle)
            return
        jump_rec = self.prog_jumpers[handle]
        load_addr = self.so_map.getLoadAddr(jump_rec.prog)
        if load_addr is None:
            self.lgr.error('jumpers setProgJumpers load_addr is none for prog %s' % jump_rec.prog)
            return
        addr = self.fixAddr(jump_rec.from_addr, jump_rec.prog)
        if jump_rec.patch: 
            if self.top.isVxDKM(cpu=self.cpu):
                # TBD incomplete.  assumes program is scheduled?
                delta = jump_rec.to_addr - jump_rec.from_addr
                less_8 = delta - 8
                by_4 = int(less_8 / 4)
                instruct = 0xea000000 + by_4
                self.lgr.debug('jumper setProgJumpers delta %d by_4 %d addr 0x%x instruct 0x%x' % (delta, by_4, addr, instruct))
                self.top.writeWord(addr, instruct, target_cpu=self.cpu)
                print('patched address 0x%x with word 0x%x' % (addr, instruct))
                self.lgr.debug('jumpers setProgJumper patched address 0x%x with word 0x%x' % (addr, instruct))
            elif self.cpu.architecture == 'ppc32':
                delta = jump_rec.to_addr - jump_rec.from_addr
                instruct = 0x48000000 + delta
                self.top.writeWord(addr, instruct, target_cpu=self.cpu)
                print('patched address 0x%x with word 0x%x' % (addr, instruct))
                self.lgr.debug('jumper setProgJumper patched address 0x%x with word 0x%x' % (addr, instruct))
            else:
                self.lgr.error('jumper setProgJumper setProgJumpers, patch only supported on ppc32 and vxworks arm for now')
                self.top.quit()
                return 

        elif jump_rec.replace:
            self.lgr.debug('jumper setProgJumpers replace instruct at 0x%x with 0x%x' % (addr, jump_rec.to_addr))
            self.top.writeWord(addr, jump_rec.to_addr, target_cpu=self.cpu)
            print('replaced address 0x%x with word 0x%x' % (addr, jump_rec.to_addr))
            self.lgr.debug('jumper setProgJumper replaced address 0x%x with word 0x%x' % (addr, jump_rec.to_addr))
        else:
            phys = self.mem_utils.v2p(self.cpu, addr)
            if phys is not None and phys != 0:
                self.lgr.debug('jumper setProgJumper call setBreak for %s on phys 0x%x' % (jump_rec.prog, phys))
                self.setBreak(jump_rec, phys)
            else:
                self.lgr.error('jumper failed to get phys for addr 0x%x' % addr)


    def handleSO(self, jump_rec):
        image_base = self.so_map.getImageBase(jump_rec.prog)
        if image_base is None:
            # No process has loaded this image.  Set a callback for each load of the library
            self.lgr.debug('jumper handleJumperEntry no process has image loaded, set SO watch callback for %s prog %s' % (jump_rec.lib_addr, jump_rec.prog))
            self.so_map.addSOWatch(jump_rec.prog, self.libLoadCallback, name=jump_rec.lib_addr)
            self.pending_libs[jump_rec.lib_addr] = jump_rec
        elif self.top.isVxDKM(cpu=self.cpu):
            jump_rec.image_base = image_base
            load_addr = self.so_map.getLoadAddr(jump_rec.prog)
            addr = jump_rec.from_addr + load_addr
            self.lgr.debug('jumper handleJumperEntry vxworks set break on 0x%x' % addr)
            self.setBreak(jump_rec, addr)
        else:
            # Library loaded by someone.  Get list of pids
            jump_rec.image_base = image_base
            loaded_pids = self.so_map.getSOPidList(jump_rec.prog)
            if len(loaded_pids) == 0:
                self.lgr.error('jumper handleJumperEntry not at least one pid for %s' % jump_rec.prog)
                return
            self.lgr.debug('jumper handleJumperEntry %d pids with lib loaded, image_base 0x%x' % (len(loaded_pids), image_base))
            phys = None
            # a bit of hackery to avoid looking up another process's page table if threads of same process.
            # can remove after all params include the page table info (mm_struct)
            tid = self.top.getTID(target=self.cell_name)
            tid = self.so_map.getSOTid(tid)
            for so_pid in loaded_pids:
                if str(so_pid) == tid:
                    use_pid = None
                else:
                    use_pid = str(so_pid)
                load_addr = self.so_map.getLoadAddr(jump_rec.prog, tid=use_pid)
                if load_addr is not None:
                    self.lgr.debug('jumper handleJumperEntrys pid:%s lib_addr %s load addr 0x%x, call getPhys' % (use_pid, jump_rec.lib_addr, load_addr))
                    phys = self.getPhys(jump_rec, load_addr, use_pid)
                    if phys is not None and phys != 0:
                        self.setBreak(jump_rec, phys)
        return True

    def libLoadCallback(self, load_addr, lib_addr):
        # called when a jumpered library is loaded
        self.lgr.debug('jumper libLoadCallback for %s load_addr 0x%x' % (lib_addr, load_addr))
        if lib_addr in self.pending_libs:
            jump_rec = self.pending_libs[lib_addr]
            if jump_rec.image_base is None:
                jump_rec.image_base = self.so_map.getImageBase(jump_rec.prog)
            tid = self.top.getTID(target=self.cell_name)
            phys = self.getPhys(jump_rec, load_addr, tid)
            if phys is not None and phys != 0:
                self.setBreak(jump_rec, phys)
            else:
                offset = load_addr - jump_rec.image_base
                linear = jump_rec.from_addr + offset
                self.lgr.debug('jumper libLoadCallback for load_addr 0x%x image_base 0x%x offset 0x%x linear 0x%x name %s' % (load_addr, jump_rec.image_base, offset, linear, jump_rec.lib_addr))
            if jump_rec.break_at_load:
                SIM_break_simulation('Jumper DLL loaded %s' % lib_addr)
        else:
            self.lgr.error('jumper libLoadCallback for %s, but not in pending_libs' % lib_addr)

    def pagedIn(self, linear, name):
        if name not in self.pending_pages:
            self.lgr.error('jumper pagedIn name %s not in pending_pages' % name)
            return
        jump_rec = self.pending_pages[name]
        cpu, comm, tid = self.top.curThread(target_cpu=self.cpu)
        self.lgr.error('jumper paged in prog %s tid:%s (%s) name: %s' % (jump_rec.prog, tid, comm, name))
        load_addr = self.so_map.getLoadAddr(jump_rec.prog, tid=tid)
        if load_addr is None:
            self.lgr.error('jumper paged_in load_addr None for prog %s handle %s' % (jump_rec.prog, name))
        else:
            self.lgr.debug('jumper paged_in load_addr 0x%x name %s linear 0x%x' % (load_addr, name, linear))
            phys = self.getPhys(jump_rec, load_addr, None)
            if phys is not None and phys != 0:
                self.setBreak(self.pending_pages[name], phys)

    def getPhys(self, jump_rec, load_addr, pid):
        if jump_rec.image_base is not None:
            offset = load_addr - jump_rec.image_base
        else:
            offset = 0
        linear = jump_rec.from_addr + offset
        phys_addr = self.mem_utils.v2p(self.cpu, linear, use_pid=pid)
        if jump_rec.image_base is not None:
            self.lgr.debug('jumper getPhys load_addr 0x%x image_base 0x%x offset 0x%x, linear 0x%x pid:%s' % (load_addr, jump_rec.image_base, offset, linear, pid))
        else:
            self.lgr.debug('jumper getPhys load_addr 0x%x no image base  offset 0x%x, linear 0x%x pid:%s' % (load_addr, offset, linear, pid))
        #if phys_addr is not None:
        #    # Cancel callbacks
        #    self.so_map.cancelSOWatch(jump_rec.prog, jump_rec.lib_addr)
        if phys_addr is None or phys_addr == 0:
            self.lgr.debug('jumper getPhys no phys for above, call pageCallback')
            self.top.pageCallback(linear, self.pagedIn, name=jump_rec.lib_addr, use_pid=pid)
            self.pending_pages[jump_rec.lib_addr] = jump_rec
        return phys_addr

    def setBreak(self, jump_rec, phys_addr):
        self.lgr.debug('jumper setBreak phys_addr 0x%x for %s' % (phys_addr, jump_rec.lib_addr))
        self.breakpoints[jump_rec.lib_addr] = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_addr, 1, 0)
        self.hap[jump_rec.lib_addr] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.doJump, jump_rec, self.breakpoints[jump_rec.lib_addr])

    def doJump(self, jump_rec, an_object, break_num, memory):
        #print('doJump')
        eip = self.top.getReg('pc', self.cpu)
        if eip == self.prev_dest_eip:
            # break is hit a 2nd time?
            return
        self.lgr.debug('doJump phys memory 0x%x cycle: 0x%x' % (memory.physical_address, self.cpu.cycles))
        ''' callback when jumper breakpoint is hit'''
        #curr_addr = memory.logical_address 
        cpu, comm, tid = self.top.curThread(target_cpu=self.cpu)
        self.lgr.debug('jumper doJump tid: %s lib_addr %s current_context (not that it affects this phys break) is %s cycle: 0x%x' % (tid, jump_rec.lib_addr, self.cpu.current_context, self.cpu.cycles))
        if jump_rec.lib_addr not in self.hap:
            self.lgr.debug('jumper doJump lib_addr %s not in haps' % jump_rec.lib_addr)
            return
        if jump_rec.comm is not None:
            if comm != jump_rec.comm:
                self.lgr.debug('doJump comm %s does not match jumper comm of %s' % (comm, jump_rec.comm))
                return
        if self.reverse_enabled is None:
            self.reverse_enabled = self.top.reverseEnabled()
            self.lgr.debug('jumpers doJump setting reverse_enabled to %r' % self.reverse_enabled)

        load_addr = self.so_map.getLoadAddr(jump_rec.prog, tid=tid)
        if load_addr is None:
            # Likely a true shared dll (same phys addr) but this process has no so map
            self.lgr.debug('jumper doJump failed to get load_addr for %s in tid:%s (%s)' % (jump_rec.prog, tid, comm))
            # TBD always do this instead of getting load_addr? 
            delta = jump_rec.to_addr - jump_rec.from_addr
            source = eip
            destination = eip + delta
        else:
            destination = self.fixAddr(jump_rec.to_addr, jump_rec.prog)
            source = self.fixAddr(jump_rec.from_addr, jump_rec.prog)
            #offset = load_addr - jump_rec.image_base
            #destination = jump_rec.to_addr + offset
            #source = jump_rec.from_addr + offset

        self.top.writeRegValue('pc', destination, alone=True, target_cpu=self.cpu)
        self.lgr.debug('jumper doJump wrote 0x%x to pc' % (destination))
        self.lgr.debug('jumper doJump from 0x%x to 0x%x in comm %s' % (source, destination, comm))
        self.prev_dest_eip = self.top.getReg('pc', self.cpu)
        if jump_rec.break_at_dest:
            SIM_break_simulation('Jumper request')
            self.lgr.debug('jumper doJump did break_simulation')
        self.lgr.debug('jumper doJump did it, eip now 0x%x' % self.prev_dest_eip)

    def disableBreaks(self):
        self.lgr.debug('Jumpers disableBreaks')
        for lib_addr in self.breakpoints:
            SIM_disable_breakpoint(self.breakpoints[lib_addr])
 
    def enableBreaks(self):
        self.lgr.debug('Jumpers enableBreaks')
        for lib_addr in self.breakpoints:
            SIM_enable_breakpoint(self.breakpoints[lib_addr])
 
    class JumperRec():
        def __init__(self, prog, comm, from_addr, to_addr, break_at_dest, break_at_load, patch, replace):
            self.prog = prog
            self.from_addr = from_addr
            self.to_addr = to_addr
            self.comm = comm
            self.break_at_dest = break_at_dest
            self.break_at_load = break_at_load
            self.patch = patch
            self.replace = replace
            self.lib_addr = '%s:0x%x' % (prog, from_addr)
            self.image_base = None
