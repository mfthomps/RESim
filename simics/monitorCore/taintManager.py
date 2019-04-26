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

import simics
from simics import *
import hapManager
import debugInfo
import startDebugging2
'''
   NOT USED, would require a lot of work and execution time for even crude taint analysis.
'''
class taintManager():
    tainted_memory = []
    tainted_regs = []
    PAINTING = 0 
    WATCHING = 1
    taint_mode = PAINTING
    def __init__(self, top, master_config, context_manager, hap_manager, os_utils, param, lgr):
        self.lgr = lgr
        self.context_manager = context_manager
        self.hap_manager = hap_manager
        self.top = top
        self.master_config = master_config
        self.os_utils = os_utils
        self.param = param

    class taintInfo():
        def __init__(self, start, length):
            self.start = start
            self.length = length

    def watchTaint(self):
        self.taint_mode = self.WATCHING

    def didRead(self, cpu, cell_name, pid, comm, orig_start, orig_length):
        if self.taint_mode == self.PAINTING:
            self.didReadTainting(cpu, cell_name, pid, comm, orig_start, orig_length)
        else:
            self.didReadWatching(cpu, cell_name, pid, comm, orig_start, orig_length)

    def didWrite(self, cpu, cell_name, pid, comm, orig_start, orig_length):
        if self.taint_mode != self.WATCHING:
            return
        self.lgr.debug('taintManager, didWrite for %s:%d (%s), start: %x, length %d' % (cell_name, pid, comm, 
            orig_start, orig_length))
        the_bytes = self.top.getBytes(cpu, orig_length, orig_start)
        if self.master_config.taint_bytes in the_bytes:
            self.lgr.debug('string of len %d is: %s' % (len(the_bytes), the_bytes))
            index = the_bytes.find(self.master_config.taint_bytes)
            found_at = orig_start + index/2
            self.lgr.debug('got taint bytes %s at address %x index was %d' % (self.master_config.taint_bytes, 
                found_at, index))
            self.context_manager.setIdaMessage('Found taint bytes <%s> at %x' % (self.master_config.taint_bytes, found_at))
            print('got taint bytes %s at address %x' % (self.master_config.taint_bytes, found_at))
            
            frame = self.os_utils.frameFromThread(self.param, cpu)
            
            phys_block = cpu.iface.processor_info.logical_to_physical(frame['eip'], Sim_Access_Read)
            cell = cpu.physical_memory
            
            break_num = SIM_breakpoint(cell, Sim_Break_Physical, Sim_Access_Execute, 
                phys_block.address, 1, 0)
            cmd = None
            cell_name = self.top.getTopComponentName(cpu)
            dbi = debugInfo.debugInfo(self.context_manager, self.hap_manager, 
                    pid, comm, cmd, None, None, 
                    'dum cb', 'dum pov', cell_name, cpu, None, None, self.lgr)
            self.top.cleanupAll()
            dbi.del_breakpoint = break_num
            startDebugging2.startDebugging2(dbi)
            #SIM_break_simulation('stopping in trackSetup for CB debugging')
            
    ''' intended to be called on a sysread while tainting memory, mark the given memory area as tainted. '''
    def didReadTainting(self, cpu, cell_name, pid, comm, orig_start, orig_length):
        self.lgr.debug('taintManager, didReadTainting for %s:%d (%s), start: %x, length %d' % (cell_name, pid, comm, 
            orig_start, orig_length))
        end = orig_start + orig_length
        mod = orig_start % self.top.PAGE_SIZE
        length = self.top.PAGE_SIZE - mod
        ''' limit is the start of the next page '''
        limit = orig_start + length
        start = orig_start
         
        while end >= limit:
            self.hap_manager.add(cpu, cell_name, pid, start, length, Sim_Access_Read, self.readCallback,
               hapManager.TAINT_PAGE)
            
            # TBD write here may remove from taint
            #self.hap_manager.add(cpu, cell_name, pid, start, length, Sim_Access_Write, self.write_callback)
            start = limit
            limit = start + self.top.PAGE_SIZE
            length = self.top.PAGE_SIZE
 
        if end > start:
            length = end - start
            self.hap_manager.add(cpu, cell_name, pid, start, length, Sim_Access_Read, self.readCallback, 
                hapManager.TAINT_PAGE)
            #self.hap_manager.add(cpu, cell_name, pid, start, length, Sim_Access_Write, self.write_callback)

    ''' intended to be called on a sysread while watching for access to tainted memory, remove taint from given memory'''
    def didReadWatching(self, cpu, cell_name, pid, comm, orig_start, orig_length):
        self.lgr.debug('taintManager, didReadWatching for %s:%d (%s), start: %x, length %d' % (cell_name, pid, comm, 
            orig_start, orig_length))
        end = orig_start + orig_length
        mod = orig_start % self.top.PAGE_SIZE
        length = self.top.PAGE_SIZE - mod
        ''' limit is the start of the next page '''
        limit = orig_start + length
        start = orig_start
         
        while end >= limit:
            self.hap_manager.rm(cell_name, pid, start, hapManager.TAINT_PAGE)
            start = limit
            limit = start + self.top.PAGE_SIZE
            length = self.top.PAGE_SIZE
 
        if end > start:
            self.hap_manager.rm(cell_name, pid, start, hapManager.TAINT_PAGE)

    def readCallback(self, my_args, third, forth, memory):
            location = memory.logical_address
            if location is 0:
               ''' recursive callback triggered by this Hap '''
               return
            physical = memory.physical_address
            length = memory.size
            op_type = SIM_get_mem_op_type(memory)
            reg_num = my_args.cpu.iface.int_register.get_number("eip")
            eip = my_args.cpu.iface.int_register.read(reg_num)
            type_name = SIM_get_mem_op_type_name(op_type)
            instruct = SIM_disassemble_address(my_args.cpu, eip, 1, 0)
            value = 0xDEADBEEF
            if length <= 8:
                if op_type is Sim_Trans_Store:
                    value = SIM_get_mem_op_value_le(memory)
                else:
                    value = int(self.top.getBytes(my_args.cpu, length, location), 16)
            else:
                self.lgr.info('Following entry for memory operation > 8 bytes, IGNORE VALUE')

            self.lgr.debug('read callback from eip: %x, %d  %s address %x (phys %x)  (%d bytes) value: %x' % (eip, 
                my_args.pid, type_name, location, physical, length, value))
            self.lgr.debug('    instruct: %s ' % instruct[1])
            if instruct[1].startswith('movsd'):
                cell_name = self.top.getTopComponentName(my_args.cpu)
                reg_num = my_args.cpu.iface.int_register.get_number("edi")
                edi = my_args.cpu.iface.int_register.read(reg_num)
                self.hap_manager.add(my_args.cpu, cell_name, my_args.pid, edi, 4, Sim_Access_Read, self.readCallback,
                    hapManager.TAINT_PAGE)
                
                

    def write_callback(self, my_args, third, forth, memory):
            location = memory.logical_address
            if location is 0:
               ''' recursive callback triggered by this Hap '''
               return
            physical = memory.physical_address
            length = memory.size
            op_type = SIM_get_mem_op_type(memory)
            reg_num = my_args.cpu.iface.int_register.get_number("eip")
            eip = my_args.cpu.iface.int_register.read(reg_num)
            type_name = SIM_get_mem_op_type_name(op_type)
            value = 0xDEADBEEF
            if length <= 8:
                if op_type is Sim_Trans_Store:
                    value = SIM_get_mem_op_value_le(memory)
                else:
                    #value = int(self.top.get_bytes_phys(my_args.cpu, length, physical), 16)
                    value = int(self.top.get_bytes(my_args.cpu, length, location), 16)
            else:
                self.lgr.info('Following entry for memory operation > 8 bytes, IGNORE VALUE')

            self.lgr.info('write callback from eip: %x, %d %s address %x (phys %x)  (%d bytes) value: %x' % (eip, my_args.pid, type_name, location, physical, length, value))
