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
import memUtils
import decode
import procInfo
import time
'''
    Catch the kernel writing to a memory breakpoint and bring the eip to the return from the syscall.
    If the memory is written by user space, stop there.
'''
class findKernelWrite():
    def __init__(self, top, cpu, addr, os_utils, os_p_utils, context_manager, param, bookmarks, lgr, rev_to_call=None, num_bytes = 1):
        self.stop_write_hap = None
        self.os_p_utils = os_p_utils
        self.os_utils = os_utils
        self.lgr = lgr
        self.top = top
        self.param = param
        self.context_manager = context_manager
        self.cpu = cpu
        self.start_cycle = cpu.cycles
        self.found_kernel_write = False
        self.rev_to_call = rev_to_call
        self.addr = addr
        self.num_bytes = num_bytes
        self.bookmarks = bookmarks
        self.mem_hap = None
        self.forward = False
        self.forward_break = None
        self.forward_eip = None
        #if top.isProtectedMemory(addr):
        #    self.lgr.debug('findKernelWrite refuses to find who wrote to magic page')
        #    self.context_manager.setIdaMessage('findKernelWrite refuses to find who wrote to magic page')
        #    
        #    self.top.skipAndMail()
        #    return
        dum_cpu, cur_addr, comm, pid = self.os_utils.currentProcessInfo(cpu)
        my_args = procInfo.procInfo(comm, cpu, pid, None, False)
        phys_block = cpu.iface.processor_info.logical_to_physical(addr, Sim_Access_Write)
        if phys_block.address == 0:
            self.lgr.error('findKernelWrite requested address %x, not mapped?' % addr)
            return
        if num_bytes > 1:
            value = self.os_p_utils.getMemUtils().readWord32(self.cpu, self.addr)
        else:
            value = self.os_p_utils.getMemUtils().readByte(self.cpu, self.addr)
        self.value = value
        self.lgr.debug( 'findKernelWrite of 0x%x to addr %x, phys %x num_bytes: %d' % (value, addr, phys_block.address, num_bytes))
        cell = cpu.physical_memory
        self.kernel_write_break = SIM_breakpoint(cell, Sim_Break_Physical, Sim_Access_Write, 
            phys_block.address, num_bytes, 0)

        ''' limit how far forward we run if trying to find bp simics misses going back '''
        #self.forward_eip = self.top.getEIP(self.cpu)
        #forward_phys_block = cpu.iface.processor_info.logical_to_physical(self.forward_eip, Sim_Access_Write)
        #if forward_phys_block.address != 0:
        #    self.forward_break = SIM_breakpoint(cell, Sim_Break_Physical, Sim_Access_Write, 
        #        forward_phys_block.address, num_bytes, 0)
        #else:
        #    self.lgr.debug('not setting forward_break, %x not mapped' % self.forward_eip)

        #### Make a stop hap.  Note you cannot reliably create a breakpoint hap for running backwards,
        #### because it gets hit an undefined number of times.
        SIM_run_alone(self.addStopHapForWriteAlone, my_args)
        #self.lgr.debug( 'breakpoint is %d, done now return from findKernelWrite, set forward break %d at 0x%x (0x%x)' % (self.kernel_write_break, self.forward_break, self.forward_eip, forward_phys_block.address))
        self.lgr.debug( 'breakpoint is %d, done now return from findKernelWrite)' % (self.kernel_write_break))
        #SIM_run_alone(SIM_run_command, 'reverse')

    def addStopHapForWriteAlone(self, my_args):
        self.stop_write_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
		    self.stopToCheckWriteCallback, my_args)
        SIM_run_command('reverse')


    def writeCallback(self, cell_name, third, forth, memory):
        location = memory.logical_address
        physical = memory.physical_address
        if location is 0 and physical is 0:
           self.lgr.debug('findKernelWrite writeCallback, location zero?')
           ''' recursive callback triggered by this Hap '''
           return
        length = memory.size
        op_type = SIM_get_mem_op_type(memory)
        type_name = SIM_get_mem_op_type_name(op_type)
        self.lgr.debug('writeCallback location 0x%x phys 0x%x len %d  type %s' % (location, physical, length, type_name))

        self.lgr.debug('writeCallback')
        self.thinkWeWrote()

    def stopToCheckWriteCallback(self, my_args, one, exception, error_string):
        self.lgr.debug('stopToCheckWriteCallback, params %s %s %s' % (one, exception, error_string))
        eip = self.top.getEIP(self.cpu)
        if self.forward is not None and eip == self.forward_eip:
            self.lgr.error('stopToCheckWriteCallback going forward hit our original eip')
            if self.stop_write_hap is not None:
                SIM_delete_breakpoint(self.kernel_write_break)
                self.stop_write_hap = None
            if self.forward_break is not None:
                SIM_delete_breakpoint(self.forward_break)
                self.forward_break = None
            return
         
        self.thinkWeWrote()

    def checkWriteValue(self, eip):
        retval = True
        if self.num_bytes > 1:
            value = self.os_p_utils.getMemUtils().readWord32(self.cpu, self.addr)
        else:
            value = self.os_p_utils.getMemUtils().readByte(self.cpu, self.addr)
        if value != self.value:

            if eip == self.bookmarks.getEIP('_start+1'):
                self.lgr.debug('checkWriteValue, We are near _start+1 desired value came from loader?')
                return True
            self.lgr.error('Simics reverse error, thought we wrote 0x%x, but value is 0x%x  skip forward until correct write' % (self.value, value))
            #return value 
            #!!!!!!!!!!!!!!!!!!!
            ''' do not clean up breakpoint, associate a hap with it and run forward '''
            
            if not self.forward:
                self.mem_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.writeCallback, self.cpu, self.kernel_write_break)
                self.forward = True
                if self.stop_write_hap is not None:
                    SIM_delete_breakpoint(self.kernel_write_break)
                    self.stop_write_hap = None
                
            status = SIM_simics_is_running()
            if not status: 
                if self.forward_break is not None:
                    SIM_run_alone(SIM_run_command, 'continue')
                else:
                    self.lgr.error('checkWriteValue refuse to run forward without a forward_break')
                    return
            else:
                self.lgr.error('checkWriteValue found simics to be running, should be invoked as part of a stop hap????')
            retval = False          
        return retval
        
    ''' We stopped, presumably because target address was written.  If in the kernel, set break on return
        address and continue to user space.
    '''
    def thinkWeWrote(self):
        #if self.stop_write_hap is None:
        #    return
        reg_num = self.cpu.iface.int_register.get_number("eip")
        eip = self.cpu.iface.int_register.read(reg_num)
        cycle = self.cpu.cycles
        cpl = memUtils.getCPL(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug( 'in thinkWeWrote, cycle %x eip: %x  %s cpl: %d' % (cycle, eip, str(instruct), cpl))
        if cpl == 0:
            if self.found_kernel_write:
                self.lgr.debug('stopToCheckWriteCallback found second write?  but we deleted the breakpoint!!!! ignore this and reverse')
                #SIM_run_alone(SIM_run_command, 'reverse')
                return
            cpu, cur_addr, comm, pid = self.os_utils.currentProcessInfo(self.cpu)
            ''' get return address '''
            frame = self.os_utils.frameFromThread(self.cpu)
            eip = frame['eip']
            self.found_kernel_write = True
            if self.kernel_write_break is not None:
                self.lgr.debug('deleting breakpoint %d' % self.kernel_write_break)
                SIM_delete_breakpoint(self.kernel_write_break)
                self.kernel_write_break = None
            phys_block = cpu.iface.processor_info.logical_to_physical(eip, Sim_Access_Write)
            if phys_block.address == 0:
                self.lgr.debug('thinkWeWrote, cannot get physical address of %x, in %d (%s)' % (eip, pid, comm))
                return
            self.lgr.debug( 'thinkWeWrote set break for addr %x, phys %x and reverse' % (eip, phys_block.address))
            cell = cpu.physical_memory
            self.kernel_write_break = SIM_breakpoint(cell, Sim_Break_Physical, Sim_Access_Execute, 
                phys_block.address, 1, 0)
            # continue to after the syscall
            SIM_run_alone(SIM_run_command, 'continue')
             
        elif self.found_kernel_write:
            self.lgr.debug('thinkWeWrote, BACKTRACK user space address 0x%x after finding kernel write to  0x%x' % (eip, self.addr))
            if not self.checkWriteValue(eip):
                return

            value = self.os_p_utils.getMemUtils().readWord32(self.cpu, self.addr)
            eip = self.top.getEIP(self.cpu)
            if eip == self.bookmarks.getEIP('_start+1'):
                ida_message = "Content of 0x%x existed pror to _start+1, perhaps from loader." % self.addr
                bm = None
            else:
                ida_message = 'Kernel wrote 0x%x to address: 0x%x' % (value, self.addr)
                self.lgr.debug('set ida msg to %s' % ida_message)
                bm = "backtrack eip:0x%x follows kernel write of value:0x%x to memory:0x%x" % (eip, value, self.addr)
            if bm is not None:
                self.bookmarks.setDebugBookmark(bm)
            self.context_manager.setIdaMessage(ida_message)
            SIM_run_alone(self.cleanup, False)
            self.top.skipAndMail()
            #previous = SIM_cycle_count(my_args.cpu) - 1
            #SIM_run_alone(SIM_run_command, 'skip-to cycle=%d' % previous)
            #eip = self.top.getEIP()
            #msg = '0x%x' % eip
            #self.top.gdbMailbox(msg)
            
            self.context_manager.setExitBreak(self.cpu)
             
        else:
            if not self.checkWriteValue(eip):
                return
            eip = self.top.getEIP(self.cpu)
            SIM_run_alone(self.cleanup, False)
            if eip == self.bookmarks.getEIP('_start+1'):
                ida_message = "Content of %s came from loader." % self.addr
                bm = "backtrack eip:0x%x content of memory:%s came from loader" % (eip, self.addr)
                self.bookmarks.setDebugBookmark(bm)
                self.context_manager.setIdaMessage(ida_message)
                SIM_run_alone(self.cleanup, False)
                self.top.skipAndMail()
                
            elif self.rev_to_call is None:
                # reverse two so we land on the instruction that does the write (after client steps forward 1)
                self.lgr.debug( 'thinkWeWrote eip is %x in user space,  stop here and reverse 2  : may break if page fault?' % eip)
                self.top.skipAndMail(cycles=2)
            else:
                SIM_run_alone(self.backOneAlone, None)
            #self.top.skipAndMail()
            #previous = SIM_cycle_count(my_args.cpu) - 1
            #SIM_run_alone(SIM_run_command, 'skip-to cycle=%d' % previous)
            #eip = self.top.getEIP()
            #msg = '0x%x' % eip
            #self.top.gdbMailbox(msg)
            
            self.context_manager.setExitBreak(self.cpu)

    def backOneAlone(self, dum):
        current = SIM_cycle_count(self.cpu)
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        value = self.os_p_utils.getMemUtils().readWord32(self.cpu, self.addr)
        self.lgr.debug('backOne user space write of 0x%x to addr 0x%x cycle/eip after write is 0x%x  eip:0x%x ' % (value, self.addr, current, eip))
        if not self.forward:
            previous = current - 1
            SIM_run_command('pselect cpu-name = %s' % self.cpu.name)
            if SIM_simics_is_running():
                self.lgr.error('backOneAlone, simics is still running, is this not part of a stop hap???')
                return
            SIM_run_command('skip-to cycle=%d' % previous)
            new = SIM_cycle_count(self.cpu) 
            self.lgr.debug('backOne back to 0x%x got 0x%x' % (previous, new))
        else:
            self.lgr.debug('backOneAlone, was going forward')
        if self.forward_break is not None:
            self.lgr.debug('backOne alone delete forward_break')
            SIM_delete_breakpoint(self.forward_break)
            self.forward_break = None
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        mn = decode.getMn(instruct[1])
        self.lgr.debug('stopToCheckWriteCallback BACKTRACK backOneAlone, write described above occured at 0x%x : %s' % (eip, str(instruct[1])))
        bm = 'backtrack eip:0x%x inst:"%s"' % (eip, instruct[1])
        self.bookmarks.setDebugBookmark(bm)
        self.lgr.debug('BT bookmark: %s' % bm)
        if decode.modifiesOp0(mn):
            self.lgr.debug('stopToCheckWriteCallback get operands from %s' % instruct[1])
            op1, op0 = decode.getOperands(instruct[1])
            actual_addr = decode.getAddressFromOperand(self.cpu, op0, self.lgr)
            if actual_addr is None:
                self.lgr.error('failed to get op0 address from %s' % instruct[1])
                return
            offset = self.addr - actual_addr
            self.lgr.debug('stopToCheckWriteCallback cycleRegisterMod mn: %s op0: %s  op1: %s actual_addr 0x%x orig 0x%x address offset is %d' % (mn, 
                 op0, op1, actual_addr, self.addr, offset))
            if decode.isIndirect(op1):
                reg_num = self.cpu.iface.int_register.get_number(op1)
                address = self.cpu.iface.int_register.read(reg_num)
                new_address = address+offset
                #if not self.top.isProtectedMemory(new_address):
                if not self.top.isProtectedMemory(new_address) and not '[' in op0:
                    self.lgr.debug('stopToCheckWriteCallback, %s is indirect, check for write to 0x%x' % (op1, new_address))
                    self.top.stopAtKernelWrite(new_address, self.rev_to_call)
                else:
                    self.lgr.debug('stopToCheckWriteCallback is indirect reg point to magic page, or move to memory, find mod of the reg vice the address content')
                    self.rev_to_call.doRevToModReg(op1, taint=True, offset=offset)
 
            elif decode.isReg(op1):
                self.lgr.debug('stopToCheckWriteCallback is reg, find mod')
                self.rev_to_call.doRevToModReg(op1, taint=True, offset=offset)
            else:
                value = None
                try:
                   value = int(op1,16)
                except:
                   pass
                if value is not None:
                    if self.top.isProtectedMemory(value):
                        self.lgr.debug('stopToCheckWriteCallback, found protected memory %x ' % value)
                        SIM_run_alone(self.cleanup, False)
                        self.top.skipAndMail()
                    else:
                        ''' stumped, constant loaded into memory '''
                        self.lgr.debug('stopToCheckWriteCallback, found constant %x, stumped' % value)
                        SIM_run_alone(self.cleanup, False)
                        self.top.skipAndMail()
                     
                   
        elif mn == 'push':
            op1, op0 = decode.getOperands(instruct[1])
            self.lgr.debug('stopToCheckWriteCallback is push reg %s, find mod', op0)
            self.rev_to_call.doRevToModReg(op0, taint=True)

        else:
            self.lgr.debug('backOneAlone, cannot track values back beyond %s' % str(instruct))
            SIM_run_alone(self.cleanup, False)
            self.top.skipAndMail()

    def cleanup(self, rm_break = False):
        self.found_kernel_write = False
        if self.kernel_write_break is not None:
            self.lgr.debug('deleting hap and breakpoint %d' % self.kernel_write_break)
            SIM_delete_breakpoint(self.kernel_write_break)
        if self.stop_write_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_write_hap)
            self.kernel_write_break = None
            self.stop_write_hap = None
        if self.mem_hap is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.mem_hap)
            self.mem_hap = None
        if self.forward_break is not None:
            self.lgr.debug('cleanup delete forward break')
            SIM_delete_breakpoint(self.forward_break)
            self.forward_break = None

                

