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
import decodeArm
import procInfo
import time
'''
    Catch the kernel writing to a memory breakpoint and bring the eip to the return from the syscall.
    If the memory is written by user space, stop there.
'''
class findKernelWrite():
    def __init__(self, top, cpu, cell, addr, task_utils, mem_utils, context_manager, param, 
                 bookmarks, dataWatch, lgr, rev_to_call=None, num_bytes = 1, satisfy_value=None):
        self.stop_write_hap = None
        self.task_utils = task_utils
        self.mem_utils = mem_utils
        self.lgr = lgr
        self.top = top
        self.param = param
        self.context_manager = context_manager
        self.dataWatch = dataWatch
        self.cpu = cpu
        self.found_kernel_write = False
        self.rev_to_call = rev_to_call
        self.addr = addr
        self.num_bytes = num_bytes
        self.bookmarks = bookmarks
        self.mem_hap = None
        self.forward = False
        self.forward_break = None
        self.forward_eip = None
        self.kernel_exit_break1 = None
        self.kernel_exit_break2 = None
        self.exit_hap = None
        self.exit_hap2 = None
        self.stop_exit_hap = None
        self.forward_hap = None
        self.cell = cell
        self.satisfy_value = satisfy_value
        self.memory_transaction = None
        self.rev_write_hap = None

        ''' handle case where address is in the initial data watch buffer, but only if that is
            not a true kernel write '''
        range_index = self.dataWatch.findRangeIndex(addr)
        if range_index == 0:
            ''' Is initial data watch buffer.'''
            self.lgr.debug('findKernelWrite, addr 0x%x in initial dataWatch range')
            if rev_to_call is None:
                self.lgr.debug('findKernelWrite, rev_to_call is None')
            else:
                self.dataWatch.goToMark(0)
    
                if satisfy_value is not None:
                    self.top.restoreDebugBreaks()
                    self.top.writeByte(addr, satisfy_value)
                    self.top.retrack()
                else:
                    self.top.skipAndMail()
                return
        if cpu.architecture == 'arm':
            self.decode = decodeArm
            self.lgr.debug('findKernelWrite using arm decoder')
        else:
            self.decode = decode
        #if top.isProtectedMemory(addr):
        #    self.lgr.debug('findKernelWrite refuses to find who wrote to magic page')
        #    self.context_manager.setIdaMessage('findKernelWrite refuses to find who wrote to magic page')
        #    
        #    self.top.skipAndMail()
        #    return
        dumb, comm, pid = self.task_utils.curProc() 
        my_args = procInfo.procInfo(comm, self.cpu, pid, None, False)
        phys_block = self.cpu.iface.processor_info.logical_to_physical(addr, Sim_Access_Write)
        if phys_block.address == 0:
            self.lgr.error('findKernelWrite requested address %x, not mapped?' % addr)
            return
        ''' TBD support byte, word, dword '''
        if num_bytes > 1:
            value = self.mem_utils.readWord32(self.cpu, self.addr)
        else:
            value = self.mem_utils.readByte(self.cpu, self.addr)
        self.value = value
        dumb, comm, pid = self.task_utils.curProc() 
        self.lgr.debug( 'findKernelWrite pid:%d of 0x%x to addr %x, phys %x num_bytes: %d' % (pid, value, addr, phys_block.address, num_bytes))
        pcell = self.cpu.physical_memory
        self.kernel_write_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, 
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
        #SIM_run_alone(self.addStopHapForWriteAlone, my_args)
        self.lgr.debug('added rev_write_hap')
        self.rev_write_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.revWriteCallback, self.cpu, self.kernel_write_break)

        #self.lgr.debug( 'breakpoint is %d, done now return from findKernelWrite, set forward break %d at 0x%x (0x%x)' % (self.kernel_write_break, self.forward_break, self.forward_eip, forward_phys_block.address))
        self.lgr.debug( 'breakpoint is %d, done now return from findKernelWrite)' % (self.kernel_write_break))
        SIM_run_alone(SIM_run_command, 'reverse')

    def vt_handler(self, logical_address):
        offset = 0
        if logical_address != self.addr:
            offset = self.addr - logical_address
        self.lgr.debug('vt_handler, logical_address is 0x%x offset: %d cycle: 0x%x' % (logical_address, offset, self.cpu.cycles))
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.rev_write_hap)
        self.rev_write_hap = None 
        SIM_run_alone(self.addStopHapForWriteAlone, offset)
        SIM_break_simulation('vt_handler')

    def revWriteCallback(self, cpu, third, forth, memory):
        if self.rev_write_hap is None:
            return
        orig_cycle = self.bookmarks.getFirstCycle()
        if self.cpu.cycles == orig_cycle:
            ida_message = 'revWriteCallback reversed to earliest bookmark'
            self.lgr.debug(ida_message)
            self.context_manager.setIdaMessage(ida_message)
            SIM_run_alone(self.cleanup, False)
            self.top.skipAndMail()
        else:
            location = memory.logical_address
            phys = memory.physical_address
            self.lgr.debug('revWriteCallback hit 0x%x (phys 0x%x) size %d cycle: 0x%x' % (location, phys, memory.size, self.cpu.cycles))
            VT_in_time_order(self.vt_handler, location)

    def addStopHapForWriteAlone(self, offset):
        self.stop_write_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
		    self.stopToCheckWriteCallback, offset)
        #SIM_run_command('reverse')
        self.lgr.debug('addStopHapForWriteAlone')


    def writeCallback(self, cpu, third, forth, memory):
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
        SIM_run_alone(self.thinkWeWrote, 0)

    def stopToCheckWriteCallback(self, offset, one, exception, error_string):
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
         
        SIM_run_alone(self.thinkWeWrote, offset)

    def checkWriteValue(self, eip):
        retval = True
        if self.num_bytes > 1:
            value = self.mem_utils.readWord32(self.cpu, self.addr)
        else:
            value = self.mem_utils.readByte(self.cpu, self.addr)
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
       
    def skipAlone(self, cycles):
        self.lgr.debug('findKernelWrite skipAlone to cycle 0x%x' % cycles)
        cmd = 'skip-to cycle=%d' % cycles
        SIM_run_command(cmd)
        eip = self.top.getEIP(self.cpu)
        ida_message = 'skipAlone?'
        if self.memory_transaction is None:
           value = None
        else:
            value = self.mem_utils.readMemory(self.cpu, self.addr, self.memory_transaction.size)
        #value = self.mem_utils.readWord32(self.cpu, self.addr)
        do_satisfy = False
        data_watch = None
        if value is None:
            ida_msg = "Nothing mapped at 0x%x, not paged in?" % self.addr
            bm = "eip:0x%x follows kernel paging of memory:0x%x" % (eip, self.addr)
        else: 
            eip = self.top.getEIP(self.cpu)
            if eip == self.bookmarks.getEIP('_start+1'):
                ida_message = "Content of 0x%x existed pror to _start+1, perhaps from loader." % self.addr
                bm = None
            else:
                data_str = ''
                if self.dataWatch is not None:
                    data_watch = self.dataWatch.findRange(self.addr)
                    if data_watch is not None:
                        offset = self.addr - data_watch
                        data_str = 'Offset %d from start of buffer at 0x%x' % (offset, data_watch)

                self.lgr.debug('skipAlone access to 0x%x' % self.memory_transaction.logical_address)
                if self.memory_transaction.logical_address == self.addr:
                    ida_message = 'Kernel wrote 0x%x to address: 0x%x %s' % (value, self.addr, data_str)
                    bm = "eip:0x%x follows kernel write of value:0x%x to memory:0x%x %s" % (eip, value, self.addr, data_str)
                else:
                    ida_message = 'Kernel wrote to user space address: 0x%x while writing 0x%x to 0x%x  %s' % (self.addr, value, self.memory_transaction.logical_address, data_str)
                    bm = "eip:0x%x follows kernel write to memory:0x%x while writing 0x%x to 0x%x  %s" % (eip, 
                           self.addr, value, self.memory_transaction.logical_address, data_str)
                if self.satisfy_value is not None:
                    self.lgr.debug(ida_message)
                    do_satisfy = True
        if not do_satisfy:                 
        
            if bm is not None:
                self.bookmarks.setBacktrackBookmark(bm)
            self.lgr.debug('set ida msg to %s' % ida_message)
            self.context_manager.setIdaMessage(ida_message)
            SIM_run_alone(self.cleanup, False)
            self.top.skipAndMail()
        else:
            self.lgr.debug('findKernelWrite satisfy condition set addr 0x%x to 0x%x' % (self.addr, self.satisfy_value))
            SIM_run_alone(self.cleanup, False)
            self.top.restoreDebugBreaks()
            self.top.writeByte(self.addr, self.satisfy_value)
            self.top.retrack()
               
    def stopExit(self, cycles, one, exception, error_string):
        ''' stopped after hitting exit after write by kernel to desired address '''
        if self.stop_exit_hap is None:
            return
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('findKernelWrite stopExit eip 0x%x' % eip)
        self.lgr.debug('findKernelWrite one %s  exce %s  err %s' % (str(one), str(exception), str(error_string)))
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_exit_hap)
        self.stop_exit_hap = None
        SIM_run_alone(self.skipAlone, cycles) 
 
    def exitAlone(self, cycles):
        ''' set stop hap and stop simulation '''
        self.lgr.debug('findKernelWrite exitAlone cycles: 0x%x' % cycles)
        self.stop_exit_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
		    self.stopExit, cycles)
        if self.exit_hap is not None:
            self.context_manager.genDeleteHap(self.exit_hap, immediate=True)
            self.exit_hap = None
        if self.exit_hap2 is not None:
            self.context_manager.genDeleteHap(self.exit_hap2, immediate=True)
            self.exit_hap2 = None
        SIM_break_simulation('exitAlone')
   
    def exitHap(self, exit_info, third, forth, memory):
        ''' we hit one of the sysexit breakpoints '''
        if self.exit_hap is None and self.exit_hap2 is None:
            return
        target_cycles = self.cpu.cycles + 1
        self.lgr.debug('findKernelWrite exitHap target cycles set to 0x%x' % target_cycles)
        SIM_run_alone(self.exitAlone, target_cycles)

    def hitForwardCallback(self, data, trigger_obj, breakpoint_id, memory):
        if self.kernel_write_break is not None:
            self.memory_transaction = memory
            self.lgr.debug('hitForward access to 0x%x' % self.memory_transaction.logical_address)
            self.lgr.debug('hitForward deleting breakpoint %d' % self.kernel_write_break)
            SIM_run_alone(self.cleanup, None)

        
    ''' We stopped, presumably because target address was written.  If in the kernel, set break on return
        address and continue to user space.
    '''
    def thinkWeWrote(self, offset):
        #if self.stop_write_hap is None:
        #    return
        eip = self.mem_utils.getRegValue(self.cpu, 'pc')
        cycle = self.cpu.cycles
        cpl = memUtils.getCPL(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        orig_cycle = self.bookmarks.getFirstCycle()
        dumb, comm, pid = self.task_utils.curProc() 
        self.lgr.debug( 'in thinkWeWrote pid:%d, cycle 0x%x eip: %x  %s cpl: %d orig cycle 0x%x' % (pid, cycle, eip, str(instruct), cpl, orig_cycle))
        if cycle <= orig_cycle:
            range_start = self.dataWatch.findRange(self.addr)
            range_msg = ''
            if range_start is not None:
                offset = self.addr - range_start
                range_msg = ' And that is %d bytes from buffer starting at 0x%x' % (offset, range_start)
            ida_msg = "Content of 0x%x was modified prior to enabling reverse execution. %s" % (self.addr, range_msg)
            self.lgr.debug('findKernelWrite thinkWeWrote '+ida_msg)
            self.context_manager.setIdaMessage(ida_msg)
            SIM_run_alone(self.cleanup, False)
            self.top.skipAndMail()
            return
        elif pid == 0:
            ida_msg = "Content of 0x%x was modified in pid ZERO?" % self.addr
            self.lgr.error('findKernelWrite thinkWeWrote '+ida_msg)
            self.context_manager.setIdaMessage(ida_msg)
            SIM_run_alone(self.cleanup, False)
            self.top.skipAndMail()
            return
        if cpl == 0:
            if self.found_kernel_write:
                self.lgr.debug('thinkWeWrote stopToCheckWriteCallback found second write?  but we deleted the breakpoint!!!! ignore this and reverse')
                #SIM_run_alone(SIM_run_command, 'reverse')
                return
            ''' get return address '''
            self.found_kernel_write = True
            ''' Simics has no way to get recent memory transaction, so, go back one and set a hap on the break so we can get the memop '''
            ''' We were going to run forward anyway to get to user space ,so manage it on the fly '''
            back_one = self.cpu.cycles - 1
            if not self.rev_to_call.skipToTest(back_one):
                return
            #cmd =  'skip-to cycle=%d' % (self.cpu.cycles-1)
            #SIM_run_command(cmd)
            self.forward_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.hitForwardCallback, None, self.kernel_write_break)

            self.lgr.debug('thinkWeWrote, forward_hap is %d  on write to 0x%x. Set breaks on exit to user' % (self.forward_hap, self.kernel_write_break))
            if self.cpu.architecture == 'arm':
                self.kernel_exit_break1 = self.context_manager.genBreakpoint(self.cell, 
                                                        Sim_Break_Linear, Sim_Access_Execute, self.param.arm_ret, 1, 0)
                self.exit_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, 
                                                           None, self.kernel_exit_break1, 'findKernelWrite armexit')
                #self.cleanup()
            else:
                if self.param.sysexit is not None:
                    self.kernel_exit_break1 = self.context_manager.genBreakpoint(self.cell, 
                                                            Sim_Break_Linear, Sim_Access_Execute, self.param.sysexit, 1, 0)
                    self.exit_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, 
                                                           None, self.kernel_exit_break1, 'findKernelWrite sysexit')
                if self.param.iretd is not None:
                    self.kernel_exit_break2 = self.context_manager.genBreakpoint(self.cell, 
                                                            Sim_Break_Linear, Sim_Access_Execute, self.param.iretd, 1, 0)
                    self.exit_hap2 = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, 
                                                           None, self.kernel_exit_break2, 'findKernelWrite iretd')
            SIM_run_alone(SIM_run_command, 'continue')

        elif self.found_kernel_write:
            self.lgr.debug('thinkWeWrote, BACKTRACK pid:%d user space address 0x%x after finding kernel write to  0x%x' % (pid, eip, self.addr))
            if not self.checkWriteValue(eip):
                return

            value = self.mem_utils.readWord32(self.cpu, self.addr)
            eip = self.top.getEIP(self.cpu)
            if eip == self.bookmarks.getEIP('_start+1'):
                ida_message = "Content of 0x%x existed pror to _start+1, perhaps from loader." % self.addr
                bm = None
            else:
                ida_message = 'Kernel wrote 0x%x to address: 0x%x' % (value, self.addr)
                self.lgr.debug('set ida msg to %s' % ida_message)
                bm = "eip:0x%x follows kernel write of value:0x%x to memory:0x%x" % (eip, value, self.addr)
            if bm is not None:
                self.bookmarks.setBacktrackBookmark(bm)
            self.context_manager.setIdaMessage(ida_message)
            SIM_run_alone(self.cleanup, False)
            self.top.skipAndMail()
            #previous = SIM_cycle_count(my_args.cpu) - 1
            #SIM_run_alone(SIM_run_command, 'skip-to cycle=%d' % previous)
            #eip = self.top.getEIP()
            #msg = '0x%x' % eip
            #self.top.gdbMailbox(msg)
            
            self.context_manager.setExitBreaks()
             
        else:
            if not self.checkWriteValue(eip):
                return
            eip = self.top.getEIP(self.cpu)
            SIM_run_alone(self.cleanup, False)
            if eip == self.bookmarks.getEIP('_start+1'):
                ida_message = "Content of %s came modified prior to enabling reverse." % self.addr
                bm = "eip:0x%x content of memory:%s modified prior to enabling reverse" % (eip, self.addr)
                self.bookmarks.setBacktrackBookmark(bm)
                self.context_manager.setIdaMessage(ida_message)
                SIM_run_alone(self.cleanup, False)
                self.top.skipAndMail()
                
            elif self.rev_to_call is None:
                # reverse two so we land on the instruction that does the write (after client steps forward 1)
                self.lgr.debug( 'thinkWeWrote eip is %x in user space,  stop here and reverse 2  : may break if page fault?' % eip)
                self.top.skipAndMail(cycles=2)
            else:
                self.lgr.debug('thinkWeWrote, call backOneAlone')
                SIM_run_alone(self.backOneAlone, offset)
            #self.top.skipAndMail()
            #previous = SIM_cycle_count(my_args.cpu) - 1
            #SIM_run_alone(SIM_run_command, 'skip-to cycle=%d' % previous)
            #eip = self.top.getEIP()
            #msg = '0x%x' % eip
            #self.top.gdbMailbox(msg)
            
            self.context_manager.setExitBreaks()

    def backOneAlone(self, offset):
        current = SIM_cycle_count(self.cpu)
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        value = self.mem_utils.readWord32(self.cpu, self.addr)
        dumb, comm, pid = self.task_utils.curProc() 
        self.lgr.debug('backOne user space pid: %d write of 0x%x to addr 0x%x cycle/eip after write is 0x%x  eip:0x%x ' % (pid, value, self.addr, current, eip))
        if not self.forward:
            previous = current - 1
            SIM_run_command('pselect %s' % self.cpu.name)
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
        mn = self.decode.getMn(instruct[1])
        self.lgr.debug('backOneAlone BACKTRACK backOneAlone, write described above occured at 0x%x : %s' % (eip, str(instruct[1])))
        bm = 'eip:0x%x inst:"%s"' % (eip, instruct[1])
        self.bookmarks.setBacktrackBookmark(bm)
        self.lgr.debug('BT bookmark: %s' % bm)
        if self.decode.modifiesOp0(mn):
            self.lgr.debug('backOneAlone get operands from %s' % instruct[1])
            op1, op0 = self.decode.getOperands(instruct[1])
            actual_addr = self.decode.getAddressFromOperand(self.cpu, op0, self.lgr)
            if actual_addr is None:
                self.lgr.error('failed to get op0 address from %s' % instruct[1])
                return
            offset = self.addr - actual_addr
            self.lgr.debug('backOneAlone cycleRegisterMod mn: %s op0: %s  op1: %s actual_addr 0x%x orig 0x%x address offset is %d' % (mn, 
                 op0, op1, actual_addr, self.addr, offset))
            if self.decode.isIndirect(op1):
                reg_num = self.cpu.iface.int_register.get_number(op1)
                address = self.cpu.iface.int_register.read(reg_num)
                new_address = address+offset
                #if not self.top.isProtectedMemory(new_address):
                if not self.top.isProtectedMemory(new_address) and not '[' in op0:
                    self.lgr.debug('backOneAlone, %s is indirect, check for write to 0x%x' % (op1, new_address))
                    self.top.stopAtKernelWrite(new_address, self.rev_to_call)
                else:
                    self.lgr.debug('backOneAlone is indirect reg point to magic page, or move to memory, find mod of the reg vice the address content')
                    self.rev_to_call.doRevToModReg(op1, taint=True, offset=offset, value=self.value, num_bytes = self.num_bytes)
 
            elif self.decode.isReg(op1):
                reg_num = self.cpu.iface.int_register.get_number(op1)
                value = self.cpu.iface.int_register.read(reg_num)
                self.lgr.debug('backOneAlone %s is reg, find where wrote value 0x%x reversing  from cycle 0x%x' % (op1, value, self.cpu.cycles))
                self.rev_to_call.doRevToModReg(op1, taint=True, offset=offset, value=self.value, num_bytes = self.num_bytes)
            else:
                value = None
                try:
                   value = int(op1,16)
                except:
                   pass
                if value is not None:
                    if self.top.isProtectedMemory(value):
                        self.lgr.debug('backOneAlone, found protected memory %x ' % value)
                        SIM_run_alone(self.cleanup, False)
                        self.top.skipAndMail()
                    else:
                        ''' stumped, constant loaded into memory '''
                        self.lgr.debug('backOneAlone, found constant %x, stumped' % value)
                        SIM_run_alone(self.cleanup, False)
                        self.top.skipAndMail()
        elif mn == 'push':
            op1, op0 = self.decode.getOperands(instruct[1])
            self.lgr.debug('backOneAlone push op0 is %s' % op0)
            if self.decode.isReg(op0): 
                self.lgr.debug('backOneAlone is push reg %s, find mod', op0)
                self.rev_to_call.doRevToModReg(op0, taint=True, value=self.value, num_bytes = self.num_bytes)
            else:
                new_address = self.decode.getAddressFromOperand(self.cpu, op0, self.lgr)
                self.lgr.debug('backOneAlone is push addr 0x%x', new_address)
                self.top.stopAtKernelWrite(new_address, self.rev_to_call)

        elif self.cpu.architecture == 'arm' and mn.startswith('stm'):
            reg = self.decode.armSTM(self.cpu, instruct[1], self.addr, self.lgr)
            self.lgr.debug('back from armSTM reg: %s cycle 0x%x' % (reg, self.cpu.cycles))
            if reg is not None:
                rval = self.mem_utils.getRegValue(self.cpu, reg)
                self.lgr.debug('backOneAlone is stm... reg %s, find mod to 0x%x' % (reg, rval))
                self.rev_to_call.doRevToModReg(reg, taint=True, value=self.value, num_bytes = self.num_bytes)
        elif self.cpu.architecture == 'arm' and mn.startswith('str'):
            reg = self.decode.armSTR(self.cpu, instruct[1], self.addr, self.lgr)
            if reg is not None:
                self.lgr.debug('backOneAlone is str... reg %s, find mod', reg)
                self.rev_to_call.doRevToModReg(reg, taint=True, value=self.value, num_bytes = self.num_bytes, offset=offset)

        else:
            self.lgr.debug('backOneAlone, cannot track values back beyond %s' % str(instruct))
            SIM_run_alone(self.cleanup, False)
            self.top.skipAndMail()

    def cleanup(self, dumb = False):
        self.found_kernel_write = False
        if self.kernel_write_break is not None:
            self.lgr.debug('findKernelWrite cleanup deleting hap and breakpoint %d' % self.kernel_write_break)
            SIM_delete_breakpoint(self.kernel_write_break)
            self.kernel_write_break = None
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
        if self.forward_hap is not None:
            self.lgr.debug('cleanup delete forward_hap %d' % self.forward_hap)
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.forward_hap)
            self.forward_hap = None
                

