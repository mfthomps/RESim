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
import cli
from simics import *
from resimHaps import *
import memUtils
import decode
import decodeArm
import decodePPC32
import procInfo
import resimUtils
import resimSimicsUtils
import time
import os
'''
    Catch the kernel writing to a memory breakpoint and bring the eip to the return from the syscall.
    If the memory is written by user space, stop there.  If track is set, then continue back tracing
    the load of the register whose value was stored to memory.
'''
class findKernelWrite():
    def __init__(self, top, cpu, cell, addr, task_utils, mem_utils, context_manager, param, 
                 bookmarks, dataWatch, reverse_mgr, lgr, rev_to_call=None, num_bytes = 1, satisfy_value=None, kernel=False, prev_buffer=False, track=False):
        self.stop_write_hap = None
        self.task_utils = task_utils
        self.mem_utils = mem_utils
        self.lgr = lgr
        self.top = top
        self.param = param
        self.context_manager = context_manager
        self.dataWatch = dataWatch
        self.reverse_mgr = reverse_mgr
        self.cpu = cpu
        self.found_kernel_write = False
        self.rev_to_call = rev_to_call
        self.addr = addr
        self.num_bytes = num_bytes
        self.bookmarks = bookmarks
        self.track = track
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
        self.kernel = kernel
        self.prev_buffer = prev_buffer
        self.memory_transaction = None
        self.rev_write_hap = None
        self.broken_hap = None

        self.prev_addr = 0
        self.prev_value = None
        self.prev_delta = None
        self.iter_count = None

        ''' kernel buffer addresses used for x86 kernel buffer injection '''
        self.k_buffer_addrs = []

        ''' handle case where address is in the initial data watch buffer, but only if that is
            not a true kernel write '''
        if not self.kernel and self.checkInitialBuffer(addr):
            self.top.skipAndMail()
            return
        if self.cpu.architecture.startswith('arm'):
            self.decode = decodeArm
            self.lgr.debug('findKernelWrite using arm decoder')
        elif self.cpu.architecture == 'ppc32':
            self.decode = decodePPC32
            self.lgr.debug('findKernelWrite using PPC32 decoder')
        else:
            self.decode = decode
        self.start_cycles = None
        self.stop_cycles = None

        # simics bugs
        self.future_count = 0
        self.best_cycle = 0

        self.lgr.debug('findKernelWrite addr 0x%x num_bytes %d' % (addr, num_bytes))
        self.go(addr)


    def go(self, addr, num_bytes=None, track=False, rev_to_call=None):
        if num_bytes is not None:
            self.num_bytes=num_bytes 
        if not self.track:
            self.track = track
        if self.rev_to_call is None:
            self.rev_to_call = rev_to_call
        ''' go forward one in case the insruction just executed is what did a write.  cheap way to catch that'''
        self.start_cycles = self.cpu.cycles
        cli.quiet_run_command('si')
        self.addr = addr
        # don't reset if set

        #phys_block = self.cpu.iface.processor_info.logical_to_physical(addr, Sim_Access_Write)
        phys = self.mem_utils.v2p(self.cpu, addr)
        #if phys_block.address == 0:
        if phys is None:
            self.lgr.error('findKernelWrite requested address %x, not mapped?' % addr)
            return
        ''' TBD support byte, word, dword '''
        if self.num_bytes > 1:
            value = self.mem_utils.readWord32(self.cpu, self.addr)
        else:
            value = self.mem_utils.readByte(self.cpu, self.addr)
        self.value = value
        dumb, comm, tid = self.task_utils.curThread() 
        self.lgr.debug( 'findKernelWrite go tid:%s of 0x%x to addr %x, phys %x num_bytes: %d' % (tid, value, addr, phys, self.num_bytes))
        pcell = self.cpu.physical_memory
        self.kernel_write_break = self.reverse_mgr.SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, 
            phys, self.num_bytes, 0)

        if not self.reverse_mgr.nativeReverse():
            self.reverse_mgr.setCallback(self.revWriteCallbackSim7)
        else:
            #self.hackOrigin()
            self.lgr.debug('findKernelWrite added rev_write_hap kernel break %d' % self.kernel_write_break)
            self.rev_write_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.revWriteCallback, self.cpu, self.kernel_write_break)
            self.broken_hap = self.top.RES_add_stop_callback(self.brokenHap, self.cpu.cycles)

        self.lgr.debug( 'breakpoint is %d, done now reverse from findKernelWrite)' % (self.kernel_write_break))
        self.context_manager.disableAll(direction='reverse')
        self.future_count = 0
        self.best_cycle = 0
        # TBD does this nonsense mask a simics bug in which the reverse never returns?
        '''
        now = self.cpu.cycles
        prev = now - 1
        if not self.top.skipToCycle(prev, cpu=self.cpu):
            self.top.quit()
        if not self.top.skipToCycle(now, cpu=self.cpu):
            self.top.quit()
        #SIM_run_alone(SIM_run_command, 'reverse')
        '''
     

        #if False and addr == 0x83ca6cf:
        #    print('remove this would reverse') 
        #else:
        self.reverse_mgr.reverse()
        #hack_limit_cycle = self.cpu.cycles - 1000
        #self.lgr.debug( 'findKernelWrite hack_limit cycle 0x%x' % hack_limit_cycle)
        #self.reverse_mgr.reverse(hack_limit_cycle)

    def hackOrigin(self):
        max_delta = 100000000
        orig = self.top.getFirstCycle()
        now = self.cpu.cycles
        delta = now - orig
        self.lgr.debug('findKernelWrite delta cycles is %s' % f'{delta:,}')
        if delta > max_delta:
            #new_origin = now - max_delta
            new_origin = origin + 1000
            self.top.skipToCycle(new_origin, disable=True)
            self.lgr.debug('findKernelWrite new origin at 0x%x' % self.cpu.cycles)
            self.top.resetOrigin()
            self.top.skipToCycle(now, disable=True)

    def checkInitialBufferAlone(self, addr):
        self.lgr.debug('findKernelWrite checkInitialBufferAlone 0%x' % addr)
        self.dataWatch.goToMark(0)
        if self.satisfy_value is not None:
            self.top.restoreDebugBreaks()
            self.top.writeByte(addr, self.satisfy_value)
            self.top.retrack()

    def checkInitialBuffer(self, addr):
        range_index = self.dataWatch.findRangeIndex(addr)
        if range_index == 0:
            ''' Is initial data watch buffer.'''
            self.lgr.debug('findKernelWrite checkInitialBuffer, addr 0x%x in initial dataWatch range' % addr)
            if self.rev_to_call is None:
                self.lgr.debug('findKernelWrite, rev_to_call is None')
            else:
                if self.satisfy_value is None:
                    SIM_run_alone(self.checkInitialBufferAlone, addr)
                    buf_start = self.dataWatch.findRange(addr)
                    eip = self.top.getEIP(self.cpu)
                    offset = addr - buf_start
                    bm = "eip:0x%x Offset 0x%x into the Initial dataWatch buffer starting  0x%x" % (eip, offset, buf_start)
                    self.bookmarks.setBacktrackBookmark(bm)
                    ida_message = 'Data traced back to address 0x%x at offset 0x%x into initial data watch buffer' % (addr, offset)
                    self.context_manager.setIdaMessage(ida_message)
                    return True
        return False

    def cleanUp(self):
        self.deleteBrokenHap()
        if self.kernel_write_break is not None: 
            self.reverse_mgr.SIM_delete_breakpoint(self.kernel_write_break)
            self.kernel_write_break = None 
            self.lgr.debug('findKernelWrite cleanUp deleted kernel_write_break')
        if self.rev_write_hap is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.rev_write_hap)
            self.rev_write_hap = None 
            self.lgr.debug('findKernelWrite cleanUp deleted rev_write_hap')

    def vt_handler(self, memory):
        if self.rev_write_hap is None:
            return
        offset = 0
        eip = self.top.getEIP(self.cpu)
        self.cleanUp()
        if memory.logical_address == 0:
            ''' TBD this would reflect an error or corruption in Simics due to reality leaks.  Replace with error message. '''
            #phys_block = self.cpu.iface.processor_info.logical_to_physical(self.addr, Sim_Access_Write)
            #phys_addr = phys_block.address
            phys_addr = self.mem_utils.v2p(self.cpu, self.addr)
            if phys_addr != memory.physical_address:
                offset = memory.physical_address = phys_addr
            self.lgr.debug('vt_handler, physical_address is 0x%x size: %d offset: %d eip: 0x%x cycle: 0x%x' % (memory.physical_address, memory.size, offset, eip, self.cpu.cycles))
        else:
            if memory.logical_address != self.addr:
                offset = memory.logical_address - self.addr
            self.lgr.debug('vt_handler, logical_address is 0x%x size 0x%x offset: %d value: 0x%x eip: 0x%x cycle: 0x%x' % (memory.logical_address, memory.size, offset, memory.value, eip, self.cpu.cycles))
        self.memory_transaction = memory
        SIM_run_alone(self.context_manager.enableAll, None)
        SIM_run_alone(self.addStopHapForWriteAlone, offset)

    def deleteBrokenAlone(self, hap):
        self.top.RES_delete_stop_hap(hap)

    class MyMemoryTransaction():
        def __init__(self, logical_address, physical_address, size, value):
            self.logical_address = logical_address 
            self.physical_address = physical_address 
            self.size = size 
            self.value = value 

    def deleteBrokenHap(self):
        if self.broken_hap is not None:
            hap = self.broken_hap
            SIM_run_alone(self.deleteBrokenAlone, hap)
            self.broken_hap = None
            self.lgr.debug('deleteBroken_hap removed broken_hap')

    def revWriteCallback(self, cpu, the_object, break_num, memory):
        #self.lgr.debug('revWriteCallback hit the_object %s  break_num %s' % (third, forth))
        if self.rev_write_hap is None:
            self.lgr.debug('revWriteCallback hit None')
            return
        orig_cycle = self.bookmarks.getFirstCycle()
        if self.cpu.cycles == orig_cycle:
            ida_message = 'revWriteCallback reversed to earliest bookmark'
            self.lgr.debug(ida_message)
            self.context_manager.setIdaMessage(ida_message)
            self.deleteBrokenHap()
            SIM_run_alone(self.context_manager.enableAll, None)
            SIM_run_alone(self.cleanup, False)
            self.top.skipAndMail()
        else:
            if memory.size <= 8:
                value = memUtils.memoryValue(self.cpu, memory)
            else:
                self.lgr.debug('revWriteCallBack, memory transaction size > 8, addr 0x%x' % memory.logical_address)
                value = 0xbaaabaaabaaabaaa
            my_memory = self.MyMemoryTransaction(memory.logical_address, memory.physical_address, memory.size, value)
            if self.cpu.cycles == self.start_cycles:
                self.lgr.debug('revWriteCallBack, is at starting cycles.  some kind of rep instruction?')
                self.vt_handler(my_memory)
            elif self.cpu.cycles < self.start_cycles:
                location = memory.logical_address
                phys = memory.physical_address
                eip = self.top.getEIP(self.cpu)
                self.lgr.debug('revWriteCallback hit 0x%x (phys 0x%x) size %d cycle: 0x%x eip: 0x%x' % (location, phys, memory.size, self.cpu.cycles, eip))
                self.future_count = 0
                if self.cpu.cycles > self.best_cycle:
                    self.best_cycle = self.cpu.cycles
                    self.lgr.debug('revWriteCallback best cycle now 0x%x' % self.best_cycle)
                VT_in_time_order(self.vt_handler, my_memory)
            else:
                location = memory.logical_address
                phys = memory.physical_address
                eip = self.top.getEIP(self.cpu)
                self.lgr.debug('revWriteCallback hit 0x%x (phys 0x%x) size %d cycle: 0x%x eip: 0x%x' % (location, phys, memory.size, self.cpu.cycles, eip))
                self.lgr.debug('revWriteCallback hit 0x%x (phys 0x%x) size %d BUT A FUTURE CYCLE cycle: 0x%x eip: 0x%x' % (location, phys, memory.size, self.cpu.cycles, eip))
                self.future_count = self.future_count+1
                if self.future_count > 100:
                    if self.best_cycle == 0:
                        bm = "eip:0x%x modification of :0x%x occured prior to current origin.?" % (eip, self.addr)
                        self.bookmarks.setBacktrackBookmark(bm)
                        SIM_break_simulation('revWriteCallback')
                        self.top.skipAndMail()
                        return
                    else:
                        bm = "eip:0x%x modification of :0x%x not found after some looking.  Simics is sick and must die." % (eip, self.addr)
                        self.lgr.debug(" revWriteCallback eip:0x%x modification of :0x%x not found after some looking.  Simics is sick and must die." % (eip, self.addr))
                        self.top.quit()
                        #self.bookmarks.setBacktrackBookmark(bm)
                        #SIM_break_simulation('revWriteCallbackx')
                        #self.top.skipAndMail()
                        return
                    #else:
                    #    self.lgr.error('revWriteCallback %d hits in the future, bail.  Best cycle was 0x%x' % (self.future_count, self.best_cycle))
                    #    #self.cleanUp()
                    #    #SIM_break_simulation('remove this and fix it')
                    #    # simics goes into loop, but can still quit
                    #    self.top.quit()
                VT_in_time_order(self.vt_handler, my_memory)
                

    def addStopHapForWriteAlone(self, offset):
        '''
        Called by VT_handler
        '''
        self.stop_write_hap = self.top.RES_add_stop_callback(self.stopToCheckWriteCallback, offset)
        #SIM_run_command('reverse')
        SIM_break_simulation('vt_handler')
        self.stop_cycles = self.cpu.cycles
        self.lgr.debug('addStopHapForWriteAlone cycles 0x%x' % self.cpu.cycles)


    def writeCallback(self, cpu, third, forth, memory):
        location = memory.logical_address
        physical = memory.physical_address
        if location == 0 and physical == 0:
           self.lgr.debug('findKernelWrite writeCallback, location zero?')
           ''' recursive callback triggered by this Hap '''
           return
        length = memory.size
        op_type = SIM_get_mem_op_type(memory)
        type_name = SIM_get_mem_op_type_name(op_type)
        self.lgr.debug('writeCallback location 0x%x phys 0x%x len %d  type %s' % (location, physical, length, type_name))

        self.lgr.debug('writeCallback')
        self.stop_cycles = self.cpu.cycles
        SIM_run_alone(self.thinkWeWrote, 0)

    def brokenHap(self, cycles, one, exception, error_string):
        if self.broken_hap is None:
            return
        SIM_run_alone(self.context_manager.enableAll, None)
        self.lgr.debug('brokenHap, address is 0x%x' % self.addr)
        self.deleteBrokenHap()
        orig_cycle = self.bookmarks.getFirstCycle()
        eip = self.top.getEIP(self.cpu)
        bm = None
        if self.cpu.cycles == orig_cycle:
            self.lgr.debug('findKernelWrite brokenHap at origin')
            if not self.checkInitialBuffer(self.addr):
                self.lgr.debug('findKernelWrite brokenHap not initial buffer, likely prior to current origin')
                bm = self.top.backtraceAddr(self.addr, cycles)
                if bm is None:
                    self.bookmarks.setBacktrackBookmark(bm)
                    bm = "eip:0x%x modification of :0x%x occured prior to current origin.?" % (eip, self.addr)
                self.bookmarks.setBacktrackBookmark(bm)
        else:
            self.lgr.debug('findKernelWrite brokenHap NOT at origin')
            bm = "eip:0x%x maybe follows kernel paging of memory:0x%x?" % (eip, self.addr)
            self.bookmarks.setBacktrackBookmark(bm)
        if bm is not None:
            self.context_manager.setIdaMessage(bm)
        SIM_run_alone(self.cleanup, False)
        self.lgr.debug('findKernelWrite brokenHap now skip')
        
        self.top.skipAndMail()

    def stopToCheckWriteCallback(self, offset, one, exception, error_string):
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('stopToCheckWriteCallback, eip: 0x%x params %s %s %s  cycle: 0x%x' % (eip, one, exception, error_string, self.cpu.cycles))
            
        if self.rev_write_hap is not None:
            self.lgr.warning('stopToCheckWrite hit but rev_write_hap set, ignore')
            return
        if self.forward is not None and eip == self.forward_eip:
            self.lgr.error('stopToCheckWriteCallback going forward hit our original eip')
            if self.stop_write_hap is not None:
                self.reverse_mgr.SIM_delete_breakpoint(self.kernel_write_break)
                self.top.RES_delete_stop_hap(self.stop_write_hap)
                self.stop_write_hap = None
                self.kernel_write_break = None
                self.lgr.debug('stopToCheckWriteCallback deleted kernel_write_break')
            if self.forward_break is not None:
                RES_delete_breakpoint(self.forward_break)
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
            #self.lgr.error('Simics reverse error, thought we wrote 0x%x, but value is 0x%x  skip forward until correct write' % (self.value, value))
            if value is not None:
                self.lgr.error('Simics reverse error, thought we wrote 0x%x, but value is 0x%x  bail' % (self.value, value))
            else:
                self.lgr.error('Simics reverse error, thought we wrote 0x%x, but value is none from reading addr  0x%x  bail' % (self.value, self.addr))
            SIM_run_alone(self.cleanup, False)
            return False 
            #!!!!!!!!!!!!!!!!!!!
            ''' do not clean up breakpoint, associate a hap with it and run forward '''
            
            if not self.forward:
                self.mem_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.writeCallback, self.cpu, self.kernel_write_break)
                self.lgr.debug('checkWriteValue set kernel_write_break')
                self.forward = True
                if self.stop_write_hap is not None:
                    # TBD does not make sense to delete these here?
                    #SIM_delete_breakpoint(self.kernel_write_break)
                    #self.kernel_write_break = None
                    self.top.RES_delete_stop_hap(self.stop_write_hap)
                    self.stop_write_hap = None
                
            status = SIM_simics_is_running()
            if not status: 
                if self.forward_break is not None:
                    SIM_run_alone(SIM_run_command, 'continue')
                else:
                    self.lgr.error('checkWriteValue refuse to run forward without a forward_break')
                    return retval
            else:
                self.lgr.error('checkWriteValue found simics to be running, should be invoked as part of a stop hap????')
            retval = False          
        return retval
       
    def skipAlone(self, cycles):
        self.lgr.debug('findKernelWrite skipAlone to cycle 0x%x' % cycles)
        self.reverse_mgr.skipToCycle(cycles)
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
                        which_read = self.dataWatch.whichRead()
                        if which_read is not None:
                            data_str = data_str+(' following %d read/recvs' % which_read)

                self.lgr.debug('skipAlone access to 0x%x' % self.memory_transaction.logical_address)
                if self.memory_transaction.logical_address == self.addr:
                    ida_message = 'Kernel wrote 0x%x to address: 0x%x %s' % (value, self.addr, data_str)
                    bm = "eip:0x%x follows kernel write of value:0x%x to memory:0x%x %s" % (eip, value, self.addr, data_str)
                else:
                    ida_message = 'Kernel wrote to user space address: 0x%x while writing 0x%x to 0x%x  %s' % (self.addr, value, self.memory_transaction.logical_address, data_str)
                    # MESSAGE used in cadet-test, do not change
                    bm = "eip:0x%x follows kernel write to memory:0x%x while writing 0x%x to 0x%x  %s" % (eip, 
                           self.addr, value, self.memory_transaction.logical_address, data_str)
                syscall_info = self.top.getPrevSyscallInfo()
                bm = bm + ' '+syscall_info
                ida_message = ida_message + ' '+syscall_info
                if self.satisfy_value is not None:
                    self.lgr.debug(ida_message)
                    do_satisfy = True
        if not do_satisfy:                 
        
            if bm is not None:
                self.bookmarks.setBacktrackBookmark(bm)
            self.lgr.debug('set ida msg to %s' % ida_message)
            self.context_manager.setIdaMessage(ida_message)
            self.top.backtraceAddr(self.addr, self.cpu.cycles)
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
        self.lgr.debug('findKernelWrite stopExit eip 0x%x, given cycles: 0x%x' % (eip, cycles))
        self.lgr.debug('findKernelWrite one %s  exce %s  err %s' % (str(one), str(exception), str(error_string)))
        self.top.RES_delete_stop_hap(self.stop_exit_hap)
        self.stop_exit_hap = None
        SIM_run_alone(self.skipAlone, cycles) 
 
    def exitAlone(self, cycles):
        ''' set stop hap and stop simulation '''
        self.lgr.debug('findKernelWrite exitAlone cycles: 0x%x' % cycles)
        self.stop_exit_hap = self.top.RES_add_stop_callback(self.stopExit, cycles)
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

    '''
    def hitForwardCallback(self, data, trigger_obj, breakpoint_id, memory):
        if self.kernel_write_break is not None:
            self.memory_transaction = memory
            self.lgr.debug('hitForward access to 0x%x' % self.memory_transaction.logical_address)
            self.lgr.debug('hitForward deleting breakpoint %d' % self.kernel_write_break)
            SIM_run_alone(self.cleanup, None)
    '''

        
    ''' We stopped, presumably because target address was written.  If in the kernel, set break on return
        address and continue to user space.
    '''
    def thinkWeWrote(self, offset):
        ''' TBD hacking drift on break_simulation?'''
        if self.cpu.cycles != self.stop_cycles:
            self.lgr.debug('thinkWeWrote, bad cycle.  fix it?')
            self.rev_to_call.skipToTest(self.stop_cycles)
        #if self.stop_write_hap is None:
        #    return
        eip = self.mem_utils.getRegValue(self.cpu, 'pc')
        cycle = self.cpu.cycles
        cpl = memUtils.getCPL(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        orig_cycle = self.bookmarks.getFirstCycle()
        dumb, comm, tid = self.task_utils.curThread() 
        self.lgr.debug( 'in thinkWeWrote tid:%s, cycle 0x%x eip: %x  %s cpl: %d orig cycle 0x%x' % (tid, cycle, eip, str(instruct), cpl, orig_cycle))
        if self.stop_write_hap is not None:
                self.lgr.debug('thinkWeWrote delete stop_write_hap')
                self.top.RES_delete_stop_hap(self.stop_write_hap)
                self.stop_write_hap = None
        if cycle <= orig_cycle:
            range_start = self.dataWatch.findRange(self.addr)
            range_msg = ''
            if range_start is not None:
                offset = self.addr - range_start
                ida_msg = ' Content of 0x%x found %d bytes from buffer starting at 0x%x' % (self.addr, offset, range_start)
            else:
                ida_msg = "Content of 0x%x was modified prior to enabling reverse execution. %s" % (self.addr, range_msg)
            self.lgr.debug('findKernelWrite thinkWeWrote '+ida_msg)
            self.context_manager.setIdaMessage(ida_msg)
            print(ida_msg)
            SIM_run_alone(self.cleanup, False)
            self.top.skipAndMail()
            return
        elif tid == 0:
            ida_msg = "Content of 0x%x was modified in tid ZERO?" % self.addr
            self.lgr.error('findKernelWrite thinkWeWrote '+ida_msg)
            self.context_manager.setIdaMessage(ida_msg)
            SIM_run_alone(self.cleanup, False)
            self.top.skipAndMail()
            return
        if cpl == 0 and not self.kernel:
            if self.found_kernel_write:
                self.lgr.debug('thinkWeWrote stopToCheckWriteCallback found second write?  but we deleted the breakpoint!!!! ignore this and reverse')
                #SIM_run_alone(SIM_run_command, 'reverse')
                return
            ''' get return address '''
            self.found_kernel_write = True
            ''' Simics has no way to get recent memory transaction, so, go back one and set a hap on the break so we can get the memop '''
            ''' We were going to run forward anyway to get to user space ,so manage it on the fly '''
            '''
            back_one = self.cpu.cycles - 1
            if not self.rev_to_call.skipToTest(back_one):
                return
            #cmd =  'skip-to cycle=%d' % (self.cpu.cycles-1)
            #SIM_run_command(cmd)
            # don't believe it, but we begin executing here during a retrack, somthing that has no calls to findKernelWrite
            # so this next bit is voodooooo
            if not self.found_kernel_write:
                self.lgr.error('voodoo in findKernel write, just return')
                SIM_run_command('c')
                return 
            self.forward_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.hitForwardCallback, None, self.kernel_write_break)

            self.lgr.debug('thinkWeWrote in kernel, forward_hap is %d  on write to 0x%x. Set breaks on exit to user' % (self.forward_hap, self.kernel_write_break))
            '''
            self.lgr.debug('thinkWeWrote in kernel. go forward to exit')
            if self.cpu.architecture.startswith('arm'):
                self.kernel_exit_break1 = self.context_manager.genBreakpoint(None, 
                                                        Sim_Break_Linear, Sim_Access_Execute, self.param.arm_ret, 1, 0)
                self.exit_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, 
                                                           None, self.kernel_exit_break1, 'findKernelWrite armexit')
                #self.cleanup()
            else:
                if self.param.sysexit is not None:
                    self.kernel_exit_break1 = self.context_manager.genBreakpoint(None, 
                                                            Sim_Break_Linear, Sim_Access_Execute, self.param.sysexit, 1, 0)
                    self.exit_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, 
                                                           None, self.kernel_exit_break1, 'findKernelWrite sysexit')
                if self.param.iretd is not None:
                    self.kernel_exit_break2 = self.context_manager.genBreakpoint(None, 
                                                            Sim_Break_Linear, Sim_Access_Execute, self.param.iretd, 1, 0)
                    self.exit_hap2 = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, 
                                                           None, self.kernel_exit_break2, 'findKernelWrite iretd')
            SIM_run_alone(SIM_run_command, 'continue')

        elif self.found_kernel_write:
            self.lgr.debug('thinkWeWrote, BACKTRACK tid:%s user space address 0x%x after finding kernel write to  0x%x' % (tid, eip, self.addr))
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
            if eip == self.bookmarks.getEIP('_start+1'):
                ida_message = "Content of %s came modified prior to enabling reverse." % self.addr
                self.lgr.debug(ida_msg)
                bm = "eip:0x%x content of memory:%s modified prior to enabling reverse" % (eip, self.addr)
                self.bookmarks.setBacktrackBookmark(bm)
                self.context_manager.setIdaMessage(ida_message)
                SIM_run_alone(self.cleanup, False)
                self.top.skipAndMail()
                
            elif self.rev_to_call is None:
                # reverse two so we land on the instruction that does the write (after client steps forward 1)
                self.lgr.debug( 'thinkWeWrote eip is %x in user space,  stop here and reverse 2  : may break if page fault?' % eip)
                SIM_run_alone(self.cleanup, False)
                self.top.skipAndMail(cycles=2)
            else:
                copy_addr, offset, mark = self.dataWatch.getMarkCopyOffset(self.addr)
                if copy_addr is not None:
                    if not self.rev_to_call.skipToTest(mark.call_cycle):
                        return
                    eip = self.top.getEIP(self.cpu)
                    ida_message = "Content of 0x%x resulted from a memory copy from 0x%x, offset %d bytes from start of copy" % (self.addr, copy_addr, offset)
                    bm = "eip:0x%x content of memory:0x%x from memory copy from 0x%x, offset %d bytes from start of copy. %s" % (eip, self.addr, copy_addr, offset, mark.mark.getMsg())
                    self.bookmarks.setBacktrackBookmark(bm)
                    self.context_manager.setIdaMessage(ida_message)
                    value = self.mem_utils.readWord32(self.cpu, copy_addr)
                    if value is None:
                        self.lgr.debug('findKernelWrite could not read from 0x%x, bail' % copy_addr)
                        SIM_run_alone(self.cleanup, False)
                        ida_message = "Content of 0x%x referenced in a memory copy from failed read at 0x%x" % (self.addr, copy_addr)
                        self.top.skipAndMail()
                        return 
                    self.lgr.debug('findKernelWrite, found mem copy, now look for address 0x%x, value is 0x%x' % (copy_addr, value))
                    SIM_run_alone(self.cleanup, False)
                    self.top.stopAtKernelWrite(copy_addr, rev_to_call=self.rev_to_call, num_bytes=self.num_bytes, kernel=self.kernel)
                elif instruct[1].startswith('rep movs') or instruct[1].startswith('rep movsd'):
                    src_addr = self.mem_utils.getRegValue(self.cpu, 'esi')
                    self.lgr.debug('findKernelWrite thinkWeWrote, is rep, %s  src add: 0x%x' % (instruct[1], src_addr))
                    if self.prev_buffer:
                        ''' TBD... assume break hit after first rep, thus subtract word from esi value... '''
                        self.k_buffer_addrs.append(src_addr - self.mem_utils.wordSize(self.cpu))
                        #self.k_buffer_addrs.append(self.addr)
                        if True or len(self.k_buffer_addrs) > 2:
                            SIM_run_alone(self.cleanup, False)
                            self.lgr.debug('findKernelWrite got rep movs.. with prev_buffer set, call rev_to_call to callback with address 0x%x' % src_addr)
                            self.rev_to_call.cleanup(self.k_buffer_addrs)
                    else:
                        eip = self.top.getEIP(self.cpu)
                        src_addr = src_addr - self.mem_utils.wordSize(self.cpu)
                        bm = "eip:0x%x content of memory:0x%x from %s from 0x%x" % (eip, self.addr, instruct[1], src_addr)
                        self.bookmarks.setBacktrackBookmark(bm)
                        self.top.stopAtKernelWrite(src_addr, rev_to_call=self.rev_to_call, num_bytes=self.num_bytes, kernel=self.kernel)
                else:
                    self.lgr.debug('findKernelWrite thinkWeWrote, call backOneAlone with offset zero?')
                    SIM_run_alone(self.backOneAlone, 0)
            
            self.context_manager.setExitBreaks()

    def backOneAlone(self, offset):
        current = self.cpu.cycles
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        value = self.mem_utils.readWord32(self.cpu, self.addr)
        
        if self.addr == self.prev_addr:
            self.iter_count += 1
            if self.iter_count > 5:
                self.lgr.debug('findKernelWrite backOneAlone, cannot track values back beyond %s' % str(instruct))
                bm = 'eip:0x%x inst:"%s Seems to be iteration, bailing"' % (eip, instruct[1])
                self.bookmarks.setBacktrackBookmark(bm)
                SIM_run_alone(self.cleanup, False)
                self.top.skipAndMail()
                return
        else:
            self.prev_addr = self.addr
            self.iter_count = 0
            
        dumb, comm, tid = self.task_utils.curThread() 
        self.lgr.debug('findKernelWrite backOne user space tid: %s write of 0x%x to addr 0x%x cycle/eip after write is 0x%x  eip:0x%x offset: 0x%x ' % (tid, 
               value, self.addr, current, eip, offset))
        if not self.forward:
            previous = current - 1
            if SIM_simics_is_running():
                self.lgr.error('findKernelWrite backOneAlone, simics is still running, is this not part of a stop hap???')
                return
            orig_eip = eip
            self.top.skipToCycle(previous, cpu=self.cpu, disable=True)
            eip = self.top.getEIP(self.cpu)
            eip = self.top.getEIP(self.cpu)
            if eip == orig_eip:
                self.lgr.warning('Simics 2 step fu, go forward then reskip...')
                cli.quiet_run_command('rev 1')
                eip = self.top.getEIP(self.cpu)
                self.top.skipToCycle(previous, cpu=self.cpu, disable=True)
                eip = self.top.getEIP(self.cpu)
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            self.lgr.debug('after skip back one, eip 0x%x' % eip)
        else:
            self.lgr.debug('findKernelWrite backOneAlone, was going forward')
        if not self.track:
            self.lgr.debug('findKernelWrite backOneAlone, not tracking, we are done.')
            SIM_run_alone(self.cleanup, False)
            self.top.skipAndMail()
            return

        if self.forward_break is not None:
            self.lgr.debug('findKernelWrite backOne alone delete forward_break')
            RES_delete_breakpoint(self.forward_break)
            self.forward_break = None
        mn = self.decode.getMn(instruct[1])
        self.lgr.debug('findKernelWrite backOneAlone BACKTRACK backOneAlone, write described above occured at 0x%x : %s' % (eip, str(instruct[1])))
        bm = 'eip:0x%x inst:"%s"' % (eip, instruct[1])
        self.bookmarks.setBacktrackBookmark(bm)
        self.lgr.debug('BT bookmark: %s' % bm)
        ''' If asked to just find previous buffer, then don't continue with reverse taint once a register source is found '''
        taint = True
        if self.prev_buffer:
            taint = False
        if self.decode.modifiesOp0(mn):
            self.lgr.debug('findKernelWrite backOneAlone get operands from %s' % instruct[1])
            op1, op0 = self.decode.getOperands(instruct[1])
            actual_addr = self.decode.getAddressFromOperand(self.cpu, op0, self.lgr)
            if actual_addr is None:
                self.lgr.error('failed to get op0 address from %s' % instruct[1])
                return
            offset = self.addr - actual_addr
            self.lgr.debug('findKernelWrite backOneAlone cycleRegisterMod mn: %s op0: %s  op1: %s actual_addr 0x%x orig 0x%x address offset is %d' % (mn, 
                 op0, op1, actual_addr, self.addr, offset))
            if self.decode.isIndirect(op1):
                #reg_num = self.cpu.iface.int_register.get_number(op1)
                #address = self.cpu.iface.int_register.read(reg_num)
                address = self.mem_utils.getRegValue(self.cpu, op1)
                new_address = address+offset
                if not '[' in op0:
                    self.lgr.debug('findKernelWrite backOneAlone, %s is indirect, check for write to 0x%x' % (op1, new_address))
                    self.top.stopAtKernelWrite(new_address, self.rev_to_call, kernel=self.kernel)
                else:
                    self.lgr.debug('findKernelWrite backOneAlone is indirect reg point to magic page, or move to memory, find mod of the reg vice the address content')
                    self.rev_to_call.doRevToModReg(op1, taint=taint, offset=offset, value=self.value, num_bytes = self.num_bytes, kernel=self.kernel)
 
            elif self.decode.isReg(op1):
                if op1.startswith('xmm'):
                    if offset >= 16:
                        suffix = 'H'
                    else:
                        suffix = 'L'
                    op1 = op1+suffix
                value = self.mem_utils.getRegValue(self.cpu, op1)
                #reg_num = self.cpu.iface.int_register.get_number(op1)
                #value = self.cpu.iface.int_register.read(reg_num)
                self.lgr.debug('findKernelWrite backOneAlone %s is reg, find where value 0x%x was loaded.  Num bytes %d offset %d   Reversing  from cycle 0x%x' % (op1, value, self.num_bytes, offset, self.cpu.cycles))
                #if op1.startswith('xmm'):
                #    SIM_break_simulation('remove this')
                #    return
                self.rev_to_call.doRevToModReg(op1, taint=taint, offset=offset, value=self.value, num_bytes = self.num_bytes, kernel=self.kernel)
            else:
                value = None
                try:
                   value = int(op1,16)
                except:
                   pass
                if value is not None:
                    ''' stumped, constant loaded into memory '''
                    self.lgr.debug('findKernelWrite backOneAlone, found constant %x, stumped' % value)
                    SIM_run_alone(self.cleanup, False)
                    self.top.skipAndMail()
        elif instruct[1].startswith('rep movs') or instruct[1].startswith('movs'):
            #copy_addr, offset, mark = self.dataWatch.getMarkCopyOffset(self.addr)
            #if copy_addr is not None:
            #    self.lgr.debug('findKernelWrite backOneAlone got copy mark addr 0x%x offset 0x%x' % (copy_addr, offset))
            #else:
            if True:
                src_addr = self.mem_utils.getRegValue(self.cpu, 'esi')
                dst_addr = self.mem_utils.getRegValue(self.cpu, 'edi')
                ecx = self.mem_utils.getRegValue(self.cpu, 'ecx')
                num_bytes = 1
                if 'movsw' in instruct[1]:
                    num_bytes = 4
                elif 'movsd' in instruct[1]:
                    num_bytes = 8
                if 'rep' in instruct[1]:
                    self.lgr.debug('findKernelWrite backOneAlone rep mov esi 0x%x edi 0x%x num_bytes %d, ecx: 0x%x addr 0x%x' % (src_addr, dst_addr, num_bytes, ecx, self.addr))
                else:
                    self.lgr.debug('findKernelWrite backOneAlone esi 0x%x edi 0x%x num_bytes %d, addr 0x%x' % (src_addr, dst_addr, num_bytes, self.addr))
                if self.prev_buffer:
                    # we are just looking for the previous buffer, e.g., to backtrack to a kernel buffer.
                    self.k_buffer_addrs.append(src_addr)
                    if True or len(self.k_buffer_addrs) > 2:
                        SIM_run_alone(self.cleanup, False)
                        self.lgr.debug('got rep movs.. with prev_buffer set, call rev_to_call to callback with address 0x%x' % src_addr)
                        self.rev_to_call.cleanup(self.k_buffer_addrs)
                    else:
                        self.top.stopAtKernelWrite(src_addr, self.rev_to_call, kernel=self.kernel, prev_buffer=self.prev_buffer, num_bytes=num_bytes)
                else:
                    self.top.stopAtKernelWrite(src_addr, self.rev_to_call, kernel=self.kernel, prev_buffer=self.prev_buffer, num_bytes=num_bytes)
        
        elif mn == 'push':
            op1, op0 = self.decode.getOperands(instruct[1])
            self.lgr.debug('findKernelWrite backOneAlone push op0 is %s' % op0)
            if self.decode.isReg(op0): 
                self.lgr.debug('findKernelWrite backOneAlone is push reg %s, find mod', op0)
                self.rev_to_call.doRevToModReg(op0, taint=taint, value=self.value, num_bytes = self.num_bytes, kernel=self.kernel)
            else:
                new_address = self.decode.getAddressFromOperand(self.cpu, op0, self.lgr)
                self.lgr.debug('findKernelWrite backOneAlone is push addr 0x%x', new_address)
                self.top.stopAtKernelWrite(new_address, self.rev_to_call, kernel=self.kernel, prev_buffer=self.prev_buffer)

        elif self.cpu.architecture.startswith('arm') and mn.startswith('stm'):
            reg = self.decode.armSTM(self.cpu, instruct[1], self.addr, self.lgr)
            self.lgr.debug('back from armSTM reg: %s cycle 0x%x' % (reg, self.cpu.cycles))
            if reg is not None:
                rval = self.mem_utils.getRegValue(self.cpu, reg)
                self.lgr.debug('findKernelWrite backOneAlone is stm... reg %s, find mod to 0x%x' % (reg, rval))
                self.rev_to_call.doRevToModReg(reg, taint=taint, value=self.value, num_bytes = self.num_bytes, kernel=self.kernel)
        elif self.cpu.architecture.startswith('arm') and (mn.startswith('str') or (mn.startswith('stu'))):
            reg = self.decode.armSTR(self.cpu, instruct[1], self.addr, self.lgr)
            if reg is not None:
                self.lgr.debug('findKernelWrite backOneAlone is str... reg %s, find mod', reg)
                self.rev_to_call.doRevToModReg(reg, taint=taint, value=self.value, num_bytes = self.num_bytes, offset=offset, kernel=self.kernel)

        else:
            self.lgr.debug('findKernelWrite backOneAlone, cannot track values back beyond %s' % str(instruct))
            SIM_run_alone(self.cleanup, False)
            self.top.skipAndMail()

    def cleanup(self, dumb = False):
        self.lgr.debug('findKernelWrite cleanup')
        self.found_kernel_write = False
        if self.kernel_write_break is not None:
            self.lgr.debug('findKernelWrite cleanup deleting hap and breakpoint %d' % self.kernel_write_break)
            self.reverse_mgr.SIM_delete_breakpoint(self.kernel_write_break)
            self.kernel_write_break = None
        if self.stop_write_hap is not None:
            self.lgr.debug('findKernelWrite cleanup delete stop_write_hap')
            self.top.RES_delete_stop_hap(self.stop_write_hap)
            self.stop_write_hap = None
        if self.mem_hap is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.mem_hap)
            self.mem_hap = None
        if self.forward_break is not None:
            self.lgr.debug('cleanup delete forward break')
            RES_delete_breakpoint(self.forward_break)
            self.forward_break = None
        if self.forward_hap is not None:
            self.lgr.debug('cleanup delete forward_hap %d' % self.forward_hap)
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.forward_hap)
            self.forward_hap = None
                
    def revWriteCallbackSim7(self, memory, dumb, dum1, dumb2):
        if type(memory) is int:
            self.lgr.debug('findKernelWrite failed to find write')
            print('failed to find write to address')
        else:
            self.lgr.debug('findKernelWrite revWriteCallbackSim7 memory 0x%x' % memory.logical_address)
            SIM_run_alone(self.cleanup, False)
            self.memory_transaction = memory
            SIM_run_alone(self.context_manager.enableAll, None)
            #self.vt_handler(memory)
            self.stop_cycles = self.cpu.cycles
            SIM_run_alone(self.thinkWeWrote, 0)
