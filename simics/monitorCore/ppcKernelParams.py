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
Get PowerPC kernel parameters: kernel entry; kernel exit and current_task.
Then calls back to getKernelParams for the rest.
'''
from simics import *
from resimHaps import RES_delete_mode_hap, RES_delete_mem_hap, RES_delete_stop_hap
class PPCKernelParams():
    def __init__(self, top, cpu, cell, mem_utils, reverse_manager, skip_to_mgr, lgr):
        self.mem_utils = mem_utils
        self.reverse_manager = reverse_manager
        self.skip_to_mgr = skip_to_mgr
        self.cpu = cpu
        self.cell = cell
        self.lgr = lgr
        self.top = top
        self.mode_hap = None
        self.kernel_start = 0xc0000000
        self.kernel_len = 0x20000000
        self.kernel_break = None
        self.kernel_hap = None
        self.super_enter_cycle = None
        self.stop_hap = None
        self.hits = {}
        self.kernel_exit = []
        self.kernel_entry = None
        self.compute_jump = None
        self.is_syscall = False
        self.exit_count = 0

    def getParams(self):
        self.reverse_manager.enableReverse()
        self.setModeHap()
 
    def modeChanged(self, cpu, one, old, new):
        pc = self.mem_utils.getRegValue(self.cpu, 'pc')
        if new == Sim_CPU_Mode_Supervisor:
            self.lgr.debug('ppcKernelParam modeChanged supervisor pc 0x%x cycle: 0x%x' % (pc, self.cpu.cycles))
            self.super_enter_cycle = self.cpu.cycles
            self.deleteModeHap()
            SIM_run_alone(self.setKernelBreak, None)
        else:
            self.lgr.debug('ppcKernelParam modeChanged user pc 0x%x' % (pc))

    def setModeHap(self):
        self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChanged, None)
        SIM_continue(0)

    def deleteModeHap(self):
        if self.mode_hap is not None:
            hap = self.mode_hap
            SIM_run_alone(RES_delete_mode_hap, hap)
            self.mode_hap = None

    def setKernelBreak(self, dumb):
        self.kernel_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.kernel_start, self.kernel_len, 0)
        self.kernel_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.kernelHap, None, self.kernel_break)

    def kernelHap(self, dumb, the_object, break_num, memory):
        if self.kernel_hap is None:
            return
        pc = self.mem_utils.getRegValue(self.cpu, 'pc')
        self.lgr.debug('ppcKernelParam kernelHap pc 0x%x' % pc)
        self.deleteKernelHap()
        SIM_run_alone(self.setKernelStop, None)

    def deleteKernelHap(self):
        if self.kernel_break is not None:
            SIM_delete_breakpoint(self.kernel_break)
            self.kernel_break = None
            hap = self.kernel_hap
            SIM_run_alone(RES_delete_mem_hap, hap)

    def setKernelStop(self, dumb):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.kernelStopHap, None)
        SIM_break_simulation('in kernel')

    def kernelStopHap(self, dumb, one, exception, error_string):
        self.lgr.debug('kernelStopHap')
        if self.stop_hap is None: 
            return
        self.delKernelStopHap()
        SIM_run_alone(self.kernelAlone, None)

    def kernelAlone(self, dumb):
        here = self.cpu.cycles
        kernel_enter_pc = self.mem_utils.getRegValue(self.cpu, 'pc')
        self.skip_to_mgr.skipToTest(self.super_enter_cycle)
        pc = self.mem_utils.getRegValue(self.cpu, 'pc')
        instruct = SIM_disassemble_address(self.cpu, pc, 1, 0)
        self.lgr.debug('ppcKernelParam kernelAlone pc 0x%x cycle: 0x%x' % (pc, self.cpu.cycles))
        if instruct[1] == 'sc':
            if self.kernel_entry is None:
                self.kernel_entry = kernel_enter_pc
            SIM_continue(100)
            if self.compute_jump is None:
                self.findCompute(here)
            r2 = self.mem_utils.getRegValue(self.cpu, 'r2')
            self.lgr.debug('ppcKernelParam kernelAlone back from continue 100 r2 is 0x%x' % r2)
            if r2 in self.hits:
                self.lgr.debug('ppcKernelParam kernelAlone already have task_rec 0x%x in hits, try again' % r2)
                self.skip_to_mgr.skipToTest(here)
                self.setModeHap()
            else:         
                self.lgr.debug('ppcKernelParam kernelAlone r2 0x%x is new, search for it' % r2)
                self.hits[r2] = []
                self.searchCurrentTaskAddr(r2)
                single = self.findSingle()
                if single is not None:
                    # We have the the current_task pointer address.  Move on to finding kernel syscall exit adresses
                    self.lgr.debug('ppcKernelParm thinks current task ptr is at 0x%x' % single)
                    self.current_task = single
                    phys_block = self.cpu.iface.processor_info.logical_to_physical(self.current_task, Sim_Access_Read)
                    self.current_phys_addr = phys_block.address
                    self.setModeExitHap() 
                elif len(self.hits[r2]) == 0:
                    self.lgr.error('No hits???')
                    return
                else:
                    self.lgr.debug('ppcKernelParam len of hits for 0x%x is %d, but no unique, try again' % (r2, len(self.hits[r2])))
                    self.skip_to_mgr.skipToTest(here)
                    self.setModeHap()
        else:
            self.lgr.debug('ppcKernelParam kernelAlone Was not sc instruction, try again')
            self.skip_to_mgr.skipToTest(here)
            self.setModeHap()

    def findCompute(self, kernel_enter_cycle):
        # ori r10,r10,0x84cc
        restore_cycle = self.cpu.cycles
        self.skip_to_mgr.skipToTest(kernel_enter_cycle)
        pc = self.mem_utils.getRegValue(self.cpu, 'pc')
        for i in range(100):
            pc = pc + 4
            instruct = SIM_disassemble_address(self.cpu, pc, 1, 0)
            if instruct[1].startswith('ori r10,r10'):
                self.lgr.debug('ppcKernelParam findCompute instruct is %s' % instruct[1])
                val_string = instruct[1].split(',')[2]
                self.compute_jump = int(val_string, 16) | 0xc0000000
                break

    def findSingle(self):
        retval = None
        hit_list = []
        for tr in self.hits:
            for hit in self.hits[tr]:
                if hit not in hit_list:
                    hit_list.append(hit)
        self.lgr.debug('ppcKernelParam findSingle %d hits' % len(hit_list))
        if len(hit_list) == 1:
            retval =  hit_list[0]
        else:
            singles = []
            for hit in hit_list:
                in_all = True
                for tr in self.hits:
                    if hit not in self.hits[tr]: 
                        in_all = False
                        break
                if in_all:
                    singles.append(hit)
            if len(singles) == 1:
                retval = singles[0]
        return retval

    def delKernelStopHap(self):
        if self.stop_hap is not None:
            hap = self.stop_hap
            SIM_run_alone(RES_delete_stop_hap, hap)
            self.stop_hap = None

    def searchCurrentTaskAddr(self, cur_task):
        ''' Look for the Linux data addresses corresponding to the current_task symbol 
            starting at 0xc0000000.  Record each address that contains a match,
            and that list will be reduced later. 
        '''
        start = 0xc0000000
        self.lgr.debug('ppcKernelParam searchCurrentTaskAddr task for task 0x%x start at: 0x%x' % (cur_task, start))
        phys_block = self.cpu.iface.processor_info.logical_to_physical(start, Sim_Access_Read)
        addr = phys_block.address
        self.lgr.debug('start search phys addr addr 0x%x' % addr)
        got_count = 0
        offset = 0
        print('Searching memory for 0x%x, please wait.' % cur_task)
        for i in range(14000000):
            val = None
            try:
                val = SIM_read_phys_memory(self.cpu, addr, 4)
            except:
                pass
            if val is None:
                self.lgr.error('got None at 0x%x' % addr)
                return 
            if val == cur_task:
                vaddr = start+offset
                self.lgr.debug('got match at addr: 0x%x vaddr: 0x%x offset 0x%x ' % (addr, vaddr, offset))
                self.hits[cur_task].append(vaddr)
                got_count += 1
                #break
            if got_count == 9999:
                self.lgr.error('exceeded count')
                break
            #print('got 0x%x from 0x%x' % (val, addr))
            addr += 4
            offset += 4
        self.lgr.debug('Done with search, final addr is 0x%x num hits %d num different tasks %d' % ((start+offset), len(self.hits[cur_task]), len(self.hits)))
        print('Done with search, final addr is 0x%x num hits %d num different tasks %d' % ((start+offset), len(self.hits[cur_task]), len(self.hits)))

    def setModeExitHap(self):
        ''' Find syscall exit addresses.  We are in the kernel via a syscall. '''
        self.is_syscall = True
        self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChangedExit, None)
        self.setSyscallBreak()

        SIM_continue(0)

    def modeChangedExit(self, cpu, one, old, new):
        if new != Sim_CPU_Mode_Supervisor and self.is_syscall:
            # exiting to user space. If this is a new exit address, record it
            pc = self.mem_utils.getRegValue(self.cpu, 'pc')
            if pc not in self.kernel_exit:
                self.kernel_exit.append(pc)
                self.lgr.debug('ppcKernelParam modeChangedGetExit user new exit pc 0x%x' % (pc))
            if self.exit_count > 10000 or len(self.kernel_exit)>1:
                self.deleteModeExitHap()
                SIM_run_alone(self.setExitStop, None)
                self.deleteKernelHap()
                if len(self.kernel_exit) < 2:
                    print('ERROR ******* failed to get 2 syscall exits')
            else:
                self.exit_count += 1
            self.is_syscall = False

    def deleteModeExitHap(self):
        if self.mode_hap is not None:
            hap = self.mode_hap
            SIM_run_alone(RES_delete_mode_hap, hap)
            self.mode_hap = None

    def setExitStop(self, dumb):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.exitStopHap, None)
        SIM_break_simulation('got exit')

    def exitStopHap(self, dumb, one, exception, error_string):
        self.lgr.debug('exitStopHap')
        if self.stop_hap is None: 
            return
        self.delExitStopHap()
        SIM_run_alone(self.recordExitAlone, None)

    def recordExitAlone(self, dumb):
        if len(self.kernel_exit) < 2:
            print('kernel parameters failed to get 2 syscall exits for ppc')
        else:
            self.top.ppcParams(self.kernel_entry, self.kernel_exit, self.current_task, self.current_phys_addr, self.compute_jump)

    def delExitStopHap(self):
        if self.stop_hap is not None:
            hap = self.stop_hap
            SIM_run_alone(RES_delete_stop_hap, hap)
            self.stop_hap = None

    def setSyscallBreak(self, dumb=None):
        self.kernel_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.kernel_entry, 1, 0)
        self.kernel_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.syscallHap, None, self.kernel_break)

    def syscallHap(self, dumb, the_object, break_num, memory):
        if self.kernel_hap is None:
            return
        pc = self.mem_utils.getRegValue(self.cpu, 'pc')
        #self.lgr.debug('ppcKernelParam syscallHap pc 0x%x' % pc)
        self.is_syscall = True

