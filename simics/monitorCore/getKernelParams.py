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
   Generates a RESim parameter file.  Intended to be invoked by launchKparam.py
   See that script for details.
   Offsets and layouts derived from task_struct defined in sched.h

'''
from simics import *
import simics
import memUtils
import taskUtils
import resimUtils
import kParams
import cellConfig
import pickle
import decode
import os
class GetKernelParams():
    def __init__(self, comp_dict):
        #self.cpu = SIM_current_processor()
        self.cell_config = cellConfig.CellConfig(list(comp_dict.keys()))
        self.target = os.getenv('RESIM_TARGET')
        self.cpu = self.cell_config.cpuFromCell(self.target)
        self.os_type = os.getenv('OS_TYPE')
        if self.os_type is None:
            self.os_type = 'LINUX32'
        word_size = 4
        if self.os_type == 'LINUX64':
            word_size = 8
        print('using target of %s, os type: %s, word size %d' % (self.target, self.os_type, word_size))

        self.log_dir = '/tmp'
        self.lgr = resimUtils.getLogger('getKernelParams', self.log_dir)
        self.lgr.debug('GetKernelParams using target of %s, os type: %s, word size %d' % (self.target, self.os_type, word_size))
        platform = None
        if 'PLATFORM' in comp_dict[self.target]:
            platform = comp_dict[self.target]['PLATFORM']
        self.param = kParams.Kparams(self.cpu, word_size, platform)


        ''' try first without reference to fs when finding current_task.  If that fails in 3 searches,
            try making phys addresses relative to the fs base '''
        self.param.current_task_fs = False

        self.mem_utils = memUtils.memUtils(word_size, self.param, self.lgr, arch=self.cpu.architecture)
        # TBD FIX THIS
        self.data_abort = None
        if self.cpu.architecture == 'arm':
            #obj = SIM_get_object('board')
            obj = SIM_get_object(self.target)
            self.page_fault = 4
            self.data_abort = 1
        else:
            obj = SIM_get_object(self.target)
            self.page_fault = 14
      
        self.cell = obj.cell_context
        print('current processor %s' % self.cpu.name)
        #self.taskUtils = taskUtils.TaskUtils(self.cpu, self.param, self.mem_utils, self.param.current_task, self.lgr)
        ''' NOTE shared between different functions, e.g., entry eip and current task candidates'''
        self.hits = []
        self.trecs = []
        self.idle = None
        self.dumb_count = 0
        self.stop_hap = None
        self.fs_stop_hap = None
        self.fs_start_cycle = None
        ''' how many instructions to look for FS fu '''
        self.fs_cycles = 500
        self.entry_mode_hap = None
        self.page_hap = None
        self.page_hap2 = None
        self.prev_instruct = ''
        self.current_task_phys = None
        self.unistd = comp_dict[self.target]['RESIM_UNISTD']
        self.unistd32 = None
        if 'RESIM_UNISTD_32' in comp_dict[self.target]:
            self.unistd32 = comp_dict[self.target]['RESIM_UNISTD_32']
        ''' don't bother looking for sysenter '''
        self.skip_sysenter = False
        if 'SYSENTER' in comp_dict[self.target]:
            self.lgr.debug('SYSENTER is %s' % comp_dict[self.target]['SYSENTER'])
            if comp_dict[self.target]['SYSENTER'].lower() == 'no':
                self.lgr.debug('will skip sysenter')
                self.skip_sysenter = True

        self.current_pid = None
        self.task_rec_mode_hap = None
        self.current_task_stop = None
 
        self.from_boot = False
        self.try_mode_switches = 0 
        self.init_task = None
        self.fs_base = None
        self.search_count = 0
        self.test_count = 0

    def searchCurrentTaskAddr(self, cur_task):
        ''' Look for the Linux data addresses corresponding to the current_task symbol 
            starting at 0xc1000000.  Record each address that contains a match,
            and that list will be reduced later. 
        '''
        #self.run2Kernel(cpu)
        start = 0xc1000000
        if self.cpu.architecture == 'arm':
            start = 0xc0000000
        self.lgr.debug('searchCurrentTaskAddr task for task 0x%x fs: %r start at: 0x%x' % (cur_task, self.param.current_task_fs, start))
        if self.param.current_task_fs:
            ''' physical address relative to fs_base '''
            self.lgr.debug('searchCurrentTaskAddr orig fs_base: 0x%x current fs_base 0x%x start: 0x%x kernel_base: 0x%x' % (self.fs_base, 
                   self.cpu.ia32_fs_base, start, self.param.kernel_base))
            addr = self.fs_base + (start-self.param.kernel_base)
        else:
            phys_block = self.cpu.iface.processor_info.logical_to_physical(start, Sim_Access_Read)
            addr = phys_block.address
        #print('cmd is %s' % cmd)
        self.lgr.debug('start search phys addr addr 0x%x' % addr)
        got_count = 0
        offset = 0
        for i in range(14000000):
            val = None
            try:
                val = SIM_read_phys_memory(self.cpu, addr, 4)
            except:
                pass
            #self.lgr.debug('val is 0x%x' % val)
            #val = self.mem_utils.readPtr(self.cpu, addr)
            if val is None:
                self.lgr.error('got None at 0x%x' % addr)
                return 
            if val == cur_task:
                if self.param.current_task_fs:
                    #addr = self.fs_base + (vaddr-self.param.kernel_base)
                    vaddr = addr - self.fs_base + self.param.kernel_base
                    self.lgr.debug('got match at addr: 0x%x vaddr: 0x%x offset 0x%x orig fs_base 0x%x now 0x%x' % (addr, vaddr, offset, self.fs_base,
                      self.cpu.ia32_fs_base))
                else:
                    vaddr = start+offset
                    self.lgr.debug('got match at addr: 0x%x vaddr: 0x%x offset 0x%x ' % (addr, vaddr, offset))
 
                self.hits.append(vaddr)
                got_count += 1
                #break
            if got_count == 9999:
                self.lgr.error('exceeded count')
                break
            #print('got 0x%x from 0x%x' % (val, addr))
            addr += 4
            offset += 4
        self.lgr.debug('final addr is 0x%x num hits %d' % ((start+offset), len(self.hits)))

    def checkHits(self, cur_task):
        ''' look at previously generated list of candidate current_task addresses and remove any
            that do not contain the given cur_task '''
        self.lgr.debug('checkHits cur_task is 0x%x' % cur_task)
        copy_hits = list(self.hits)
        for hit in copy_hits:

            if self.param.current_task_fs:
                addr = self.fs_base + (hit-self.param.kernel_base)
            else:
                phys_block = self.cpu.iface.processor_info.logical_to_physical(hit, Sim_Access_Read)
                addr = phys_block.address

            val = SIM_read_phys_memory(self.cpu, addr, 4)
            if val != cur_task:
                self.lgr.debug('checkHits hit at 0x%x, removing because cur_task 0x%x does not equal val 0x%x ' % (hit, cur_task, val))
                self.hits.remove(hit)
        if len(self.hits) > 0 and len(self.hits) < 3:
            for hit in self.hits:
                self.lgr.debug('hit: 0x%x' % hit)
            self.param.current_task = self.hits[0]
            self.lgr.debug('checkHits remaining hits < 3, assigned 0x%x' % self.hits[0])
            SIM_run_alone(self.delTaskModeAlone, None)
           

    def delTaskModeAlone(self, dumb): 
        if self.task_rec_mode_hap is not None:
            SIM_hap_delete_callback_id("Core_Mode_Change", self.task_rec_mode_hap)
            self.task_rec_mode_hap = None


    def taskModeChanged32(self, cpu, one, old, new):
        if self.task_rec_mode_hap is None:
            return
        ''' find the current_task record pointer ''' 
        if new == Sim_CPU_Mode_Supervisor:
            eip = self.mem_utils.getRegValue(self.cpu, 'eip')
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            self.lgr.debug('taskModeChanged32 eip 0x%x %s' % (eip, instruct[1]))
            if 'illegal' in instruct[1]:
                self.lgr.debug('taskModeChanged32 page fault, continue')
            elif 'sys' not in instruct[1] and 'int' not in instruct[1]:
                self.lgr.debug('taskModeChanged32 not a syscall, page fault, continue')
            else:
                self.lgr.debug('taskModeChanged32 must be a call, look for FS')
                self.lookForFS(None)
        else:
           pass

    def taskModeChanged64(self, cpu, one, old, new):
        if self.task_rec_mode_hap is None:
            return
        ''' find the current_task record pointer ''' 
        if new == Sim_CPU_Mode_Supervisor:
            eip = self.mem_utils.getRegValue(self.cpu, 'eip')
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            self.lgr.debug('taskModeChanged64 eip 0x%x %s' % (eip, instruct[1]))
            if 'illegal' in instruct[1]:
                self.lgr.debug('taskModeChanged64 page fault, continue')
            elif 'sys' not in instruct[1] and 'int' not in instruct[1]:
                self.lgr.debug('taskModeChanged64 not a syscall, page fault, continue')
            else:
                SIM_run_alone(self.delTaskModeAlone, None)
                SIM_break_simulation('got it?')
                ''' TBD not done yet'''
        else:
           pass

    def getCurrentTaskPtr(self):
        ''' Find the current_task address.  Method varies by cpu type '''
        print('Searching for current_task, this may take a moment...')
        self.idle = None
        if self.cpu.architecture == 'arm':
            self.param.current_task_fs = False
        if self.mem_utils.WORD_SIZE == 4:
            ''' use mode haps and brute force search for values that match the current task value '''
            #self.task_rec_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.taskModeChanged, self.cpu)
            self.task_rec_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.taskModeChanged32, self.cpu)
            self.current_task_stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.currentTaskStopHap, None)
            #self.current_task_stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.supervisor32StopHap, None)
            self.lgr.debug('getCurrentTaskPtr added mode and stop haps')
            self.continueAhead()
        else:
            self.task_rec_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.taskModeChanged64, self.cpu)
            #self.current_task_stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.currentTaskStopHap, None)
            self.lgr.debug('getCurrentTaskPtr added mode and stop haps')
            self.continueAhead()

            '''
            gs_b700 = self.mem_utils.getGSCurrent_task_offset(self.cpu)
            self.param.current_task = self.mem_utils.getUnsigned(gs_b700)
            self.param.current_task_phys = self.mem_utils.v2p(self.cpu, gs_b700)
            self.current_task = self.param.current_task
            self.current_task_phys = self.param.current_task_phys
            gs_base = self.cpu.ia32_gs_base
            self.lgr.debug('64-bit gs_base is 0x%x  gs_b700 0x%x current_task at 0x%x  phys 0x%x' % (gs_base, gs_b700, self.param.current_task, self.param.current_task_phys))
            self.findSwapper()
            '''

    def delCurrentTaskStopHap(self, dumb):
        if self.current_task_stop_hap is not None:
            self.lgr.debug('delCurrrentTaskStopHap')
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.current_task_stop_hap)
            self.current_task_stop_hap = None

    def fsEnableReverse(self, dumb):
            self.deleteHaps(None)
            self.delCurrentTaskStopHap(None)
            self.delTaskModeAlone(None)
            SIM_run_command('enable-reverse-execution')

            self.fs_start_cycle = self.cpu.cycles
            self.lgr.debug('fsEnableReverse, , now continue %d cycles' % self.fs_cycles)
            ''' tbd point of going forward?'''
            SIM_continue(self.fs_cycles)
            self.fsFindAlone()

    def currentTaskStopHap(self, dumb, one, exception, error_string):
        if self.current_task_stop_hap is None:
            return
        if self.fs_stop_hap:
            self.lgr.debug('currentTaskStopHap, fs_stop_hap is true')
            SIM_run_alone(self.fsEnableReverse, None)
        
        elif self.param.current_task is None:
            self.lgr.debug('currentTaskStopHap, but no current_task yet, assume mem map fu')
        else:
            SIM_run_alone(self.delTaskModeAlone, None)
            SIM_run_alone(self.delCurrentTaskStopHap, None)
            self.lgr.debug('currentTaskStopHap, now call findSwapper')
            self.findSwapper()
            SIM_run_alone(self.continueAhead, None)

    def fsFindAlone(self):
        self.lgr.debug('fsFindAlone, fs_cycles is %d' % self.fs_cycles)
        for i in range(1,self.fs_cycles):
            resimUtils.skipToTest(self.cpu, self.fs_start_cycle+i, self.lgr)
            eip = self.mem_utils.getRegValue(self.cpu, 'eip')
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            if 'fs:' in instruct[1]:
                prefix, addr = decode.getInBrackets(self.cpu, instruct[1], self.lgr) 
                print('got addr %s from %s' % (addr, instruct[1]))
                addr = int(addr, 16)
                self.fs_base = self.cpu.ia32_fs_base
                self.param.current_task_fs  = True
                self.param.fs_base = self.fs_base
                self.param.current_task = addr
                self.lgr.debug('fs_base: 0x%x current_task is 0x%x ' % (self.fs_base, self.param.current_task))
                phys = self.fs_base + (self.param.current_task-self.param.kernel_base)
                self.lgr.debug('phys of current_task is 0x%x' % phys)
                self.current_task_phys = phys
                SIM_run_command('disable-reverse-execution')
                self.findSwapper()
                break
                
    def lookForFS(self, dumb):
         self.lgr.debug('lookForFS')
         ''' will piggy back on the currentTaskStopHap'''
         self.fs_stop_hap = True
         self.param.current_task = None
         SIM_break_simulation('fs stop')
       

    def taskModeChanged(self, cpu, one, old, new):
        ''' search kernel memory for the current_task address that seems to match
            the task address found for the current process '''
        if self.task_rec_mode_hap is None:
            return
        ''' find the current_task record pointer ''' 
        if self.try_mode_switches < 900000:
            self.try_mode_switches += 1
            if new == Sim_CPU_Mode_Supervisor:
                eip = self.mem_utils.getRegValue(self.cpu, 'eip')
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                self.lgr.debug('entering sup mode eip: 0x%x  instruct: %s' % (eip, instruct[1]))
                #SIM_break_simulation('remove this')
                #return
                ta = self.mem_utils.getCurrentTask(self.cpu)
                if ta is None or ta == 0:
                    self.lgr.debug('ta nothing, continue')
                    #SIM_break_simulation('remove this')
                    #return
                if ta < self.param.kernel_base:
                    self.lgr.debug('ta 0x%x less than base 0x%x   return?' % (ta, self.param.kernel_base))
                    #SIM_break_simulation('no soap')
                    if instruct[1] == 'sysenter':
                        SIM_run_alone(self.lookForFS, None)
                        return
                else:
                    self.from_boot = True
                self.lgr.debug('ta is 0x%x' % ta)
                #tmp_pid = self.mem_utils.readWord32(self.cpu, ta+260)
                #print('pid is %d' % tmp_pid)
                if ta not in self.trecs:
                    if len(self.hits) == 0:
                        self.lgr.debug('getCurrentTaskPtr search current for ta 0x%x' % ta)
                        self.searchCurrentTaskAddr(ta)
                        self.trecs.append(ta)
                        if self.param.current_task_fs and not self.from_boot and (len(self.hits) > 0 and len(self.hits)<3):
                            self.lgr.debug('getCurrentTaskPtr after searchCurrentTaskAdd adding trec 0x%x' % ta)
                            ''' maybe older kernel, we assumed those with fs relative will have many hits '''
                            self.hits = []
                            self.lgr.debug('getCurrentTaskPtr set current_task_fs to False')
                            self.param.current_task_fs = False
                            self.searchCurrentTaskAddr(ta)
                        if not self.param.current_task_fs and self.param.current_task is None:
                            self.search_count += 1
                            self.lgr.debug('getCurrentTaskPtr added to search count, now %d' % self.search_count)
                            if self.search_count > 3:
                                self.param.current_task_fs = True
                 
                    else:
                        self.lgr.debug('getCurrentTaskPtr adding trec 0x%x' % ta)
                        self.trecs.append(ta)
                        self.lgr.debug('checkHits with new ta 0x%x' % ta)
                        self.checkHits(ta)

            else:
                ta = self.mem_utils.getCurrentTask(self.cpu)
                self.lgr.debug('user mode? ta is %s' % str(ta))
                #SIM_break_simulation('user mode')
                return

        elif len(self.hits) > 2 and new == Sim_CPU_Mode_Supervisor:
            ''' do not leave unless in kernel '''
            ''' maybe in tight application loop, assume second to last entry based on observations '''
            self.param.current_task = self.hits[-2]
            self.lgr.debug('assuming 2nd to last for current_task 0x%x' % self.param.current_task)
            SIM_run_alone(self.delTaskModeAlone, None)
        if self.param.current_task is not None:
            self.lgr.debug('getCurrentTaskPtr got current task')
            if self.param.current_task_fs:
                phys = self.fs_base + (self.param.current_task-self.param.kernel_base)
                self.lgr.debug('findSwapper use fs_base phys of current_task 0x%x is 0x%x' % (self.param.current_task, phys))
            else:
                #phys_block = self.cpu.iface.processor_info.logical_to_physical(self.param.current_task, Sim_Access_Read)
                #phys = phys_block.address
                phys = self.mem_utils.v2p(self.cpu, self.param.current_task)
                self.lgr.debug('findSwapper phys of current_task 0x%x is 0x%x' % (self.param.current_task, phys))
            self.current_task_phys = phys
            self.lgr.debug('findSwapper got current task 0x%x phys: 0x%x' % (self.param.current_task, phys))
            SIM_break_simulation('got current task 0x%x phys: 0x%x' % (self.param.current_task, phys))
            

    def isThisSwapper(self, task):
        real_parent_offset = 0
        maybe=[]
        for i in range(800):
            #self.lgr.debug('isThisSwapper read from 0x%x' % ((task + real_parent_offset)))
            test_task = self.mem_utils.readPtr(self.cpu, task + real_parent_offset)
            test_task1 = self.mem_utils.readPtr(self.cpu, task + real_parent_offset+self.mem_utils.WORD_SIZE)
            if test_task == task and test_task1 == task:
                self.lgr.debug('isThisSwapper found match 0x%x ' % test_task)
                maybe.append(real_parent_offset)
                #return real_parent_offset
                real_parent_offset += self.mem_utils.WORD_SIZE
            else:
                #if test_task is not None and test_task1 is not None:
                #    self.lgr.debug('loop %d task was 0x%x test_task 0x%x test_task1 0x%x' % (i, task, test_task, test_task1))
                #else:
                #    self.lgr.debug('test task was None')
                #real_parent_offset += self.mem_utils.WORD_SIZE
                real_parent_offset += 4
        if len(maybe)>0:
            self.lgr.debug('last match for real parent 0x%x from count %d' % (maybe[-1], len(maybe)))
            return maybe[-1]
        return None

    def getOff(self, words):
        return words * self.mem_utils.WORD_SIZE

    def isSwapper(self, task): 
        ''' look for what might be a real_parent and subsequent parent pointer fields that point to the
            given task.  if found, assume this is swaper and record those offsets.'''
        self.lgr.debug('isSwapper check task 0x%x ' % (task))
        real_parent_offset = self.isThisSwapper(task)
        if real_parent_offset is not None:
            self.lgr.debug('isSwapper (maybe) real_parent at 0x%x looks like swapper at 0x%x' % (real_parent_offset, task))
            self.idle = task
            self.param.ts_real_parent = real_parent_offset
            self.param.ts_parent = real_parent_offset + self.getOff(1)
            self.param.ts_children_list_head = real_parent_offset + self.getOff(2)
            self.param.ts_sibling_list_head = real_parent_offset + self.getOff(4)
            self.param.ts_group_leader = real_parent_offset + self.getOff(6)
            # pidtype_max is 3?  pid_link is hlist_node and pointer.  hlist_node is two pointers.  total 4 words x 3 is 12 words?
            # no idea how we get 8 words from group leader...  works on arm
            self.param.ts_thread_group_list_head = self.param.ts_group_leader+self.getOff(14)

            parent = self.mem_utils.readPtr(self.cpu, task+self.param.ts_parent) 
            group_leader = self.mem_utils.readPtr(self.cpu, task+self.param.ts_group_leader) 
            ''' will confirm is swapper and will set init_task and ts_next '''
            self.getNextOffset() 
            if self.param.ts_next is None:
                return None
        return real_parent_offset
      
    def getInitAlone(self, dumb): 
        result = self.getInit()
        if result != 0:
            self.lgr.error('error from getInit')
            return
        self.lgr.debug('back from getInit, now call checkTasks')
        self.checkTasks()
        self.lgr.debug('back from checkTasks')
        SIM_run_alone(self.checkKernelEntry, None)

    def swapperStopHap(self, dumb, one, exception, error_string):
        self.lgr.debug('swapperStopHap')
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_hap)
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        SIM_run_alone(self.getInitAlone, None)

    def changedThread(self, cpu, third, forth, memory):
        #self.lgr.debug('changed thread')
        ''' does the current thread look like swapper? would have consecutive pointers to itself '''
        if self.task_break is None:
            return
        cur_task = SIM_read_phys_memory(self.cpu, self.current_task_phys, self.mem_utils.WORD_SIZE)
        if cur_task not in self.trecs:
            self.trecs.append(cur_task)
            self.lgr.debug('changedThread try task 0x%x' % cur_task)
            #xcom = cur_task+0x5a0 
            #comm = self.mem_utils.readString(self.cpu, xcom, 16)
            #print('comm: %s' % comm)
            #SIM_break_simulation('remove this')
            #self.lgr.debug('changedThread did break simulation')
            #return

            if cur_task != 0 and self.isSwapper(cur_task) is not None:
                self.lgr.debug('changedThread found swapper 0x%x  real_parent %d' % (self.idle, self.param.ts_real_parent))
                SIM_break_simulation('found swapper')
                SIM_delete_breakpoint(self.task_break)
                self.task_break = None 

    def findSwapper(self):
        self.trecs = []
        pcell = self.cpu.physical_memory
        self.task_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, self.current_task_phys, self.mem_utils.WORD_SIZE, 0)
        self.task_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.changedThread, self.cpu, self.task_break)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.swapperStopHap, None)
        self.lgr.debug('findSwapper set break at 0x%x (phys 0x%x) and callback, now continue' % (self.param.current_task, self.current_task_phys))
        self.continueAhead()
    
    def runUntilSwapper(self):
        ''' run until it appears that the swapper is running.  Will set self.idle, real_parent, siblings '''
        ''' Will first find the current_task adress if not already set '''
        self.lgr.debug('runUntilSwapper')
        if self.param.current_task is None:
            self.lgr.debug('will get Current Task Ptr, may take a minute')
            self.getCurrentTaskPtr()
        else: 
            self.lgr.warning('Using existing Current Task ptr of 0x%x' % self.param.current_task)
            self.findSwapper()
    
    def getNextOffset(self): 
        swapper_child = self.mem_utils.readPtr(self.cpu, self.idle+self.param.ts_children_list_head) 
        self.lgr.debug('getInit swapper_child_next is 0x%x  sib %d' % (swapper_child, self.param.ts_sibling_list_head))
        init = swapper_child - self.param.ts_sibling_list_head
        self.lgr.debug('getInit init is 0x%x' % init)
        next_offset = 20
        #self.lgr.debug('getInit real next is %d' % self.real_param.ts_next)
        for i in range(800):
            swap_next_value = self.mem_utils.readPtr(self.cpu, self.idle + next_offset) 
            swap_next = swap_next_value - next_offset
            #self.lgr.debug('getInit look for 0x%x swap_next_value 0x%x swap_next 0x%x' % (init, swap_next_value, swap_next))
            if swap_next == init:
                self.param.ts_next = next_offset
                self.param.ts_prev = next_offset + self.mem_utils.WORD_SIZE
                self.init_task = init
                self.lgr.debug('getInit think next is %d ts_next %d  ts_prev %d' % (next_offset, self.param.ts_next, self.param.ts_prev))
                break
            else:
                next_offset += 4
        if self.param.ts_next is None:
            self.lgr.debug('failed to find ts_next')

    def findComm(self, task):
        got_comm = False
        self.lgr.debug('getInit look for comm from task 0x%x' % (task))
        comm_offset = self.param.ts_pid+8
        #self.lgr.debug('getInit real comm at %d' % (self.real_param.ts_comm))
        for i in range(800):
            comm = self.mem_utils.readString(self.cpu, task+comm_offset, 16)
            if comm.startswith('init') or comm.startswith('systemd') or comm.startswith('linuxrc') or comm.startswith('swapper'):
                self.lgr.debug('getInit found comm %s at %d' % (comm, comm_offset))
                self.param.ts_comm = comm_offset
                got_comm = True
                break
            else:
                self.lgr.debug('offset %d comm: %s' % (comm_offset, comm))
                pass
            comm_offset += 4
        self.lgr.debug('getInit out of comm loop')
        return got_comm
    

    def getInit(self):
        ''' Assuming we have swapper in init.idle, find init and use it to locate
            next, prev, pid and comm '''
        #print('real_parent is %d  children %d' % (self.param.ts_real_parent, self.param.ts_children_list_head))
        ''' loop until we have a child of the init process '''
        if self.init_task is None:
            self.lgr.error('getInit no init_task, bail')
            return 1

        init_has_child = False
        test_val = 0x5000
        while not init_has_child:   
            init_next_ptr = self.mem_utils.readPtr(self.cpu, self.init_task + self.param.ts_next) 
            delta = abs(self.init_task - init_next_ptr)
            self.lgr.debug('getInit ts_next %d  ptr 0x%x delta 0x%x' % (self.param.ts_next, init_next_ptr, delta))
            if self.mem_utils.getUnsigned(delta) < test_val:
                self.lgr.debug('got second proc')
                init_has_child = True
            else:
                self.lgr.debug('only one proc, continue')
                SIM_run_command('c 500000') 


        #self.lgr.debug('getInit real pid is %d' % self.real_param.ts_pid)
        init_next_ptr = self.mem_utils.readPtr(self.cpu, self.init_task + self.param.ts_next) 
        init_next = init_next_ptr - self.param.ts_next
        self.lgr.debug('getInit ts_next %d  ptr 0x%x init_next is 0x%x' % (self.param.ts_next, init_next_ptr, init_next))
        pid_offset = 0
        init_pid = 0
        next_pid = 0
        for i in range(800):
            init_pid = self.mem_utils.readWord32(self.cpu, self.init_task+pid_offset)
            next_pid = self.mem_utils.readWord32(self.cpu, init_next+pid_offset)
            next_next_pid = self.mem_utils.readWord32(self.cpu, next_pid+pid_offset)
            init_pid_g = self.mem_utils.readWord32(self.cpu, self.init_task+pid_offset+4)
            next_pid_g = self.mem_utils.readWord32(self.cpu, init_next+pid_offset+4)
            #if init_pid == 1 and init_pid_g ==1 and ((next_pid == 2 and next_pid_g == 2) or (next_pid == 0 and next_pid_g == 0)):
            if init_pid == 1 and init_pid_g ==1 and ((next_pid == 2 and next_pid_g == 2)):
                self.lgr.debug('getInit looking for pid, got 1 at offset %d  next_pid %d' % (pid_offset, next_pid))
                self.param.ts_pid = pid_offset
                self.param.ts_tgid = pid_offset+4
                break
            else:
                #self.lgr.debug('looking for pid offset %d init_pid of %d next_pid %d init_pid_g %d  next_pid_g %d' % (pid_offset, init_pid, next_pid, init_pid_g, next_pid_g))
                pass
            pid_offset += 4
         
        if self.param.ts_pid is not None:
            got_comm = self.findComm(self.idle)
            if not got_comm:
                self.lgr.debug('failed to get comm for idle process, try init')
                got_comm = self.findComm(self.init_task)
            if not got_comm:
                self.lgr.error('failed to find comm')
                return 1
        else:
            self.lgr.error('failed to find ts_pid')
            return 1
        if self.param.ts_comm is None:
            self.lgr.error('Failed t find comm offset')    
        self.lgr.debug('getInit done')
        return 0

    def checkTasks(self):        
        #self.lgr.debug(self.param.getParamString())
        self.taskUtils = taskUtils.TaskUtils(self.cpu, self.target, self.param, self.mem_utils, self.unistd, self.unistd32, None, self.lgr)
        swapper_child = self.mem_utils.readPtr(self.cpu, self.idle+self.param.ts_children_list_head) 
        self.lgr.debug('checkTasks swapper_child_next is 0x%x  sib %d' % (swapper_child, self.param.ts_sibling_list_head))
        init = swapper_child - self.param.ts_sibling_list_head
        ts = self.taskUtils.readTaskStruct(init, self.cpu)
        try:
            self.lgr.debug('checkTasks, init pid is %d' % ts.pid)
        except:
            print(dir(ts))
        self.lgr.debug('now get tasks')
        tasks = self.taskUtils.getTaskStructs()
        plist = {}
        for t in tasks:
            plist[tasks[t].pid] = t 
        for pid in sorted(plist):
            t = plist[pid]
            print('pid: %d task_rec: 0x%x  comm: %s children 0x%x 0x%x' % (tasks[t].pid, t, tasks[t].comm, tasks[t].children[0], tasks[t].children[1]))
        
        
   
    def entryModeChangedARM(self, dumb, one, old, new):
        if self.entry_mode_hap is None:
            return
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        if old == Sim_CPU_Mode_Supervisor:
            ''' leaving kernel, capture address, note instruction cannot be read '''
            if eip not in self.hits:
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                if instruct[1] == '<illegal memory mapping>':
                    self.lgr.debug('entryModeChanged ARM, nothing mapped at eip 0x%x ' % (eip))
                    if self.param.arm_ret is None:
                        self.param.arm_ret = eip
                    elif self.param.arm_ret2 is None:
                        if eip != self.param.arm_ret:
                            self.param.arm_ret2 = eip
                    else:
                        SIM_break_simulation('entryModeChanged found two rets: 0x%x 0x%x' % (self.param.arm_ret, self.param.arm_ret2))
                    
        elif old == Sim_CPU_Mode_User:
            self.dumb_count += 1
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            if self.param.arm_entry is None and instruct[1].startswith('svc 0'):
                self.lgr.debug('mode changed svc old %d  new %d eip: 0x%x %s' % (old, new, eip, instruct[1]))
                self.prev_instruct = instruct[1]
                self.lgr.debug('entryModeChanged ARM found svc 0')
                SIM_break_simulation('entryModeChanged found svc 0')
            elif self.param.arm_entry is None and instruct[1].startswith('svc'):
                self.lgr.debug('mode changed svn 0x9000 old %d  new %d eip: 0x%x %s' % (old, new, eip, instruct[1]))
                self.prev_instruct = instruct[1]
                self.lgr.debug('entryModeChanged ARM found svc 9999..')
                SIM_break_simulation('entryModeChanged found svc 9999')

    def entryModeChanged(self, compat32, one, old, new):
        if self.entry_mode_hap is None:
            return
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        
        dumb, comm, pid = self.taskUtils.curProc() 
        if old == Sim_CPU_Mode_Supervisor and not compat32:
            ''' leaving kernel, capture iret and sysexit '''
            if eip not in self.hits:
                self.hits.append(eip)
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                self.lgr.debug('entryModeChanged pid:%d kernel exit eip 0x%x %s' % (pid, eip, instruct[1]))
                if instruct[1].startswith('iret'):
                    self.param.iretd = eip
                elif instruct[1] == 'sysexit':
                    self.param.sysexit = eip
                elif instruct[1] == 'sysret64':
                    self.param.sysret64 = eip
                
                #if self.mem_utils.WORD_SIZE == 4:     
                if True:
                    if self.param.iretd is not None and self.param.sysexit is not None:
                        self.lgr.debug('entryModeChanged found exits')
                        SIM_break_simulation('found sysexit and iretd')
                '''
                else:
                    if self.param.iretd is not None and self.param.sysexit is not None and self.sysret64 is not None:
                        self.lgr.debug('entryModeChanged found exits')
                        SIM_break_simulation('found sysexit and iretd and sysret64')
                '''
        elif old == Sim_CPU_Mode_User:
            self.dumb_count += 1
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)

            self.prev_instruct = instruct[1]
            self.lgr.debug('entryModeChanged pid:%d supervisor eip 0x%x instruct %s count %d' % (pid, eip, instruct[1], self.dumb_count))

            if self.param.sys_entry is None and instruct[1].startswith('int 128'):
                self.lgr.debug('mode changed old %d  new %d eip: 0x%x %s' % (old, new, eip, instruct[1]))
                self.lgr.debug('entryModeChanged found int 128')
                SIM_break_simulation('found int 128')
            elif self.param.sysenter is None and (instruct[1].startswith('sysenter') or instruct[1].startswith('syscall')):
                self.lgr.debug('mode changed old %d  new %d eip: 0x%x %s' % (old, new, eip, instruct[1]))
                self.lgr.debug('entryModeChanged found sysenter')
                SIM_break_simulation('entryModeChanged found sysenter')
            elif compat32:
                if instruct[1].startswith('sysenter') or instruct[1].startswith('int 128'):
                    self.lgr.debug('mode changed compat32 old %d  new %d eip: 0x%x %s' % (old, new, eip, instruct[1]))
                    SIM_break_simulation('entryModeChanged compat32 found sysenter')
            #if self.param.sys_entry is not None and self.skip_sysenter:
            #    self.lgr.debug('entryModeChanged got sys_entry and told to skip sysenter')
            #    SIM_break_simulation('skip sysenter')
            if self.dumb_count > 1000000:
                self.lgr.debug('entryModeChanged did 1000')
                SIM_break_simulation('did 10000')
    
    def stepCompute(self, compat32=False): 
        self.lgr.debug('stepCompute')
        SIM_delete_breakpoint(self.task_break)
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_hap)
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.task_hap = None
        self.computeStopHap = None
        count = 0
        if self.cpu.architecture == 'arm':
            prefix = 'ldrcc pc, [r8, r7, LSL #2]'
            eip = self.mem_utils.getRegValue(self.cpu, 'eip')
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            self.lgr.debug('stepCompute arm pc 0x%x  %s' % (eip, instruct[1]))
            while True:
                SIM_run_command('si -q')
                eip = self.mem_utils.getRegValue(self.cpu, 'eip')
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                if instruct[1].startswith(prefix):
                    self.param.syscall_compute = eip
                    print(instruct[1])
                    self.param.syscall_jump = self.mem_utils.getRegValue(self.cpu, 'r8')
                    self.lgr.debug('got compute at 0x%x jump constant is 0x%x  %s' % (eip, self.param.syscall_jump, instruct[1]))
                    break
                count += 1
                if count > 1000:
                    self.lgr.error('failed to find compute %s  for ARM' % prefix)
            ''' do not need to fix up stack frame eip offset for arm, go right to page faults '''
            SIM_run_alone(self.setPageFaultHap, None)
        else:
            ''' find where we do the syscall jump table computation '''
            prefix = 'call dword ptr [eax*4'
            prefix1 = 'mov eax,dword ptr [eax*4'
            if self.mem_utils.WORD_SIZE == 8:
                prefix = 'call qword ptr [rax*8'
            while True:
                SIM_run_command('si -q')
                eip = self.mem_utils.getRegValue(self.cpu, 'eip')
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                self.lgr.debug('instruct: %s' % (instruct[1]))
                if instruct[1].startswith(prefix) or instruct[1].startswith(prefix1):
                    if compat32:
                        self.param.compat_32_compute = eip
                        print(instruct[1])
                        self.param.compat_32_jump = int(instruct[1].split('-')[1][:-1], 16)
                        self.lgr.debug('got compute compat32 at 0x%x jump constant is 0x%x  %s' % (eip, self.param.compat_32_jump, instruct[1]))
                    else:
                        self.param.syscall_compute = eip
                        print(instruct[1])
                        self.param.syscall_jump = int(instruct[1].split('-')[1][:-1], 16)
                        self.lgr.debug('got compute at 0x%x jump constant is 0x%x  %s' % (eip, self.param.syscall_jump, instruct[1]))
                    break
                count += 1
                if count > 1000:
                    self.lgr.error('failed to find compute %s for X86' % prefix)
                    break
            if compat32:
                self.saveParam()
            elif self.mem_utils.WORD_SIZE == 4:
                SIM_run_alone(self.fixStackFrame, None)
            else:
                ''' do not need to fix up stack frame eip offset for x86-64, go right to page faults '''
                SIM_run_alone(self.setPageFaultHap, None)

    def computeStopHap(self, compat32, one, exception, error_string):
        if self.stop_hap is None:
            return
        self.lgr.debug('computeStopHap')
        SIM_run_alone(self.stepCompute, compat32)

    def computeDoStop(self, dumb, third, forth, memory):
        self.lgr.debug('computeDoStop must be at sys_entry')
        SIM_break_simulation('computeDoStop')

    def findCompute(self, compat32=False):
        #cell = self.cell_config.cell_context[self.target]
        self.lgr.debug('findCompute')
        if self.cpu.architecture == 'arm':
            self.task_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_entry, 1, 0)
            self.task_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.computeDoStop, None, self.task_break)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.computeStopHap, compat32)
        else:
            
            if compat32:
                entry = self.param.compat_32_entry
            elif self.mem_utils.WORD_SIZE == 4:
                entry = self.param.sys_entry
            else:
                entry = self.param.sysenter
            self.task_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
            self.task_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.computeDoStop, None, self.task_break)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.computeStopHap, compat32)
        self.continueAhead()

    def deleteHaps(self, dumb):
        self.lgr.debug('deleteHaps')
        if self.entry_mode_hap is not None:
            SIM_hap_delete_callback_id("Core_Mode_Change", self.entry_mode_hap)
            self.entry_mode_hap = None
        if self.stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
        self.fs_stop_hap = False

    def getEntries(self):
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_num')
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('getEntries instruct is %s prev_instruct %s eip 0x%x  len %d' % (self.prev_instruct, instruct[1], eip, instruct[0]))
        do_not_continue = False
        if self.prev_instruct.startswith('int 128') and self.param.sys_entry is None:
            self.lgr.debug('getEntries is int 128')
            self.param.sys_entry = eip 

            ''' NOTE MUST delete these before call to findCompute'''
            #SIM_hap_delete_callback_id("Core_Mode_Change", self.entry_mode_hap)
            #self.entry_mode_hap = None
            #SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            #self.stop_hap = None
            #SIM_run_alone(self.findCompute, None)

        elif (self.prev_instruct == 'sysenter' or self.prev_instruct == 'syscall') and self.param.sysenter is None:
            self.lgr.debug('getEntries is sysenter eax %d' % eax)
            #TBD FIX HACK
            if self.prev_instruct == 'syscall':
                self.param.sys_entry = 0
            self.param.sysenter = eip 
            #SIM_run_alone(self.findCompute, None)
            
        if (self.param.sysenter is not None or self.skip_sysenter) and self.param.sys_entry is not None \
                 and (self.param.sysexit is not None or self.skip_sysenter) and self.param.iretd is not None:
            SIM_run_alone(self.deleteHaps, None)

            self.lgr.debug('kernel entry and exits found')

            ''' HERE is where we do more stuff, at the end of this HAP '''
            #param_json = json.dumps(self.param)
            #SIM_run_alone(self.fixStackFrame, None)
            SIM_run_alone(self.findCompute, False)
        elif not do_not_continue:
            self.lgr.debug('getEntries not done collecting sys enter/exit, so continue')
            SIM_run_alone(self.continueAhead, None)

    def stopHap(self, dumb, one, exception, error_string):
        self.lgr.debug('stopHap')
        if self.stop_hap is not None: 
            self.getEntries()
        

    def stopHapARM(self, dumb, one, exception, error_string):
        if self.stop_hap is None: 
            return
        eip = self.mem_utils.getRegValue(self.cpu, 'pc')
        call_num = self.mem_utils.getRegValue(self.cpu, 'syscall_num')
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('stopHapARM instruct is %s eip 0x%x  len %d prev is %s' % (instruct[1], eip, instruct[0], self.prev_instruct))
        do_not_continue = False
        if self.param.arm_entry is None and self.prev_instruct.startswith('svc 0'): 
            self.lgr.debug('stopHapARM set arm_entry to 0x%x' % eip) 
            self.param.arm_entry = eip 
        elif self.param.arm_entry is None and self.prev_instruct.startswith('svc'): 
            self.lgr.debug('stopHapARM SVC 0x9000 set arm_entry to 0x%x' % eip) 
            self.param.arm_entry = eip 
            self.param.arm_svc = True
            
        if self.param.arm_entry is not None and self.param.arm_ret is not None and self.param.arm_ret2 is not None:
            SIM_run_alone(self.deleteHaps, None)
            self.lgr.debug('kernel entry and exits found')

            ''' HERE is where we do more stuff, at the end of this HAP '''
            #param_json = json.dumps(self.param)
            #SIM_run_alone(self.fixStackFrame, None)
            SIM_run_alone(self.findCompute, False)
        elif not do_not_continue:
            self.lgr.debug('stopHapARM missing exit or entry, now continue')
            SIM_run_alone(self.continueAhead, None)

    def stopCompat32Hap(self, dumb, one, exception, error_string):
        if self.stop_hap is None: 
            return
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        if eip == self.param.sysenter:
            self.lgr.debug('stopCompat32Hap entry is same as sysentry, ignore')
            return
        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_num')
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        dumb, comm, pid = self.taskUtils.curProc() 
        self.lgr.debug('stopCompat32Hap pid:%d instruct is %s prev %s  eip 0x%x  len %d' % (pid, instruct[1], self.prev_instruct, eip, instruct[0]))
       
        if self.prev_instruct == 'sysenter' and self.param.compat_32_entry is None:
            self.param.compat_32_entry = eip
        elif self.prev_instruct == 'int 128' and self.param.compat_32_int128 is None:
            self.param.compat_32_int128 = eip
        if self.param.compat_32_entry is not None and self.param.compat_32_int128 is not None:
            SIM_run_alone(self.deleteHaps, None)
            SIM_run_alone(self.findCompute, True)
        else:
            SIM_run_along(self.continueAhead, None)

    def compat32Entry(self):
        self.taskUtils = taskUtils.TaskUtils(self.cpu, self.target, self.param, self.mem_utils, self.unistd, self.unistd32, None, self.lgr)
        self.entry_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.entryModeChanged, True)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopCompat32Hap, None)
        self.lgr.debug('checkKernelEntry added mode changed and stop hap, continue')
        self.continueAhead()

    def checkKernelEntry(self, dumb):
        #SIM_run_command('enable-reverse-execution')
        self.lgr.debug('checkKernelEntry')
        self.dumb_count = 0
        self.hits = []
        if self.cpu.architecture == 'arm':
            self.entry_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.entryModeChangedARM, False)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHapARM, None)
        else:
            self.entry_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.entryModeChanged, False)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap, None)
        self.lgr.debug('checkKernelEntry added mode changed and stop hap, continue')
        self.continueAhead()

    def loadParam(self):
        self.lgr.debug('loadParam')
        fname = '%s.param' % self.target
        self.param = pickle.load( open(fname, 'rb') )

    def saveParam(self):
        self.lgr.debug('saveParam')
        fname = '%s.param' % self.target
        pickle.dump( self.param, open( fname, "wb" ) )
        self.param.printParams()
        print('Param file stored in %s current_task was 0x%x' % (fname, self.param.current_task))

    def deleteStopTaskHap(self, dumb):
        self.lgr.debug('deleteStopTaskHap')
        if self.task_break is not None:
            SIM_delete_breakpoint(self.task_break)
            self.task_break = None
        if self.stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
        if self.task_hap is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_hap)
            self.task_hap = None

    def userEIPStopHap(self, dumb, one, exception, error_string):
        SIM_run_alone(self.deleteStopTaskHap, None)
        SIM_run_alone(self.setPageFaultHap, None)
        
    def findUserEIP(self, user_eip, third, forth, memory):
        dumb, comm, pid = self.taskUtils.curProc() 
        self.lgr.debug('findUserEIP of 0x%x pid %d wanted %d' % (user_eip, pid, self.current_pid))
        if self.current_pid != pid:
            return
        esp = self.mem_utils.getRegValue(self.cpu, 'esp')
        ''' adjust to start of frame  eh?'''
        #start = esp + self.mem_utils.WORD_SIZE
        start = esp 
        esp = start
        ''' TBD what about 64 bit? '''
        ret_eip = user_eip + 2
        for i in range(800):
            stack_val = self.mem_utils.readPtr(self.cpu, esp)
            if stack_val == ret_eip:
                self.lgr.debug('findUserEIP GOT it at 0x%x' % esp)
                self.param.stack_frame_eip = esp - start
                #SIM_break_simulation('got eip offset')
                break
            esp = esp + self.mem_utils.WORD_SIZE
        if self.param.stack_frame_eip is None:
            self.lgr.error('FAILED to find eip 0x%x' % user_eip)

        self.lgr.debug('findUserEIP break simulation')
        SIM_break_simulation('findUserEIP')
        

    def fixFrameHap(self, user_eip):
        if self.entry_mode_hap is None:
            return
        #cell = self.cell_config.cell_context[self.target]
        self.lgr.debug('fixFramHap, remove mode hap and set break on 0x%x' % self.param.syscall_compute)
        SIM_hap_delete_callback_id("Core_Mode_Change", self.entry_mode_hap)
        self.task_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.syscall_compute, 1, 0)
        self.task_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.findUserEIP, user_eip, self.task_break)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.userEIPStopHap, None)
        #SIM_break_simulation('fixframe fix')
         
 
    def fixFrameModeChanged(self, cpu, one, old, new):
        if old == Sim_CPU_Mode_User:
            eip = self.mem_utils.getRegValue(self.cpu, 'eip')
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            if instruct[1].startswith('int 128'):
                eax = self.mem_utils.getRegValue(self.cpu, 'eax')
                dumb, comm, self.current_pid = self.taskUtils.curProc() 
                self.lgr.debug('fixFrameModeChanged eip is 0x%x pid %d' % (eip, self.current_pid))
                #SIM_break_simulation('here maybe?')
                SIM_run_alone(self.fixFrameHap, eip)

    def fixStackFrame(self, dumb):
        self.lgr.debug('fixStackFrame add fixFrameodeChanged hap')
        self.entry_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.fixFrameModeChanged, self.cpu)
        self.continueAhead()

    def pageStopHap(self, dumb, one, exception, error_string):
        if self.page_stop_hap is not None:
            SIM_run_alone(self.stepGetEIP, dumb)
    
    def dataAbortStopHap(self, dumb, one, exception, error_string):
        self.lgr.debug('dataAbortStopHap')
        if self.data_abort_hap is not None:
            SIM_run_alone(self.stepGetDataAbortEIP, dumb)
    
    def stepGetEIP(self, dumb):
        if self.param.page_fault is None:
            SIM_run_command('si -q')
            self.param.page_fault = self.mem_utils.getRegValue(self.cpu, 'eip')
            self.lgr.debug('stepGetEIP page_fault at 0x%x' % self.param.page_fault)
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.page_stop_hap)
            SIM_hap_delete_callback_id("Core_Exception", self.page_hap)
            SIM_break_simulation('stepGetEIP')
            self.page_hap = None
            if self.cpu.architecture != 'arm':
                self.saveParam()
            else:
                SIM_run_alone(self.setDataAbortHap, None)
                

    def stepGetDataAbortEIP(self, dumb):
        if self.param.data_abort is None:
            SIM_run_command('si -q')
            self.param.data_abort = self.mem_utils.getRegValue(self.cpu, 'eip')
            self.lgr.debug('stepGetDataAbortEIP data_abort at 0x%x' % self.param.data_abort)
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.data_abort_hap)
            SIM_hap_delete_callback_id("Core_Exception", self.page_hap2)
            SIM_break_simulation('stepGetDataAbortEIP')
            self.page_hap2 = None
            self.saveParam()
        else:
            self.lgr.debug('stepGetDataAbortEIP param.data_abort is not none')

    def delPageHapAlone(self, dumb):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.page_stop_hap)
        SIM_hap_delete_callback_id("Core_Exception", self.page_hap)
        self.page_hap = None

    def delAbortHapAlone(self, dumb):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.page_stop_hap)
        SIM_hap_delete_callback_id("Core_Exception", self.page_hap2)
        self.page_hap = None

    def pageFaultHap(self, kind, one, exception_number):
        self.lgr.debug('pageFaultHap except %d' % exception_number)
        if self.page_hap is None:
            return
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        self.lgr.debug('pageFaultHap eip 0x%x' % eip)
        SIM_break_simulation('pageFaultHap')
        if eip < self.param.kernel_base: 
            SIM_break_simulation('pageFaultHap')
        else:
            self.param.page_fault = eip
            self.lgr.debug('pageFaultHap page_fault right off at 0x%x' % self.param.page_fault)
            SIM_run_alone(self.delPageHapAlone, None)
            if self.cpu.architecture != 'arm':
                self.saveParam()
            else:
                SIM_run_alone(self.setDataAbortHap, None)
        
    def dataAbortHap(self, kind, one, exception_number):
        if self.page_hap2 is None:
            return
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        self.lgr.debug('dataAbort eip 0x%x' % eip)
        SIM_break_simulation('dataAbortHap')
        return
        if eip < self.param.kernel_base: 
            SIM_break_simulation('dataAbortHap')
        else:
            self.param.page_fault = eip
            self.lgr.debug('dataAbort page_fault right off at 0x%x' % self.param.page_fault)
            SIM_run_alone(self.delAbortHapAlone, None)
            self.saveParam()

    def setPageFaultHap(self, dumb):
        self.page_hap = SIM_hap_add_callback_obj_index("Core_Exception", self.cpu, 0,
                 self.pageFaultHap, 'prefetch abort', self.page_fault)
        self.page_stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.pageStopHap, 'prefetch abort')
        self.lgr.debug('setPageFaultHap set exception and stop haps')
        self.continueAhead()

    def setDataAbortHap(self, dumb):
        if self.data_abort is not None:
            self.page_hap2 = SIM_hap_add_callback_obj_index("Core_Exception", self.cpu, 0,
                 self.dataAbortHap, 'data abort', self.data_abort)
            self.data_abort_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.dataAbortStopHap, 'data abort')
            self.lgr.debug('setDataAbortHap set exception and stop haps')
        self.continueAhead()
       
    def go(self, force=False, skip_sysenter=False): 
        ''' Initial method for gathering kernel parameters.  Will chain a number of functions, the first being runUntilSwapper '''
        cpl = memUtils.getCPL(self.cpu)
        if cpl != 0:
            print('not in kernel, please run forward until in kernel')
            return
        if self.cpu.architecture != 'arm':
            self.fs_base = self.cpu.ia32_fs_base
            if self.fs_base == 0 and not force:
                print('fs_base is zero, maybe just entered kernel?  consider running ahead a bit, or use gkp.go(True)')
                return
        if skip_sysenter:
            self.skip_sysenter = skip_sysenter
        self.runUntilSwapper()

    def compat32(self):
        self.loadParam()
        self.param.compat_32_entry = None
        self.param.compat_32_int128 = None
        self.compat32Entry()

    def continueAhead(self, dumb=None):
        if not SIM_simics_is_running():
            try:
                SIM_continue(0)
                self.lgr.debug('continueAhead did continue')
            except simics.SimExc_General:
                pass

if __name__ == '__main__':
    gkp = GetKernelParams()
    #gkp.runUntilSwapper()
    ''' NOTE: see swapperStopHap hap for follow-on processing and the start of
        as stop hap chain '''
