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
import resimSimicsUtils
import kParams
import cellConfig
import pickle
import decode
import decodeArm
import decodePPC32
import pageUtils
import reverseMgr
import skipToMgr
import ppcKernelParams
import os
import cli

import w7Params
import winxpParams
import winKParams
def my_SIM_disassemble_address(cpu, pc, logical, sub_instruct):
        instruct = SIM_disassemble_address(cpu, pc, logical, sub_instruct)
        if 'cluster' in cpu.name:
            cmd = 'disassemble address = 0x%x' % pc
            dumb, cli_instruct = cli.quiet_run_command(cmd)
            #print('cli_instruct is type %s' % type(cli_instruct))
            instruct_parts = cli_instruct.split(' ',3)
            #print('instruct_str value %s' % str(instruct_parts))
            instruct_str = instruct_parts[3]
            instruct = (4, instruct_str)
            #print('instruct 1 is %s' % instruct[1])
        else:
            instruct = SIM_disassemble_address(cpu, pc, logical, sub_instruct)
        return instruct

class GetKernelParams():
    def __init__(self, conf, comp_dict, run_from_snap):
        #self.cpu = SIM_current_processor()
        self.log_dir = './logs'
        self.lgr = resimUtils.getLogger('getKernelParams', self.log_dir)
        self.cell_config = cellConfig.CellConfig(list(comp_dict.keys()), self.lgr)
        self.target = os.getenv('RESIM_TARGET')
        self.cpu = self.cell_config.cpuFromCell(self.target)
        self.comp_dict = comp_dict
        self.os_type = comp_dict[self.target]['OS_TYPE']

        self.current_task_phys = None
        self.hack_cycles = 0
        self.hack_stop = False
        self.run_from_snap = run_from_snap
        self.only_64 = False

        if self.os_type is None:
            self.os_type = 'LINUX32'
        self.word_size = 4
        if self.os_type == 'LINUX64' or self.os_type == 'WIN7':
            self.word_size = 8
  
        print('using target of %s, os type: %s, word size %d' % (self.target, self.os_type, self.word_size))

        #self.log_dir = '/tmp'
        self.lgr.debug('GetKernelParams using target of %s, os type: %s, word size %d' % (self.target, self.os_type, self.word_size))
        platform = None
        self.want_arm32 = False
        self.want_arm64 = False
        if 'PLATFORM' in comp_dict[self.target]:
            platform = comp_dict[self.target]['PLATFORM']
            self.lgr.debug('PLATFORM is %s' % platform)
            if platform.startswith('arm'):
                if platform == 'armMixed':
                    self.want_arm32 = True
                    self.want_arm64 = True
                    self.lgr.debug('Will look for ARM 32 and 64 bit syscall jump tables')
                    print('Will look for ARM 32 and 64 bit syscall jump tables')
                elif platform == 'arm64':
                    self.want_arm64 = True
                    self.lgr.debug('Will look for only ARM 64 bit syscall jump tables')
                    print('Will look for only ARM 64 bit syscall jump tables')
                else:
                    self.want_arm32 = True
                    self.lgr.debug('Will look for only ARM 32 bit syscall jump tables')
                    print('Will look for only ARM 32 bit syscall jump tables')
        if self.os_type in ['WIN7', 'WINXP']:
            self.param = winKParams.WinKParams(self.os_type)
            self.lgr.debug('GetKernelParams kernel_base is 0x%x' % self.param.kernel_base)
        else:
            self.param = kParams.Kparams(self.cpu, self.word_size, platform)
            # override a previous hack
            self.param.sysexit = None
            self.lgr.debug('GetKernelParams kernel_base is 0x%x' % self.param.kernel_base)
        if self.os_type == 'WINXP':
            return


        # NOT used for windows XP
        # try first without reference to fs when finding current_task.  If that fails in 3 searches,
        #    try making phys addresses relative to the fs base 
        self.param.current_task_fs = False

        self.mem_utils = memUtils.MemUtils(self, self.word_size, self.param, self.lgr, arch=self.cpu.architecture)
        # TBD FIX THIS
        self.data_abort = None
        obj = SIM_get_object(self.target)
        if self.cpu.architecture == 'arm' or self.cpu.architecture == 'arm64':
            self.page_fault = 4
            self.data_abort = 1
        elif self.cpu.architecture == 'ppc32':
            self.page_fault = 5
        else:
            self.page_fault = 14
      
        self.cell = obj.cell_context
        print('current processor %s' % self.cpu.name)
        #self.taskUtils = taskUtils.TaskUtils(self.cpu, self.param, self.mem_utils, self.param.current_task, self.lgr)
        ''' NOTE shared between different functions, e.g., entry eip and current task candidates'''
        self.hits = []
        self.trecs = []
        self.idle = None
        self.dumb_count = 0
        self.mode_entry_limit = 10000
        self.stop_hap = None
        self.fs_stop_hap = None
        self.fs_start_cycle = None
        ''' how many instructions to look for FS fu '''
        self.fs_cycles = 500
        self.gs_stop_hap = None
        self.gs_start_cycle = None
        self.arm64_hap = None
        ''' how many instructions to look for GS fu '''
        self.gs_cycles = 500
        self.entry_mode_hap = None
        self.page_hap = None
        self.page_hap2 = None
        self.prev_instruct = ''
        # TBD remove unistd from here, only passed because taskutils cannot handle none
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
        self.current_task_stop_hap = None
 
        self.from_boot = False
        self.try_mode_switches = 0 
        self.init_task = None
        self.fs_base = None
        self.search_count = 0
        self.test_count = 0
     

        self.win7_tasks = []
        self.win7_count = 0
        self.win7_saved_cr3_phys = None

        self.quit = False
        self.force = False

        # another hack.  if the kernel entry we find early are sysenter, use fs, otherwise it is a fools errand.
        self.ignore_fs = False
 
        # yah to avoid mode change haps while skipping around 
        self.ignore_mode = False

        self.reverse_mgr = reverseMgr.ReverseMgr(conf, self.cpu, self.lgr, top=self)
        self.skip_to_mgr = skipToMgr.SkipToMgr(self.reverse_mgr, self.cpu, self.lgr)
        self.ppc_kparams = ppcKernelParams.PPCKernelParams(self, self.cpu, self.cell, self.mem_utils, self.reverse_mgr, self.skip_to_mgr, self.lgr)
  
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
        self.lgr.debug('taskModeChanged32 new %s' % str(new))
        if self.task_rec_mode_hap is None:
            return
        ''' find the current_task record pointer ''' 
        if new == Sim_CPU_Mode_Supervisor:
            eip = self.mem_utils.getRegValue(self.cpu, 'eip')
            instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
            self.lgr.debug('taskModeChanged32 eip 0x%x %s' % (eip, instruct[1]))
            if 'illegal' in instruct[1]:
                self.lgr.debug('taskModeChanged32 page fault, continue')
            elif 'sys' not in instruct[1] and 'int' not in instruct[1] and 'svc' not in instruct[1]:
                self.lgr.debug('taskModeChanged32 not a syscall, page fault, continue')
            else:
                if self.ignore_fs or instruct[1].startswith('int'):
                    self.lgr.debug('taskModeChanged32 an int80 call, use brute force')
                    self.taskModeChanged(cpu, one, old, new)
                    self.ignore_fs = True
                else:
                    self.lgr.debug('taskModeChanged32 must be a non-int call, look for FS')
                    self.lookForFS(None)
        else:
           pass

    def taskModeChanged64(self, cpu, one, old, new):
        if self.task_rec_mode_hap is None:
            return
        ''' find the current_task record pointer ''' 
        if new == Sim_CPU_Mode_Supervisor:
            eip = self.mem_utils.getRegValue(self.cpu, 'eip')
            instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
            self.lgr.debug('taskModeChanged64 eip 0x%x %s' % (eip, instruct[1]))
            print('taskModeChanged64 eip 0x%x %s' % (eip, instruct[1]))
            if 'illegal' in instruct[1]:
                self.lgr.debug('taskModeChanged64 page fault, continue')
            elif 'sys' not in instruct[1] and 'int' not in instruct[1]:
                self.lgr.debug('taskModeChanged64 not a syscall, page fault, continue')
            else:
                rax = self.mem_utils.getRegValue(self.cpu, 'rax')
                self.lgr.debug('taskModeChanged64 must be a call rax is 0x%x, look for GS' % rax)
                if rax > 100:
                    self.lgr.debug('superstition about multiple jump tables, skip this one')
                    return
                #self.lookForFS(None)
                self.lookForGS(None)
                SIM_run_alone(self.delTaskModeAlone, None)
                #SIM_break_simulation('got it?')
                ''' TBD not done yet'''
        else:
           pass

    def getCurrentTaskPtr(self):
        ''' Find the current_task address.  Method varies by cpu type '''
        print('Searching for current_task, this may take a moment...')
        self.lgr.debug('getCurrentTaskPtr Searching for current_task, this may take a moment...')
        self.idle = None
        if self.cpu.architecture.startswith('arm') or self.cpu.architecture == 'ppc32':
            self.param.current_task_fs = False
        if self.mem_utils.WORD_SIZE == 4:
            ''' use mode haps and brute force search for values that match the current task value '''
            if self.cpu.architecture == 'arm':
                self.task_rec_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.taskModeChanged, self.cpu)
            else:
                self.task_rec_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.taskModeChanged32, self.cpu)
                self.lgr.debug('getCurrentTaskPtr added taskModeChanged32')
            self.current_task_stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.currentTaskStopHap, None)
            #self.current_task_stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.supervisor32StopHap, None)
            self.lgr.debug('getCurrentTaskPtr added mode and stop haps')
            self.continueAhead()
        elif self.cpu.architecture == 'arm64':
            self.task_rec_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.taskModeChangedArm64, self.cpu)
            self.current_task_stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.currentTaskStopHap, None)
            self.lgr.debug('getCurrentTaskPtr added mode for arm64 and stop haps')
            self.continueAhead()
        else:
            self.task_rec_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.taskModeChanged64, self.cpu)
            self.current_task_stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.currentTaskStopHap, None)
            self.lgr.debug('getCurrentTaskPtr added mode and stop haps 64 bit')
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
            self.reverse_mgr.enableReverse()

            self.fs_start_cycle = self.cpu.cycles
            self.lgr.debug('fsEnableReverse, , now continue %d cycles' % self.fs_cycles)
            ''' go forward so that we can later reverse '''
            SIM_continue(self.fs_cycles)
            self.fsFindAlone()

    def gsEnableReverse(self, dumb):
            self.deleteHaps(None)
            self.delCurrentTaskStopHap(None)
            self.delTaskModeAlone(None)
            self.reverse_mgr.enableReverse()

            eip = self.mem_utils.getRegValue(self.cpu, 'eip')
            self.gs_start_cycle = self.cpu.cycles
            self.lgr.debug('gsEnableReverse should be at kernel entry. eip is 0x%x, , now continue %d cycles' % (eip, self.gs_cycles))
            ''' The point of going forward is to let us reverse'''
            SIM_continue(self.gs_cycles)
            self.lgr.debug('gsEnableReverse back from continue, now call gsFindAlone')
            got_it = self.gsFindAlone()
            if not got_it:
                self.gsFindAlone(any_reg=True)
            self.lgr.debug('gsEnableReverse back from gsFindAlone')

    def currentTaskStopHap(self, dumb, one, exception, error_string):
        # stop hap when stopped from task mode change
        self.lgr.debug('currentTaskStopHap')
        if self.current_task_stop_hap is None:
            self.lgr.debug('currentTaskStopHap, hap was gone, bail')
            return
        if self.fs_stop_hap:
            self.lgr.debug('currentTaskStopHap, fs_stop_hap is true')
            SIM_run_alone(self.fsEnableReverse, None)
        elif self.gs_stop_hap:
            self.lgr.debug('currentTaskStopHap, gs_stop_hap is true')
            SIM_run_alone(self.gsEnableReverse, None)
        elif self.arm64_hap:
            self.lgr.debug('currentTaskStopHap, arm64_hap is true')
            SIM_run_alone(self.getARM64Task, None)
        
        elif self.param.current_task is None:
            self.lgr.debug('currentTaskStopHap, but no current_task yet, assume mem map fu')
        else:
            SIM_run_alone(self.delTaskModeAlone, None)
            SIM_run_alone(self.delCurrentTaskStopHap, None)
            self.lgr.debug('currentTaskStopHap, now call findSwapper')
            self.findSwapper()
            SIM_run_alone(self.continueAhead, None)

    def getEIP(self):
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        return eip

    def fsFindAlone(self):
        self.lgr.debug('fsFindAlone, fs_cycles is %d' % self.fs_cycles)
        gotit = False
        for i in range(1,self.fs_cycles):
            self.skip_to_mgr.skipToTest(self.fs_start_cycle+i)
            eip = self.mem_utils.getRegValue(self.cpu, 'eip')
            instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
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
                self.reverse_mgr.disableReverse()
                gotit = True
                self.findSwapper()
                break
        if not gotit:
            self.lgr.error('fsFindAlone failed to find fs: instruction')

    def gsFindAlone(self, any_reg=False):
        retval = False
        self.lgr.debug('gsFindAlone, gs_cycles is %d' % self.gs_cycles)
        did_offset = []
        for i in range(1,self.gs_cycles):
            want = self.gs_start_cycle + i
            self.skip_to_mgr.skipToTest(want)
            eip = self.mem_utils.getRegValue(self.cpu, 'eip')
            instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
            if 'gs:' in instruct[1]:
                mn = decode.getMn(instruct[1])
                op2, op1 = decode.getOperands(instruct[1])
                self.lgr.debug('eip: 0x%x %s, mn: %s op2: <%s> op1: <%s>' % (eip, instruct[1], mn, op2, op1)) 
                print('eip: 0x%x %s, mn: %s op2: <%s> op1: <%s>' % (eip, instruct[1], mn, op2, op1)) 


                # TBD may need to cycle through multiple gsFindAlone iterations to get to the right gs reference.
                if self.isWindows(): 
                    if mn != 'mov' or op1 == 'rsp' or not op1.startswith('r'):
                        continue
                else:
                    if mn != 'mov':
                        continue
                    if 'rip' in instruct[1] or 'rsp' in instruct[1]:
                        continue
                    if (not any_reg and not op1.startswith('ra')):
                        self.lgr.debug('gsFind wrong op1? %s' % op1)
                        continue

                prefix, addr = decode.getInBrackets(self.cpu, instruct[1], self.lgr) 
                print('gsFind alone eip: 0x%x got addr %s from %s' % (eip, addr, instruct[1]))
                self.lgr.debug('gsFind eip: 0x%x got addr %s from %s' % (eip, addr, instruct[1]))
                addr = self.mem_utils.getUnsigned(int(addr, 16))
                if not self.isWindows() and addr < 0x1000:
                    self.lgr.debug('gs offset looks dicey, skip this 0x%x' % addr)
                    continue

                did_offset.append(addr)
                self.gs_base = self.cpu.ia32_gs_base
                self.param.current_task_gs  = True
                self.param.gs_base = self.gs_base
                self.param.current_task = addr
                self.lgr.debug('gs_base: 0x%x current_task is 0x%x kernel_base 0x%x ' % (self.gs_base, self.param.current_task, self.param.kernel_base))
                va = self.gs_base + self.param.current_task
                self.lgr.debug('va is 0x%x' % va)
                phys = self.mem_utils.v2p(self.cpu, va)
                #phys = (self.gs_base + self.param.current_task)-self.param.kernel_base
                self.lgr.debug('phys of current_task is 0x%x' % phys)
                cur_task = SIM_read_phys_memory(self.cpu, phys, self.mem_utils.WORD_SIZE)
                if not self.isWindows() and cur_task < 0x10000:
                    self.lgr.debug('cur task looks dicey, skip this 0x%x' % cur_task)
                    continue

                self.current_task_phys = phys
                self.reverse_mgr.disableReverse()
                retval = True
                if self.os_type == 'WIN7':
                    next_eip = eip + instruct[0]
                    next_instruct = my_SIM_disassemble_address(self.cpu, next_eip, 1, 0)
                    next_mn = decode.getMn(next_instruct[1])
                    next_op2, op1 = decode.getOperands(next_instruct[1])
 
                    self.findWin7Params()
                else:
                    self.lgr.debug('got gs stuff, call findSwapper')
                    self.findSwapper()
                break
        if self.current_task_phys is None:
            self.lgr.error('gsFindAlone failed')
        return retval
                
    def lookForFS(self, dumb):
         self.lgr.debug('lookForFS')
         ''' will piggy back on the currentTaskStopHap'''
         self.fs_stop_hap = True
         self.param.current_task = None
         SIM_break_simulation('fs stop')
       
    def lookForGS(self, dumb):
         self.lgr.debug('lookForGS')
         ''' will piggy back on the currentTaskStopHap'''
         self.gs_stop_hap = True
         self.param.current_task = None
         self.lgr.debug('lookForGS, now break')
         SIM_break_simulation('gs stop')

    def taskModeChanged(self, cpu, one, old, new):
        ''' *** NOT ALWAYS USED *** see other variations taskModeChanged '''
        ''' search kernel memory for the current_task address that seems to match
            the task address found for the current process '''
        if self.task_rec_mode_hap is None:
            return
        ''' find the current_task record pointer ''' 
        if self.try_mode_switches < 900000:
            self.try_mode_switches += 1
            if new == Sim_CPU_Mode_Supervisor:
                eip = self.mem_utils.getRegValue(self.cpu, 'eip')
                instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
                self.lgr.debug('entering sup mode eip: 0x%x  instruct: %s' % (eip, instruct[1]))
                ta = self.mem_utils.getCurrentTask(self.cpu)
                if ta is None or ta == 0:
                    self.lgr.debug('ta nothing, continue')
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
        for i in range(2000):
            self.lgr.debug('isThisSwapper read from 0x%x' % ((task + real_parent_offset)))
            test_task = self.mem_utils.readPtr(self.cpu, task + real_parent_offset)
            test_task1 = self.mem_utils.readPtr(self.cpu, task + real_parent_offset+self.mem_utils.WORD_SIZE)
            if test_task == task and test_task1 == task:
                self.lgr.debug('isThisSwapper found match 0x%x ' % test_task)
                maybe.append(real_parent_offset)
                #return real_parent_offset
                real_parent_offset += self.mem_utils.WORD_SIZE
            else:
                if test_task is not None and test_task1 is not None:
                    self.lgr.debug('loop %d task was 0x%x test_task 0x%x test_task1 0x%x' % (i, task, test_task, test_task1))
                else:
                    self.lgr.debug('test task was None')
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
            if self.cpu.architecture.startswith('arm'):
                self.param.ts_thread_group_list_head = self.param.ts_group_leader+self.getOff(14)
            else:
                self.param.ts_thread_group_list_head = self.param.ts_group_leader+self.getOff(15)

            parent = self.mem_utils.readPtr(self.cpu, task+self.param.ts_parent) 
            group_leader = self.mem_utils.readPtr(self.cpu, task+self.param.ts_group_leader) 
            ''' will confirm is swapper and will set init_task and ts_next '''
            self.getNextOffset() 
            if self.param.ts_next is None:
                return None
        return real_parent_offset
      
    def getInitAlone(self, dumb): 
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_hap)
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.task_hap = None
        self.stop_hap = None
        result = self.getInit()
        if result != 0:
            self.lgr.error('error from getInit')
            return
        self.lgr.debug('back from getInit, now call checkTasks')
        self.checkTasks()
        self.lgr.debug('back from checkTasks')
        print('back from checkTasks, now check kernel entry')
        ''' get kernel entry points/exits '''
        #SIM_run_alone(self.checkKernelEntry, None)
        if self.cpu.architecture == 'ppc32':
            self.findCompute()
        else:
            self.checkKernelEntry(None)

    def swapperStopHap(self, dumb, one, exception, error_string):
        self.lgr.debug('swapperStopHap')
        SIM_run_alone(self.getInitAlone, None)

    def rmTaskStopAlone(self, dumb):
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_hap)
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.task_hap = None
        self.stop_hap = None

    def win7StopHap(self, dumb, one, exception, error_string):
        self.lgr.debug('win7StopHap')
        SIM_run_alone(self.rmTaskStopAlone, None)
        SIM_run_alone(self.getWin7Params, None)

    def getWin7Params(self, dumb):
        w7Params.findParams(self.cpu, self.mem_utils, self.win7_tasks, self.param, self.current_task_phys, self.lgr)
        if self.param.ts_pid is not None:
            print('got pid %d' % self.param.ts_pid)
        else:
            print('ts_pid is None!!!!')
            return
        self.checkKernelEntry(None)

    def changedThreadWin7(self, cpu, third, forth, memory):
        cur_task = SIM_read_phys_memory(self.cpu, self.current_task_phys, self.mem_utils.WORD_SIZE)
        '''
        pid_off = 960
        next_off = 1064
        pid_ptr = cur_task + pid_off
        pid = self.mem_utils.readWord(self.cpu, pid_ptr)
        next_ptr = cur_task + next_off + 8
        next_head = self.mem_utils.readWord(self.cpu, next_ptr)
        print('task 0x%x pid: %d next_head 0x%x' % (cur_task, pid, next_head))
        '''

        if cur_task not in self.win7_tasks:
            self.win7_tasks.append(cur_task) 
            print('num tasks now %d,  changed threads %d times' % (len(self.win7_tasks), self.win7_count))
        self.win7_count = self.win7_count+1
        #if self.win7_count > 1000:
        if len(self.win7_tasks) > 50:
            #pickle.dump( self.win7_tasks, open( 'task_list.pickle', "wb" ) )
            print('Did enough tasks? num tasks %d,  changed threads %d times' % (len(self.win7_tasks), self.win7_count))
            SIM_break_simulation('changed thread enough')
            SIM_delete_breakpoint(self.task_break)

    def changedThread(self, cpu, third, forth, memory):
        self.lgr.debug('changed thread')
        ''' does the current thread look like swapper? would have consecutive pointers to itself '''
        if self.task_break is None:
            return
        cur_task = SIM_read_phys_memory(self.cpu, self.current_task_phys, self.mem_utils.WORD_SIZE)
        if cur_task not in self.trecs:
            self.trecs.append(cur_task)
            self.lgr.debug('changedThread try task 0x%x' % cur_task)

            if cur_task != 0 and self.isSwapper(cur_task) is not None:
                self.lgr.debug('changedThread found swapper 0x%x  real_parent %d' % (self.idle, self.param.ts_real_parent))
                SIM_break_simulation('found swapper')
                SIM_delete_breakpoint(self.task_break)
                self.task_break = None 

    def findWin7Params(self):
        pcell = self.cpu.physical_memory
        self.task_break = SIM_breakpoint(pcell, Sim_Break_Physical, Sim_Access_Write, self.current_task_phys, self.mem_utils.WORD_SIZE, 0)
        self.task_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.changedThreadWin7, self.cpu, self.task_break)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.win7StopHap, None)
        self.continueAhead()

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
            if comm is None:
                print('remove this')
                return False 
            if comm is not None and (comm.startswith('init') or comm.startswith('systemd') or comm.startswith('linuxrc') or comm.startswith('swapper')):
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
        #test_val = 0x5000
        test_val = 0xf000
        while not init_has_child:   
            init_next_ptr = self.mem_utils.readPtr(self.cpu, self.init_task + self.param.ts_next) 
            if init_next_ptr is not None:
                delta = abs(self.init_task - init_next_ptr)
                self.lgr.debug('getInit ts_next %d  ptr 0x%x delta 0x%x' % (self.param.ts_next, init_next_ptr, delta))
                if self.mem_utils.getUnsigned(delta) < test_val:
                    self.lgr.debug('got second proc')
                    init_has_child = True
                else:
                    self.lgr.debug('only one proc, continue')
                    SIM_run_command('c 500000') 
            else:
                self.lgr.debug('init_next_ptr is none, continue')
                SIM_run_command('c 500000') 

        #self.lgr.debug('getInit real pid is %d' % self.real_param.ts_pid)

        # save cr3 for use by memutils
        if not self.cpu.architecture.startswith('arm'):
           self.mem_utils.saveKernelCR3(self.cpu)

        init_next_ptr = self.mem_utils.readPtr(self.cpu, self.init_task + self.param.ts_next) 
        init_next = init_next_ptr - self.param.ts_next
        self.lgr.debug('getInit ts_next %d  ptr 0x%x init_next is 0x%x' % (self.param.ts_next, init_next_ptr, init_next))
        pid_offset = 0
        init_pid = 0
        next_pid = 0
        for i in range(800):
            init_pid = self.mem_utils.readWord32(self.cpu, self.init_task+pid_offset)
            next_pid = self.mem_utils.readWord32(self.cpu, init_next+pid_offset)
            init_pid_g = self.mem_utils.readWord32(self.cpu, self.init_task+pid_offset+4)
            next_pid_g = self.mem_utils.readWord32(self.cpu, init_next+pid_offset+4)
            #if init_pid == 1 and init_pid_g ==1 and ((next_pid == 2 and next_pid_g == 2) or (next_pid == 0 and next_pid_g == 0)):
            if init_pid == 1 and init_pid_g ==1 and ((next_pid == 2 and next_pid_g == 2)):
                self.lgr.debug('getInit looking for pid, got 1 at offset %d  next_pid %d' % (pid_offset, next_pid))
                self.param.ts_pid = pid_offset
                self.param.ts_tgid = pid_offset+4
                break
            else:
                self.lgr.debug('looking for pid offset %d init_pid of %d next_pid %d init_pid_g %d  next_pid_g %d' % (pid_offset, init_pid, next_pid, init_pid_g, next_pid_g))
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
        self.lgr.debug(self.param.getParamString())
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
        self.lgr.debug('num tasks: %d' % len(tasks))
         
        plist = {}
        for t in tasks:
            plist[tasks[t].pid] = t 
        for pid in sorted(plist):
            t = plist[pid]
            print('pid: %d task_rec: 0x%x  comm: %s children 0x%x 0x%x' % (tasks[t].pid, t, tasks[t].comm, tasks[t].children[0], tasks[t].children[1]))
            self.lgr.debug('pid: %d task_rec: 0x%x  comm: %s children 0x%x 0x%x' % (tasks[t].pid, t, tasks[t].comm, tasks[t].children[0], tasks[t].children[1]))
        
        
   
    def entryModeChangedARM(self, dumb, one, old, new):
        if self.ignore_mode:
            return
        if self.entry_mode_hap is None:
            return
        eip = self.mem_utils.getRegValue(self.cpu, 'pc')
        #self.lgr.debug('entryModeChanged ARM, pc is  0x%x ' % (eip))
        if old == Sim_CPU_Mode_Supervisor and new == Sim_CPU_Mode_User:
            #self.lgr.debug('entryModeChanged ARM, supervisor  mode')
            ''' leaving kernel, capture address, note instruction cannot be read '''
            if eip not in self.hits:
                instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
                if instruct[1] == '<illegal memory mapping>':
                    #self.lgr.debug('entryModeChangedARM, nothing mapped at eip 0x%x ' % (eip))
                    pass
                if self.param.arm_ret is None:
                    self.lgr.debug('entryModeChangedARM, think arm_ret is 0x%x' % eip)
                    self.param.arm_ret = eip
                elif self.param.arm_ret2 is None:
                    if eip != self.param.arm_ret:
                        self.lgr.debug('entryModeChanged ARM, think arm_ret2 is 0x%x' % eip)
                        self.param.arm_ret2 = eip
                else:
                    self.lgr.debug('entryModeChanged ARM, found both rets')
                    SIM_break_simulation('entryModeChanged found two rets: 0x%x 0x%x' % (self.param.arm_ret, self.param.arm_ret2))
                    
        elif old == Sim_CPU_Mode_User:
            #if self.param.page_table is None:
            #    self.param.page_table = self.getPageTableDirectory()
            self.dumb_count += 1
            self.lgr.debug('entryModeChanged ARM, from user mode pc 0x%x' % eip)
            '''
            if self.cpu.architecture == 'arm64':
                # while the pc register reflects the user eip, the translation logic thinks we are in pl0 and thus breaks.  Simics model issue?
                # use page table to get phys addr
                pinfo = pageUtils.findPageTable(self.cpu, eip, self.lgr)
                paddr = pinfo.page_addr
                self.lgr.debug('entryModeChanged use phys to get instruct arm64 paddr is 0x%x' % paddr)
                instruct = SIM_disassemble_address(self.cpu, paddr, 0, 0)
            else:
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            '''
            if self.cpu.architecture == 'arm64' and not self.isSyscall():
                self.lgr.debug('entryModeChanged ARM, from user mode but not syscall, bail')
                return

            if (self.param.arm_entry is None or self.param.arm64_entry is None): 
                self.lgr.debug('mode changed old %d  new %d eip: 0x%x armv8 cannot get user instruction from kernel mode' % (old, new, eip))
                self.prev_instruct = 'broken'
                self.lgr.debug('entryModeChanged ARM must be armv8, stop simulation')
                SIM_break_simulation('entryModeChanged stop simulation')

            '''
            instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
            self.lgr.debug('entryModeChanged ARM, user mode instruct %s' % instruct[1])
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
            if (self.param.arm_entry is None or self.param.arm64_entry is None) and instruct[1].startswith('<illegal'):
                self.lgr.debug('mode changed old %d  new %d eip: 0x%x armv8 cannot get user instruction from kernel mode' % (old, new, eip))
                self.prev_instruct = 'broken'
                self.lgr.debug('entryModeChanged ARM must be armv8, stop simulation')
                SIM_break_simulation('entryModeChanged stop simulation')
            elif self.param.arm_entry is None:
                self.lgr.debug('entryModeChanged ARM  eip 0x%x, instruct %s, what is it?' % (eip, instruct[1])) 
                #self.stop_hap = None
            '''

    def entryModeChanged(self, compat32, one, old, new):
        ''' HAP entered when mode changes looking for kernel entry and exits. 
            Since on entry the eip is from user space, we need to stop the simulation
            and then read eip.
        '''
        if self.entry_mode_hap is None:
            return
        self.hack_stop = False
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        #self.lgr.debug('entryModeChanged eip 0x%x compat32: %r cycles: 0x%x' % (eip, compat32, self.cpu.cycles)) 
        dumb, comm, pid = self.taskUtils.curThread() 
        if pid is None:
            self.lgr.debug('entryModeChanged failed to get pid, continue?')
            return
        if old == Sim_CPU_Mode_Supervisor and not compat32:
            ''' leaving kernel, capture iret and sysexit '''
            #self.lgr.debug('entryModeChanged leaving kernel len of hits is %d' % len(self.hits))
            if eip not in self.hits:
                self.hits.append(eip)
                instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
                self.lgr.debug('entryModeChanged pid:%s kernel exit eip 0x%x %s' % (pid, eip, instruct[1]))
                if instruct[1].startswith('iret'):
                    self.param.iretd = eip
                    self.lgr.debug('entryModeChanged found iret')
                elif instruct[1] == 'sysexit':
                    self.param.sysexit = eip
                    self.lgr.debug('entryModeChanged found sysexit 0x%x' % eip)
                elif instruct[1] == 'sysret64':
                    if self.param.sysret64 is not None:
                        ''' use sysexit to record 2nd sysret64 exit '''
                        if self.param.sysexit is None:
                            self.param.sysexit = eip
                            self.lgr.debug('entryModeChanged found 2nd sysret64, save as sysexit 0x%x' % eip)
                        else:
                            self.lgr.error('entryModeChanged got sysret64 0x%x but already got sysret64 twice' % eip)
                    else:
                        self.param.sysret64 = eip
                        self.lgr.debug('entryModeChanged found sysret64 0x%x' % eip)
                
                '''
                TBD seems no reason to stop the simulation, we are gathering exits.
                if self.mem_utils.WORD_SIZE == 4:     
                    if self.param.iretd is not None and self.param.sysexit is not None:
                        self.lgr.debug('entryModeChanged found exits')
                        self.hack_stop = True
                        SIM_break_simulation('found sysexit and iretd')
                else:
                    if self.param.iretd is not None and self.param.sysret64 is not None:
                        self.lgr.debug('entryModeChanged found exits')
                        SIM_break_simulation('found iretd and sysret64')
                else:
                    if self.param.iretd is not None and self.param.sysexit is not None and self.sysret64 is not None:
                        self.lgr.debug('entryModeChanged found exits')
                        SIM_break_simulation('found sysexit and iretd and sysret64')
                '''
            else:
                #self.lgr.debug('entryModeChanged, 0x%x in already hits?' % eip)
                pass
        elif old == Sim_CPU_Mode_Supervisor and compat32:
            self.lgr.debug('entryModeChanged, leaving kernel, compat32 so ignore?')
        elif old == Sim_CPU_Mode_User:
            #self.lgr.debug('entryModeChanged entering kernel')
            if self.dumb_count < 50:
                if not self.isWindows() and self.param.mm_struct is None:
                    if not self.getPageTableDirectory():
                        if self.dumb_count == 50:
                            self.lgr.error('Failed to get page table offsets from process record, may not be fatal')
            self.dumb_count += 1
            instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)

            self.prev_instruct = instruct[1]
            #self.lgr.debug('entryModeChanged pid:%s supervisor eip 0x%x instruct %s count %d' % (pid, eip, instruct[1], self.dumb_count))

            if self.param.sys_entry is None and instruct[1].startswith('int 128'):
                self.lgr.debug('mode changed old %d  new %d eip: 0x%x %s' % (old, new, eip, instruct[1]))
                self.lgr.debug('entryModeChanged found int 128')
                self.hack_stop = True
                SIM_break_simulation('found int 128')
            elif self.param.sysenter is None and (instruct[1].startswith('sysenter') or instruct[1].startswith('syscall')):
                self.lgr.debug('mode changed old %d  new %d eip: 0x%x %s' % (old, new, eip, instruct[1]))
                self.lgr.debug('entryModeChanged found sysenter %s' % instruct[1])
                self.hack_stop = True
                SIM_break_simulation('entryModeChanged found sysenter')
            elif compat32:
                if instruct[1].startswith('sysenter') or instruct[1].startswith('int 128'):
                    self.lgr.debug('mode changed compat32 old %d  new %d eip: 0x%x %s' % (old, new, eip, instruct[1]))
                    self.hack_stop = True
                    SIM_break_simulation('entryModeChanged compat32 found sysenter')
            else:
                #self.lgr.debug('entryModeChanged nothing to do, continue')
                pass
            #if self.param.sys_entry is not None and self.skip_sysenter:
            #    self.lgr.debug('entryModeChanged got sys_entry and told to skip sysenter')
            #    SIM_break_simulation('skip sysenter')
            if self.dumb_count > self.mode_entry_limit:
                self.lgr.debug('entryModeChanged did 1000')
                self.hack_stop = True
                SIM_break_simulation('did %s mode entries' % self.mode_entry_limit)
    
    def entryModeChangedWin(self, dumb, one, old, new):
        ''' HAP entered when mode changes looking for kernel entry '''
        if self.entry_mode_hap is None:
            return
        self.hack_stop = False
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        self.lgr.debug('entryModeChangedWin eip 0x%x cycles: 0x%x' % (eip, self.cpu.cycles)) 
        if old == Sim_CPU_Mode_Supervisor:
            if eip not in self.hits:
                self.hits.append(eip)
                instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
                self.lgr.debug('entryModeChangedWin kernel exit eip 0x%x %s' % (eip, instruct[1]))
                if instruct[1].startswith('iret'):
                    self.param.iretd = eip
                    self.lgr.debug('entryModeChangedWin got iretd 0x%x' % eip)
                elif instruct[1] == 'sysexit':
                    self.param.sysexit = eip
                elif instruct[1] == 'sysret64':
                    self.param.sysret64 = eip
                if self.param.iretd is not None and self.param.sysexit is not None:
                    self.lgr.debug('entryModeChangedWin found exits')
                    self.hack_stop = True
                    SIM_break_simulation('entryModeChangedWin found sysexit and iretd')
        elif old == Sim_CPU_Mode_User:
            self.lgr.debug('entryModeChangedWin entering kernel')
            self.dumb_count += 1
            instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)

            self.prev_instruct = instruct[1]
            self.lgr.debug('entryModeChangedWin supervisor eip 0x%x instruct %s count %d' % (eip, instruct[1], self.dumb_count))

            if self.param.sysenter is None and (instruct[1].startswith('sysenter') or instruct[1].startswith('syscall')):
                self.lgr.debug('mode changed old %d  new %d eip: 0x%x %s' % (old, new, eip, instruct[1]))
                self.lgr.debug('entryModeChangedWin found sysenter')
                self.hack_stop = True
                SIM_break_simulation('entryModeChangedWin found sysenter')
            elif self.param.sysenter is not None:
                self.lgr.debug('entryModeChangedWin alread found sysenter??')
                self.hack_stop = True
                SIM_break_simulation('entryModeChangedWin alread found sysenter??')
            else:
                self.lgr.debug('entryModeChangedWin what to do?')

    def stepCompute(self, compat32=False): 
        # find the jump table used for system calls and record the 2 parameters needed to recreate the jump address
        # based on the call
        self.lgr.debug('stepCompute')
        SIM_delete_breakpoint(self.task_break)
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_hap)
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.task_hap = None
        self.stop_hap = None
        #print('remove this')
        #return
        count = 0
        if self.cpu.architecture == 'arm':
            prefix = 'ldrcc pc, [r8, r7, LSL #2]'
            eip = self.mem_utils.getRegValue(self.cpu, 'pc')
            if not self.mem_utils.isKernel(eip):
                self.lgr.error('stepCompute returned to user space')
                return
            instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
            self.lgr.debug('stepCompute arm pc 0x%x  %s' % (eip, instruct[1]))
            while True:
                SIM_run_command('si -q')
                prev_eip = eip
                prev_instruct = instruct
                eip = self.mem_utils.getRegValue(self.cpu, 'pc')
                instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
                if not decodeArm.isBranch(self.cpu, prev_instruct[1])  and eip != prev_eip + 4:
                    self.lgr.debug('stepCompute eip 0x%x does not follow previous 0x%x, instruct %s' % (eip, prev_eip, instruct[1]))
                    print('stepping interrupted, try again')
                    SIM_run_alone(self.findCompute, False)
                    return
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
        elif self.cpu.architecture == 'arm64':
            # Need to get values for 32 and 64 bit apps.  TBD override switch for just one of them 
            print('arm64 compute.  walk forward to find computed jump')
            self.lgr.debug('arm64 compute.  walk forward to find computed jump')
            # x20 is the syscall number.  
            prefix = 'ldr x1, [x22, x20, lsl #3]'
            eip = self.mem_utils.getRegValue(self.cpu, 'pc')
            if not self.mem_utils.isKernel(eip):
                self.lgr.error('stepCompute returned to user space')
                return
            instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
            self.lgr.debug('stepCompute arm64 pc 0x%x  %s' % (eip, instruct[1]))
            while True:
                SIM_run_command('si -q')
                prev_eip = eip
                prev_instruct = instruct
                eip = self.mem_utils.getRegValue(self.cpu, 'pc')
                instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
                self.lgr.debug('stepCompute arm64 pc 0x%x  %s' % (eip, instruct[1]))
                if not decodeArm.isBranch(self.cpu, prev_instruct[1])  and eip != prev_eip + 4:
                    self.lgr.debug('stepCompute eip 0x%x does not follow previous 0x%x, instruct %s' % (eip, prev_eip, instruct[1]))
                    print('stepping interrupted, try again')
                    SIM_run_alone(self.findCompute, False)
                    return
                if instruct[1].startswith(prefix):
                    #self.param.syscall_compute = eip
                    print(instruct[1])
                    esr_el1 = self.getEL1()
                    if esr_el1 == 0x11:
                        self.param.syscall_jump = self.mem_utils.getRegValue(self.cpu, 'x22')
                        self.lgr.debug('got compute at 0x%x jump constant for 32 bit is 0x%x  %s' % (eip, self.param.syscall_jump, instruct[1]))
                    elif esr_el1 == 0x15:
                        self.param.syscall64_jump = self.mem_utils.getRegValue(self.cpu, 'x22')
                        self.lgr.debug('got compute at 0x%x jump constant for 64 bit is 0x%x  %s' % (eip, self.param.syscall64_jump, instruct[1]))
                    else:
                        self.lgr.error('arm64 compute esr_el1 not for syscall? 0x%x' % esr_el1)
                        return
                    break
                count += 1
                if count > 1000:
                    self.lgr.error('failed to find compute %s  for ARM64' % prefix)
                    SIM_break_simulation('failed to find compute %s for ARM64' % prefix)
                    return
            # assumes we look for arm32 first if it was needed.
            if self.want_arm64 and self.param.syscall64_jump is None:
                self.lgr.debug('stepCompute got arm32 now look for arm64 compute')
                self.findCompute()
            else:
                ''' armv8 page fault entry is same as syscall entry, call it done'''
                self.saveParam()
        elif self.os_type == 'WIN7':
            # looks like  cs:0xfffff800034f1e1d p:0x0034f1e1d  movsx r11,dword ptr [r10+rax*4]
            #             cs:0xfffff800034f1e24 p:0x0034f1e24  sar r11,4
            #             cs:0xfffff800034f1e28 p:0x0034f1e28  add r10,r11

            ptr2stack_prefix = 'mov rsp,qword ptr gs:'
            other_ptr2stack_prefix = 'mov qword ptr gs:'
            prefix = 'movsx r11,dword ptr [r10'
            other_prefix = 'movsxd r11,dword ptr [r10'
            reg_num = self.cpu.iface.int_register.get_number("cr3")
            cr3 = self.cpu.iface.int_register.read(reg_num)
            starting_cr3 = cr3
            self.lgr.debug('starting cr3 0x%x' % cr3)
            while True:
                SIM_run_command('si -q')
                rip = self.mem_utils.getRegValue(self.cpu, 'rip')
                instruct = my_SIM_disassemble_address(self.cpu, rip, 1, 0)
                self.lgr.debug('stepCompute rip: 0x%x instruct: %s' % (rip, instruct[1]))
                if not self.mem_utils.isKernel(rip):
                    self.lgr.error('stepCompute returned to user space rip 0x%X  kernel_base 0x%x' % (rip, self.param.kernel_base))
                    return
                ''' TBD tenuous '''
                if instruct[1].startswith(ptr2stack_prefix):
                    last = instruct[1].split()[-1].strip()
                    content = last.split('[', 1)[1].split(']')[0]
                    if '0x60' in content:
                        self.lgr.debug('stepCompute we believe there is a saved cr3 in this kernel')
                        no_cr3 = False
                    else:
                        self.lgr.debug('stepCompute we believe there is no saved cr3 in this kernel')
                        no_cr3 = True
                    if not no_cr3:
                        value = int(content, 16)
                        if self.param.saved_cr3 is None:
                            self.param.saved_cr3 = value
                            gs_base = self.cpu.ia32_gs_base
                            ptr = gs_base + value
                            phys_block = self.cpu.iface.processor_info.logical_to_physical(ptr, Sim_Access_Read)
                            self.win7_saved_cr3_phys = phys_block.address
                            self.lgr.debug('stepCompute instruct %s param.saved_cr3 to 0x%x ptr 0x%x win7_saved_cr3 0x%x' % (instruct[1], self.param.saved_cr3,
                                ptr, self.win7_saved_cr3_phys))
                        elif self.param.ptr2stack is None:
                            self.param.ptr2stack = value
                            self.lgr.debug('stepCompute saved ptr2stack as 0x%x' % value)
                        else:
                            self.lgr.error('stepCompute confused')
                elif instruct[1].startswith(other_ptr2stack_prefix) and instruct[1].endswith('rsp'):
                    ''' get offset from gs of where user stack stored'''
                    after = instruct[1][len(other_ptr2stack_prefix):]
                    bracketed = after.split(',')[0]
                    content = bracketed.split('[', 1)[1].split(']')[0]
                    value = int(content, 16)
                    self.param.ptr2stack = value
                    self.lgr.debug('stepCompute saved other ptr2stack as 0x%x' % value)
                       
                elif instruct[1].startswith(prefix) or instruct[1].startswith(other_prefix):
                    self.param.syscall_compute = rip
                    self.param.syscall_jump = self.mem_utils.getRegValue(self.cpu, 'r10')
                    self.lgr.debug('stepCompute win7 syscall_compute 0x%x syscall_jump 0x%x' % (self.param.syscall_compute, self.param.syscall_jump))
                    #SIM_run_alone(self.testCompute, eip)
                    break
            #end while
            SIM_run_alone(self.setPageFaultHap, None)
            # Above is Windows
        else:
            ''' find where we do the syscall jump table computation '''
            prefix = 'call dword ptr [eax*4'
            prefix1 = 'mov eax,dword ptr [eax*4'
            prefix2 = 'mov eax,dword ptr [eax*4'
            if self.mem_utils.WORD_SIZE == 8:
                prefix = 'call qword ptr [rax*8'
                prefix1 = 'mov rax,qword ptr [rbx*8-'
                prefix2 = 'mov rax,qword ptr [rax*8-'
            prev_instruct = None
            prev_eip = None
            while True:
                SIM_run_command('si -q')
                eip = self.mem_utils.getRegValue(self.cpu, 'eip')
                if not self.mem_utils.isKernel(eip):
                    self.lgr.error('stepCompute returned to user space')
                    return
                instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
                self.lgr.debug('eip: 0x%x instruct: %s' % (eip, instruct[1]))
                if instruct[1].startswith(prefix) or instruct[1].startswith(prefix1) or instruct[1].startswith(prefix2):
                    if compat32:
                        self.param.compat_32_compute = eip
                        print(instruct[1])
                        self.param.compat_32_jump = int(instruct[1].split('-')[1][:-1], 16)
                        self.lgr.debug('got compute compat32 at 0x%x jump constant is 0x%x  %s' % (eip, self.param.compat_32_jump, instruct[1]))
                    else:
                        self.param.syscall_compute = eip
                        print(instruct[1])
                        self.param.syscall_jump = int(instruct[1].split('-')[1][:-1], 16)
                        self.lgr.debug('got compute at count %d 0x%x jump constant is 0x%x  %s' % (count, eip, self.param.syscall_jump, instruct[1]))
                    break
                elif instruct[1].startswith('je ') and prev_instruct.startswith('cmp edx'):
                    self.lgr.debug('stepCompute believe coded jump table at 0x%x' % prev_eip)
                    self.computeJumpTable(prev_eip)
                    # kernel syscall handling location for use in fixStackFrame
                    self.param.syscall_compute = prev_eip
                    break
                elif instruct[1].startswith('je ') and prev_instruct.startswith('cmp esi'):
                    self.lgr.debug('stepCompute believe esi-based coded jump table at 0x%x' % prev_eip)
                    self.computeESIJumpTable(prev_eip)
                    # kernel syscall handling location for use in fixStackFrame
                    self.param.syscall_compute = prev_eip
                    break
                count += 1
                if count > 3000:
                    self.lgr.error('x86 failed to find compute %s for X86' % prefix)
                    break
                prev_instruct = instruct[1]
                prev_eip = eip
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

    def isSyscall(self):
        reg_num = self.cpu.iface.int_register.get_number('esr_el1')
        reg_value = self.cpu.iface.int_register.read(reg_num)
        reg_value = reg_value >> 26
        if reg_value == 0x11 or reg_value == 0x15:
            return True
        else:
            return False

    def computeDoStop(self, compat32, third, forth, memory):
        # entered via break at kernel entry address
        if self.cpu.architecture != 'arm' and self.os_type == 'WIN7':
            rax = self.mem_utils.getRegValue(self.cpu, 'rax')
            ''' TBD handle different windows syscall jump tables '''
            if rax > 500:
                self.lgr.debug('skip this call...')
                return
            self.lgr.debug('computeDoStop must be at sys_entry rax is %d' % rax)

        if self.cpu.architecture == 'arm64':
            # armv8 syscalls and page faults all come in via same kernel address.  Uses esr_el1
            # to determine which?
            
            esr_el1 = self.getEL1()
            if esr_el1 == 0x11 and self.param.syscall_jump is None:
                self.lgr.debug('computeDoStop arm64 looks like 32 bit syscall and we do not yet have syscall_jump, now call computeDoStopAlone')
                SIM_run_alone(self.computeDoStopAlone, compat32)
            elif esr_el1 == 0x15 and self.param.syscall64_jump is None:
                self.lgr.debug('computeDoStop arm64 looks like 64 bit syscall and we do not yet have syscall64_jump, now call computeDoStopAlone')
                SIM_run_alone(self.computeDoStopAlone, compat32)
            else:
                self.lgr.debug('computeDoStop arm64 not a syscall')

        else:
            self.lgr.debug('computeDoStop now call computeDoStopAlone') 
            SIM_run_alone(self.computeDoStopAlone, compat32)

    def computeDoStopAlone(self, compat32):
        self.lgr.debug('computeDoStopAlone') 
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.computeStopHap, compat32)
        SIM_break_simulation('computeDoStop')

    def testComputeHap(self, dumb, third, forth, memory):
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        r15 = self.mem_utils.getRegValue(self.cpu, 'r15')
        rcx = self.mem_utils.getRegValue(self.cpu, 'rcx')
        instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('testComputeHap instruct is %s eip 0x%x  r15 0x%x  rcx 0x%x' % (instruct[1], eip, r15, rcx))
    
    def testCompute(self, eip):
        self.task_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, eip, 1, 0)
        self.task_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.testComputeHap, None, self.task_break)

    def findCompute(self, compat32=False):
        # find value(s) needed to compute jump table destination of system calls.
        #cell = self.cell_config.cell_context[self.target]
        self.lgr.debug('findCompute')
        if self.cpu.architecture.startswith('arm'):
            if self.want_arm32 and self.param.syscall_jump is None and not self.only_64:
                print('Looking for ARM 32-bit app syscall jump table computation.  Cause an arm32 syscall to happen.')
                self.task_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_entry, 1, 0)
                self.lgr.debug('findCompute task break set on 0x%x' % self.param.arm_entry)
            elif self.want_arm64 and self.param.syscall64_jump is None:
                print('Looking for ARM 64-bit app syscall jump table computation.  Cause an arm64 syscall to happen.')
                self.task_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.param.arm64_entry, 1, 0)
                self.lgr.debug('findCompute task break set on 0x%x' % self.param.arm64_entry)
            self.task_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.computeDoStop, compat32, self.task_break)
            self.continueAhead()
        
        elif self.cpu.architecture == 'ppc32':
            # already gotten from ppcKernelParams
            self.saveParam()
        else:
            if compat32:
                entry = self.param.compat_32_entry
            #elif self.mem_utils.WORD_SIZE == 4:
            elif self.param.sysenter is None:
                entry = self.param.sys_entry
            else:
                entry = self.param.sysenter
            # running room away from entry so we can debug
            SIM_continue(100)
            self.lgr.debug('findCompute set break on sysenter 0x%x cycle 0x%x' % (entry, self.cpu.cycles))
            self.task_break = SIM_breakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
            self.task_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.computeDoStop, None, self.task_break)
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
        self.gs_stop_hap = False

    def getEntries(self):
        ''' Get kernel entry point information.  We found a kernel entry via a mode hap, and then stopped the
            simulation so that we can get the kernel address that is hit. (during mode hap entry, the eip is from where we came from.)'''
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_num')
        instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('getEntries instruct is %s prev_instruct %s eip 0x%x  len %d' % (self.prev_instruct, instruct[1], eip, instruct[0]))
        if self.prev_instruct.startswith('int 128') and self.param.sys_entry is None:
            self.lgr.debug('getEntries is int 128 0x%x' % eip)
            self.param.sys_entry = eip 

            ''' NOTE MUST delete these before call to findCompute'''
            #SIM_hap_delete_callback_id("Core_Mode_Change", self.entry_mode_hap)
            #self.entry_mode_hap = None
            #SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            #self.stop_hap = None
            #SIM_run_alone(self.findCompute, None)

        elif (self.prev_instruct == 'sysenter' or self.prev_instruct == 'syscall') and self.param.sysenter is None:
            self.lgr.debug('getEntries is sysenter eax %d eip: 0x%x' % (eax, eip))
            #TBD FIX HACK
            if self.prev_instruct == 'syscall':
                self.param.sys_entry = 0
            self.param.sysenter = eip 
            #SIM_run_alone(self.findCompute, None)
            
        if self.dumb_count > self.mode_entry_limit and (self.param.sysenter is not None or self.skip_sysenter) and self.param.sys_entry is not None \
                 and (self.param.sysexit is not None or self.skip_sysenter or self.mem_utils.WORD_SIZE==8) and self.param.iretd is not None \
                 and not (self.mem_utils.WORD_SIZE == 8 and self.param.sysret64 is None):
            SIM_run_alone(self.deleteHaps, None)

            self.lgr.debug('kernel entry and exits found')

            ''' HERE is where we do more stuff, at the end of this HAP '''
            #param_json = json.dumps(self.param)
            #SIM_run_alone(self.fixStackFrame, None)
            SIM_run_alone(self.findCompute, False)
        else: 
            self.lgr.debug('getEntries not done collecting sys enter/exit, so continue')
            SIM_run_alone(self.continueAhead, None)

    def getWinEntries(self):
        rip = self.mem_utils.getRegValue(self.cpu, 'rip')
        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_num')
        instruct = my_SIM_disassemble_address(self.cpu, rip, 1, 0)
        self.lgr.debug('getWinEntries instruct is %s prev_instruct %s rip 0x%x  len %d' % (self.prev_instruct, instruct[1], rip, instruct[0]))
        do_not_continue = False
        if (self.prev_instruct == 'sysenter' or self.prev_instruct == 'syscall') and self.param.sysenter is None:
            #TBD FIX HACK
            if self.prev_instruct == 'syscall':
                self.param.sys_entry = 0
            self.param.sysenter = rip 
            self.lgr.debug('getWinEntries is sysenter eax %d param.sysenter 0x%x' % (eax, self.param.sysenter))
            #SIM_run_alone(self.findCompute, None)
            
        if self.param.sysenter is not None and self.param.sysret64 is not None:
            SIM_run_alone(self.deleteHaps, None)
            self.lgr.debug('kernel entry and exits found')

            ''' HERE is where we do more stuff, at the end of this HAP '''
            SIM_run_alone(self.findCompute, False)
            #print('would find compute here')
        elif not do_not_continue:
            self.lgr.debug('getWinEntries not done collecting sys enter/exit, so continue')
            SIM_run_alone(self.continueAhead, None)

    def entryStopHap(self, dumb, one, exception, error_string):
        ''' called when mode hap determines this is a kernel entry, and other times.  Needs cleanup, very obscure. '''
        self.lgr.debug('entryStopHap')
        if self.stop_hap is None:
            self.lgr.debug('entryStopHap haps was none bail')
            return
        pc = self.mem_utils.getRegValue(self.cpu, 'pc')
        self.lgr.debug('entryStopHap cycles: 0x%x exception %s  error_string %s pc 0x%x' % (self.cpu.cycles, str(exception), error_string, pc))
        if not self.hack_stop:
            self.lgr.debug('entryStopHap, hack stop not set')
            if self.param.syscall_jump is None:
                SIM_run_alone(self.deleteHaps, None)
                SIM_run_alone(self.findCompute, False)
            return
        else:
            self.lgr.debug('entryStopHap, hack stop set OK?')
        if self.cpu.cycles == self.hack_cycles:
            self.lgr.debug('entryStopHap, got nowhere before stop, continue and ignore?')
            SIM_run_alone(self.continueAhead, None)
        else:
            if self.stop_hap is not None: 
                self.getEntries()

    def entryStopHapWin(self, dumb, one, exception, error_string):
        if not self.hack_stop:
            self.lgr.debug('entryStopHap, hack stop not set')
            return
        if self.cpu.cycles == self.hack_cycles:
            self.lgr.debug('entryStopHap, got nowhere before stop, continue and ignore?')
            SIM_run_alone(self.continueAhead, None)
        else:
            if self.stop_hap is not None: 
                self.getWinEntries()
        self.lgr.debug('entryStopHapWin cycles 0x%x hack_cycles 0x%x' % (self.cpu.cycles, self.hack_cycles))

    def getEL1(self):
        reg_num = self.cpu.iface.int_register.get_number('esr_el1')
        reg_value = self.cpu.iface.int_register.read(reg_num)
        ret_value = reg_value >> 26
        self.lgr.debug('getEL1 reg_value 0x%x retval 0x%x' % (reg_value, ret_value))
        return ret_value


    def entryArmAlone(self, dumb):
        # we entered supervisor on arm from what we think is a syscall.  record syscall address
        # NOTE returns
        eip = self.mem_utils.getRegValue(self.cpu, 'pc')
        call_num = self.mem_utils.getRegValue(self.cpu, 'syscall_num')
        instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('entryArmAlone instruct is %s eip 0x%x  len %d prev is %s' % (instruct[1], eip, instruct[0], self.prev_instruct))
        if self.param.arm_entry is None and self.prev_instruct.startswith('svc 0'): 
            self.lgr.debug('entryStopHapARM set arm_entry to 0x%x' % eip) 
            self.param.arm_entry = eip 
        elif self.param.arm_entry is None and self.prev_instruct.startswith('svc'): 
            self.lgr.debug('entryStopHapARM SVC 0x9000 set arm_entry to 0x%x' % eip) 
            self.param.arm_entry = eip 
            self.param.arm_svc = True
        elif self.param.arm_entry is None and self.prev_instruct.startswith('broken'): 
            esr_el1 = self.getEL1()
            caller = None
            if esr_el1 == 0x11 :
                if self.param.arm_entry is not None:
                    SIM_run_command('continue')
                    return
                caller = 'aarch32'
            elif esr_el1 == 0x15: 
                if self.param.arm64_entry is not None:
                    SIM_run_command('continue')
                    return
                caller = 'aarch64'
            else:
                self.lgr.debug('entryStopHapARM esr_el1 0x%x, not syscall?, bail' % esr_el1)
                SIM_run_command('continue')
                return
            self.lgr.debug('entryStopHapARM arm64 do not yet know previous instruction, try back one')
            # hack to skip mode haps while we skip
            self.ignore_mode = True
            here = self.cpu.cycles 
            prev = self.cpu.cycles - 1
            self.skip_to_mgr.skipToTest(prev)
            eip = self.mem_utils.getRegValue(self.cpu, 'pc')
            self.lgr.debug('entryStopHapARM went back one eip now 0x%x caller %s' % (eip, caller))
            prev_instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
            if not prev_instruct[1].startswith('svc 0') and not prev_instruct[1].startswith('svc #0x0'):
                self.lgr.debug('entryStopHapARM user instruct at 0x%x is %s NOT svc, so continue' % (eip, prev_instruct[1]))
                self.ignore_mode = False
                SIM_run_command('continue')
                return
            else:
                self.lgr.debug('entryStopHapARM prev_instruct is %s' % prev_instruct[1])
                self.skip_to_mgr.skipToTest(here)
                eip = self.mem_utils.getRegValue(self.cpu, 'pc')
                if caller == 'aarch32':
                    self.param.arm_entry = eip 
                    self.lgr.debug('entryStopHapARM set arm_entry for v8 to 0x%x' % eip) 
                else:
                    self.param.arm64_entry = eip 
                    self.lgr.debug('entryStopHapARM set arm64_entry for v8 to 0x%x' % eip) 
            self.ignore_mode = False
           
        done = False
        if self.cpu.architecture == 'arm64':
            self.lgr.debug('entryStopHapARM is arm64')
            if self.only_64:
                self.lgr.debug('entryStopHapARM is only 64 bit')
                if self.param.arm64_entry is not None and self.param.arm_ret is not None:
                    done = True
            else:
                self.lgr.debug('entryStopHapARM is mixed 32/64 bit')
                if self.param.arm_entry is not None and self.param.arm64_entry is not None and self.param.arm_ret is not None:
                    done = True
        else:
            if self.param.arm_entry is not None and self.param.arm_ret is not None and self.param.arm_ret2 is not None:
                done = True
        
        if done:
            self.deleteHaps(None)
            self.lgr.debug('kernel entry and exits found')

            ''' HERE is where we do more stuff, at the end of this HAP '''
            #param_json = json.dumps(self.param)
            #SIM_run_alone(self.fixStackFrame, None)
            self.findCompute(False)
        else:
            self.lgr.debug('entryStopHapARM missing exit or entry, now continue')
            self.continueAhead(None)

    def entryStopHapARM(self, dumb, one, exception, error_string):
        if self.stop_hap is None: 
            return
        SIM_run_alone(self.entryArmAlone, None)

    def stopCompat32Hap(self, dumb, one, exception, error_string):
        if self.stop_hap is None: 
            return
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        if eip == self.param.sysenter:
            self.lgr.debug('stopCompat32Hap entry is same as sysentry, ignore')
            return
        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_num')
        instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
        dumb, comm, pid = self.taskUtils.curThread() 
        self.lgr.debug('stopCompat32Hap pid:%s instruct is %s prev %s  eip 0x%x  len %d' % (pid, instruct[1], self.prev_instruct, eip, instruct[0]))
       
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
        self.lgr.debug('compat32Entry added mode changed and stop hap, continue')
        self.continueAhead()

    def checkKernelEntry(self, dumb):
        ''' Use mode change haps to catch kernel entry and collected entry/exit information'''
        #SIM_run_command('enable-reverse-execution')
        self.lgr.debug('checkKernelEntry cycles: 0x%x' % self.cpu.cycles)
        self.dumb_count = 0
        self.hits = []
        if self.cpu.architecture.startswith('arm'):
            self.lgr.debug('checkKernelEntry add mode hap for arm')
            self.entry_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.entryModeChangedARM, False)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.entryStopHapARM, None)
        elif self.cpu.architecture == 'ppc32':
            self.lgr.error('checkKernelEntry not expected for for ppc32')
        elif self.os_type == 'WIN7':
            self.entry_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.entryModeChangedWin, False)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.entryStopHapWin, None)
        else:
            self.entry_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.entryModeChanged, False)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.entryStopHap, None)
        self.lgr.debug('checkKernelEntry added mode changed and stop hap, continue')
        self.continueAhead()

    def loadParam(self):
        self.lgr.debug('loadParam')
        fname = '%s.param' % self.target
        self.param = pickle.load( open(fname, 'rb') )

    def saveParam(self):
        self.lgr.debug(self.param.getParamString())
        self.lgr.debug('saveParam')
        fname = '%s.param' % self.target
        pickle.dump( self.param, open( fname, "wb" ) )
        self.param.printParams()
        print('Param file stored in %s current_task was 0x%x' % (fname, self.param.current_task))
        if self.run_from_snap is not None:
             pfile = os.path.join(self.run_from_snap, 'phys.pickle')
             prec = {}
             prec['current_task_phys'] = self.current_task_phys
             prec['saved_cr3_phys'] = self.win7_saved_cr3_phys
             pickle.dump(prec, open(pfile, 'wb'))
             print('current task phys addr written to %s' % pfile)
        if self.quit:
             SIM_run_command('quit')

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
        '''
        Find the user eip in the kernel parameter stack frame
        '''
        dumb, comm, pid = self.taskUtils.curThread() 
        self.lgr.debug('findUserEIP of 0x%x pid %s wanted %s' % (user_eip, pid, self.current_pid))
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
        '''
        For 32 bit x86 find where user eip is stored
        '''
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
            instruct = my_SIM_disassemble_address(self.cpu, eip, 1, 0)
            if instruct[1].startswith('int 128'):
                eax = self.mem_utils.getRegValue(self.cpu, 'eax')
                dumb, comm, self.current_pid = self.taskUtils.curThread() 
                self.lgr.debug('fixFrameModeChanged eip is 0x%x pid %s' % (eip, self.current_pid))
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
            if not self.cpu.architecture.startswith('arm'):
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
        if eip > self.param.kernel_base: 
            self.lgr.debug('pageFaultHap from kernel, skip')
            return
        SIM_break_simulation('pageFaultHap')
        '''
        if eip < self.param.kernel_base: 
            self.lgr.debug('pageFaultHap page_fault eip in user space?' % eip)
            SIM_break_simulation('pageFaultHap')
            pass
        else:
            self.param.page_fault = eip
            self.lgr.debug('pageFaultHap page_fault right off at 0x%x' % self.param.page_fault)
            SIM_run_alone(self.delPageHapAlone, None)
            if self.cpu.architecture != 'arm':
                self.saveParam()
            else:
                SIM_run_alone(self.setDataAbortHap, None)
        '''
        
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
       
    def go(self, force=False, skip_sysenter=False, quit=False, only_64=False): 
        ''' Initial method for gathering kernel parameters.  Will chain a number of functions, the first being runUntilSwapper '''
        self.quit = quit
        self.skip_sysenter = skip_sysenter
        self.force = force
        self.only_64 = only_64
        cpl = memUtils.getCPL(self.cpu)
        if self.os_type == 'WINXP':
             self.lgr.debug('is WINXP')
             winxpParams.WinxpParams(self.param, self.target)
        elif self.cpu.architecture == 'ppc32':
            self.ppc_kparams.getParams()
        elif cpl != 0:
            self.entry_mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.startInKernel, True)
            SIM_continue(0)
            #print('not in kernel, please run forward until in kernel')
            #return
        else:
            self.go2()

    def go2(self, dumb=None):
        if self.cpu.architecture.startswith('x86'):
            self.fs_base = self.cpu.ia32_fs_base
            if self.fs_base == 0 and not self.force:
                print('fs_base is zero, maybe just entered kernel?  consider running ahead a bit, or use gkp.go(True)')
                return
        self.lgr.debug('go2 call runUntilSwapper')
        self.runUntilSwapper()

    def startInKernel(self, cpu, one, old, new):
        self.lgr.debug('startInKernel')
        hap = self.entry_mode_hap
        self.entry_mode_hap = None
        SIM_run_alone(self.deleteModeAlone, hap)
        SIM_run_alone(self.go2, None)

    def deleteModeAlone(self, hap):
        if hap is not None:
            SIM_hap_delete_callback_id("Core_Mode_Change", hap)

    def compat32(self):
        self.loadParam()
        self.param.compat_32_entry = None
        self.param.compat_32_int128 = None
        self.compat32Entry()

    def continueAhead(self, dumb=None):
        self.hack_cycles = self.cpu.cycles
        self.lgr.debug('continueAhead hack_cycles 0x%x' % self.hack_cycles)
        if not SIM_simics_is_running():
            try:
                SIM_continue(0)
                self.lgr.debug('continueAhead did continue')
            except SimExc_General:
                self.lgr.debug('continueAhead exception on SIM_continue')
                pass
        else:
            self.lgr.debug('continueAhead was running')

    def getWin7CallParams(self, stop_on=None, only=None):
        ''' Use breakpoints set on the user space to identify call parameter 
            Optional stop_on will stop on exit from call'''
        cell_name = self.target 
        if 'RESIM_PARAM' in self.comp_dict[cell_name] and self.param.ts_pid is None:
            param_file = self.comp_dict[cell_name]['RESIM_PARAM']
            if os.path.isfile(param_file):
                self.param = pickle.load(open(param_file, 'rb'))
                self.lgr.debug('w7Tasks loaded params from %s' % param_file)
                if self.run_from_snap is not None:
                    pfile = os.path.join(self.run_from_snap, 'phys.pickle')
                    if os.path.isfile(pfile):
                        value = pickle.load(open(pfile, 'rb'))
                        if type(value) is int:
                            self.current_task_phys = pickle.load(open(pfile, 'rb'))
                        else:
                            self.current_task_phys = value['current_task_phys']
                    else:
                        self.lgr.error('getWin7CallParams, no file at %s, cannot run.  Generate params again.' % pfile)
                        return

    def test(self):
        rbx = self.mem_utils.getRegValue(self.cpu, 'rdi')
        ref_ptr = rbx
        #ref_ptr = self.mem_utils.readPtr(self.cpu, rsp)
        print('rbx is 0x%x ref_ptr 0x%x' % (rbx, ref_ptr))
        if ref_ptr is not None:
            b = self.mem_utils.readBytes(self.cpu, ref_ptr, 80)
            if b is not None:
                x = b.decode('utf-16be', errors='ignore')
                print('decoded be %s' % x)
                x = b.decode('utf-16le', errors='ignore')
                print('decoded le %s' % x)
                x = b.decode('utf-8', errors='ignore')
                print('decoded 8 %s' % x)
                x = b.decode('ascii', errors='ignore')
                print('decoded ascii %s' % x)

    def isWindows(self, cpu=None):
        if self.os_type.startswith('WIN'):
            return True
        else:
            return False

    def getPageTableDirectory(self):
        self.lgr.debug('getPageTableDirectory')
        retval = False
        if self.cpu.architecture == 'arm':
            ttbr = self.cpu.translation_table_base0
            page_dir_addr = ttbr & 0xfffff000
        elif self.cpu.architecture == 'arm64':
            ttbr = self.cpu.translation_table_base0
            page_dir_addr = ttbr & 0xfffff000
        else:
            reg_num = self.cpu.iface.int_register.get_number("cr3")
            #page_dir_addr = self.cpu.iface.int_register.read(reg_num)
            page_dir_addr = self.mem_utils.getKernelSavedCR3()
        proc_rec = self.taskUtils.getCurProcRec()
        self.lgr.debug('getPageTableDirectory proc rec 0x%x page_dir_addr 0x%x' % (proc_rec, page_dir_addr)) 
        start = self.param.ts_prev + 4
        ptr = proc_rec + start
        mm_struct = None
        mm_struct_off = None
        end = proc_rec + self.param.ts_pid 
        self.lgr.debug('getPageTableDirectory start 0x%x ptr 0x%x end 0x%x' % (start, ptr, end))
        while ptr < end:
            maybe = self.mem_utils.readPtr(self.cpu, ptr)
            self.lgr.debug('getPageTableDirectory ptr 0x%x maybe 0x%x' % (ptr, maybe))
            # noise reduction
            if maybe > 0x500:
                pgd_ptr = maybe
                for i in range(100):
                    pgd = self.mem_utils.readWord32(self.cpu, pgd_ptr)
                    if pgd is not None:
                        self.lgr.debug('\t pgd_ptr 0x%x   pgd 0x%x' % (pgd_ptr, pgd))
                        if pgd == page_dir_addr:
                            mm_struct = ptr - proc_rec
                            self.param.mm_struct = mm_struct
                            mm_struct_off = i * 4
                            self.param.mm_struct_offset = mm_struct_off
                            self.lgr.debug('getPageTableDirectory got it  mm_struct %d  offset %d' % (mm_struct, mm_struct_off))
                            retval = True
                            break
                    pgd_ptr = pgd_ptr+4
            ptr = ptr + 4
            if retval:
                break
        return retval

    def hasUserPageTable(self, cpu=None):
        return False

    def taskModeChangedArm64(self, cpu, one, old, new):
        if new == Sim_CPU_Mode_Hypervisor or old == Sim_CPU_Mode_Hypervisor:
            return  
        if new == Sim_CPU_Mode_User:
            return  
        self.lgr.debug('taskModeChangedArm64 old %d new %d' % (old, new))
        reg_num = self.cpu.iface.int_register.get_number('esr_el1')
        reg_value = self.cpu.iface.int_register.read(reg_num)
        reg_value = reg_value >> 26
        if reg_value != 0x11 and reg_value != 0x15:
            self.lgr.debug('taskModeChangedArm64 supervisor, but not syscall, bail')
            return
        ''' will piggy back on the currentTaskStopHap'''
        SIM_run_alone(self.delTaskModeAlone, None)
        self.arm64_hap = True
        self.param.current_task = None
        self.lgr.debug('taskModeChangedARM64 looks like syscall, now break')
        SIM_break_simulation('arm64 stop')

    def getARM64Task(self, dumb):
        self.deleteHaps(None)
        self.delCurrentTaskStopHap(None)
        self.delTaskModeAlone(None)
        done = False
        self.reverse_mgr.enableReverse()
        bailat = 1000
        i = 0
        our_reg = None
        self.lgr.debug('getARM64Task find sp_el0')
        while not done:
            i = i + 1
            if i > bailat:
                print('never found sp_el0 ref')
                return
            SIM_continue(1)
            pc = self.mem_utils.getRegValue(self.cpu, 'pc')
            instruct = my_SIM_disassemble_address(self.cpu, pc, 1, 0)
            #print('instruct at 0x%x is %s' % (pc, instruct[1]))
            if instruct[1].startswith('msr sp_el0'):
                done = True
                print('got instruct at 0x%x' % pc)
                op2, op1 = decodeArm.getOperands(instruct[1])
                print('operand 1 %s  2 %s' % (op1, op2))
                our_reg = op2
        done = False
        bailat = 1000
        i = 0
        our_exp = None
        while not done:
            i = i + 1
            if i > bailat:
                print('never found sp_el0 ref')
                return
            prev = self.cpu.cycles - 1
            self.skip_to_mgr.skipToTest(prev)
            pc = self.mem_utils.getRegValue(self.cpu, 'pc')
            instruct = my_SIM_disassemble_address(self.cpu, pc, 1, 0)
            if isinstance(instruct, tuple):
                print(instruct[1])
                op2, op1 = decodeArm.getOperands(instruct[1])
                if op1 == our_reg:
                    print('got our reg in %s' % instruct[1])
                    self.lgr.debug('got our reg in %s' % instruct[1])
                    done = True
                    our_expr = op2

        self.lgr.debug('arm64 our_expr is %s' % our_expr)
        addr = decodeArm.getAddressFromOperand(self.cpu, our_expr, self.lgr)
        self.param.current_task = addr
        self.lgr.debug('arm64 current_task found at 0x%x' % addr)

        try:
            phys_block = self.cpu.iface.processor_info.logical_to_physical(addr, Sim_Access_Read)
            phys = phys_block.address
        except:
            self.lgr.error('memUtils v2pKaddr logical_to_physical failed on 0x%x' % v)
            return

        self.current_task_phys = phys
        if self.current_task_phys is None:
            self.lgr.error('failed to get phys of current task 0x%x' % addr)
        else:
            self.lgr.debug('arm64 current_task phys at 0x%x' % self.current_task_phys)
            self.findSwapper()

    def ppcParams(self, kernel_enter, kernel_exit, current_task, phys_addr, compute_jump, super_pc):
        self.param.current_task = current_task
        self.current_task_phys = phys_addr
        self.param.page_fault = 0x400
        self.param.ppc32_entry = kernel_enter
        self.param.ppc32_ret = kernel_exit[0]
        self.param.ppc32_super_enter = super_pc
        if len(kernel_exit) > 1:
            self.param.ppc32_ret2 = kernel_exit[1]
        if len(kernel_exit) > 2:
            self.lgr.error('More than 2 kernel exits.  fix this')
            return
        self.param.syscall_jump = compute_jump
        print('think current_task is 0x%x phys: 0x%x' % (current_task, self.current_task_phys))
        self.findSwapper()

    def computeJumpTable(self, begin):
        '''
        The begin is the start of an in-code jump table.  Read the instructions to create a dictionary of calls to addresses
        '''
        #begin = 0x00000000c1000d43
        current = begin
        call_map = {}
        # code uses process of elimination
        last_call_elimination = None
        last_call = None
        look_for_call = False
        # record address of the call instructions (we think)
        for i in range(18000):
            instruct = SIM_disassemble_address(self.cpu, current, 1, 0)
            if instruct[1].startswith('cmp edx'):
                last_call_elimination = None
                try:
                    current_call = int(instruct[1].strip().split(',')[1], 16)
                    last_call = current_call
                except:
                    pass
                look_for_call = False
            elif instruct[1].startswith('jne'):
                look_for_call = True
                last_call_elimination = None
            elif instruct[1].startswith('je'):
                destination = instruct[1].strip().split()[1]
                if current_call not in call_map:
                    call_map[current_call] = int(destination, 16)
                last_call_elimination = current_call
                look_for_call = False
            elif instruct[1].startswith('call ') and last_call_elimination is not None:
                maybe_call = last_call_elimination + 1
                if maybe_call not in call_map:
                    call_map[maybe_call] = current
                last_call_elimination = None
                look_for_call = False
            elif instruct[1].startswith('call ') and look_for_call:
                if current_call not in call_map:
                    call_map[last_call] = current
                look_for_call = False
                last_call_elimination = None
            else:
                last_call_elimination = None
                look_for_call = False
            current = current + instruct[0]

        self.param.code_jump_table = call_map
        key_list = call_map.keys()
        self.lgr.debug('computeJumpTable len of key_list is %d' % len(key_list))

    def computeESIJumpTable(self, begin):
        call_map = {}
        stack = []
        #begin = 0xffffffffb8c04cd9
        stack.append(begin)
        current_call = None
        while len(stack) > 0:
            #if len(call_map) > 10:
            #    print('doneish')
            #    break
            current_eip = stack.pop()
            instruct = SIM_disassemble_address(self.cpu, current_eip, 1, 0)
            did_call = False
            #print('popped 0x%x instruct %s' % (current_eip, instruct[1]))
            while not did_call:
                if instruct[1].startswith('cmp esi'):
                    try:
                        current_call = int(instruct[1].strip().split(',')[1], 16)
                        if current_call > 0x200:
                            print('current call is 0x%x, eh?' % current_call)
                            break
                        last_call = current_call
                    except:
                        print('failed to get current call from %s' % instruct[1])
                        break
                elif instruct[1].startswith('test esi'):
                    #print('is test esi ip 0x%x' % current_eip)
                    current_call = 0
                    #current_eip = current_eip + instruct[0]
                    #instruct = SIM_disassemble_address(self.cpu, current_eip, 1, 0)
                else:
                    print('expected cmp esi, bail got %s' % instruct[1])
                    break
                current_eip = current_eip + instruct[0]
                instruct = SIM_disassemble_address(self.cpu, current_eip, 1, 0)
                #print('instruct %s' % instruct[1])
                if instruct[1].startswith('je'):
                    #print('is je instruct %s' % instruct[1])
                    jmp_eip = int(instruct[1].strip().split()[1], 16)
                    jmp_instruct = SIM_disassemble_address(self.cpu, jmp_eip, 1, 0)
                    #print('got je to eip  0x%x that instruct is %s' % (jmp_eip, instruct[1]))
                    call_to_eip = int(jmp_instruct[1].strip().split()[1], 16)
                    if current_call in call_map:
                        print('************** after je already has current_call 0x%x' % current_call)
                    else:
                        call_map[current_call] = jmp_eip
                        #if current_call < 8:
                        #    print('after je mapped 0x%x to 0x%x current_eip 0x%x' % (current_call, call_to_eip, current_eip))
                    current_eip = current_eip + instruct[0]
                    instruct = SIM_disassemble_address(self.cpu, current_eip, 1, 0)
                    if instruct[1].startswith('j'):
                        jump_to = int(instruct[1].strip().split()[1], 16)
                        #print('pushed jump_to after ja or jbe 0x%x' % jump_to)
                        stack.append(jump_to)
                        current_eip = current_eip + instruct[0]
                        instruct = SIM_disassemble_address(self.cpu, current_eip, 1, 0)
                    else:
                        if instruct[1].startswith('cmp esi'):
                            continue
                        else:
                            print('after je, expected a jump got %s' % instruct[1])
                            break
                    
                elif instruct[1].startswith('jne'):
                    jmp_to = int(instruct[1].strip().split()[1], 16)
                    jmp_instruct = SIM_disassemble_address(self.cpu, jmp_to, 1, 0)
                    if jmp_instruct[1].startswith('call'):
                        call_to_eip  = int(jmp_instruct[1].strip().split()[1], 16)
                        #call_plus_one = current_call + 1
                        #if call_plus_one in call_map:
                        #    print('************** already has call_plus_one 0x%x' % call_plus_one)
                        #call_map[call_plus_one] = call_to_eip
                        if current_call in call_map:
                            print('************** already has current_call 0x%x' % current_call)
                        elif False:
                            call_map[current_call] = call_to_eip
                            print('after jne mapped 0x%x to 0x%x' % (current_call, call_to_eip))
                    else:
                        print('confused expected call got %s' % jmp_instruct)
                        break
                    # expect next to be call for current_call
                    current_eip = current_eip + instruct[0]
                    instruct = SIM_disassemble_address(self.cpu, current_eip, 1, 0)
                    if instruct[1].startswith('call'):
                        call_to_eip = int(instruct[1].strip().split()[1], 16)
                        if current_call in call_map:
                            print('************** already has current_call 0x%x' % current_call)
                        else:
                            call_map[current_call] = current_eip
                            #if current_call < 8:
                            #    print('after jne mapped 0x%x to 0x%x current_eip 0x%x' % (current_call, call_to_eip, current_eip))
                        did_call = True
                else:
                    print('confused by instruct %s' % instruct[1])
                    break
            #print('broke after did_call')
            pass
        self.param.code_jump_table = call_map
        key_list = call_map.keys()
        self.lgr.debug('computeESIJumpTable len of key_list is %d' % len(key_list))

if __name__ == '__main__':
    gkp = GetKernelParams()
    #gkp.runUntilSwapper()
    ''' NOTE: see swapperStopHap hap for follow-on processing and the start of
        as stop hap chain '''
