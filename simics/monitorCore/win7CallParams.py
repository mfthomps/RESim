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
from simics import *
import os
import json
import struct
import binascii
import resimUtils
import memUtils
import taskUtils
import paramRefTracker
from resimHaps import *
'''
Functions for experimenting with Win7 
to determine how parameters are passed to the kernel.
These assume a param has been built containing the pid offset.
And it assumes the param includes the syscall_jump value
reflecting jump table values for syscalls.
The physical address of the current task record is passed in,
e.g., from getKernelParam.  A real system would compute that from
the param, using gs_base and logic to account for aslr.

'''
watch_stack_params = 6
class Win7CallParams():
    def __init__(self, top, cpu, cell, cell_name, mem_utils, task_utils, current_task_phys, param, lgr, stop_on=None, only=None, only_proc=None, track_params=False):
        self.top = top
        self.lgr = lgr
        self.param = param
        
        #self.current_task_phys = 0x3634188
        self.current_task_phys = current_task_phys
        self.entry = param.sysenter
        #self.entry = 0xfffff80003622bc0
        self.lgr.debug('Win7CallParams current task phys 0x%x sysenter 0x%x syscall_jump: 0x%x track_params: %r' % (self.current_task_phys, self.entry, param.syscall_jump, track_params))
        self.entry_break = None
        self.entry_hap = None
        self.exit_break = None
        self.exit_hap = None
        self.only = only
        self.only_proc = only_proc
        self.track_params = track_params
       
        self.user_break = None
        self.user_hap = None
        self.user_write_break = None
        self.user_write_hap = None
        self.param_ref_tracker = None

        self.current_call = {}
        self.entry_rsp = {}
        self.all_reg_values = {}


        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.cell = cell
        self.cell_name = cell_name
        self.cpu = cpu
        self.stop_on = stop_on
        resim_dir = os.getenv('RESIM_DIR')
        self.call_map = {}
        self.call_num_map = {}
        w7mapfile = os.path.join(resim_dir, 'windows', 'win7.json')
        if os.path.isfile(w7mapfile):
            cm = json.load(open(w7mapfile))     
            for call in cm:
                self.call_map[int(call)] = cm[call] 
                ''' drop Nt prefix'''
                self.call_num_map[cm[call][2:]] = int(call)
        else:
            self.lgr.error('Cannot open %s' % w7mapfile)
            return
        ''' track parameters to different calls '''
        self.call_param_offsets = {}


        context = 'RESim_%s' % self.cell_name
        try:
            obj = SIM_get_object(context)
        except:
            obj = None
  
        if obj is None:
            cmd = 'new-context %s' % context
            self.lgr.debug('cmd is %s' % cmd)
            SIM_run_command(cmd)
            obj = SIM_get_object(context)
        self.resim_context = obj
        self.lgr.debug('win7CallParams defining context cell %s resim_context defined as obj %s' % (self.cell_name, str(obj)))
        self.default_context = self.cpu.current_context
        if self.cpu.current_context == self.resim_context:
            self.lgr.debug('win7CallParams, already in RESim context, assume debugging')
            self.do_context_switch = False
        else:
            self.do_context_switch = True
      
        self.one_entry = None
        if only is not None:
            if only in self.call_num_map:
                call_num = self.call_num_map[only]
                self.one_entry = self.getComputed(call_num)
            else:
                self.lgr.error('%s not found in syscall map' % only)
                print('%s' % str(self.call_num_map))
                return

        self.reverse_to_call = True
        self.rev_entry_break = None
        self.rev_entry_hap = None
        self.rev_stop_hap = None

        if self.reverse_to_call and only is not None:
            SIM_run_command('enable-reverse-execution')
        if track_params:
            track_log_file = os.path.join('logs', 'call_params.log')
            self.track_log = open(track_log_file, 'w')
            self.lgr.debug('win7CallParams will log param tracking to %s' % track_log_file)
        else:
            self.track_log = None

        self.doBreaks()

    def doBreaks(self):
        ''' set breaks on syscall entries and exits '''
        if self.one_entry is not None:
            self.entry_break = SIM_breakpoint(self.default_context, Sim_Break_Linear, Sim_Access_Execute, self.one_entry, 1, 0)
            self.entry_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.oneCallHap, None, self.entry_break)
        else:
            self.entry_break = SIM_breakpoint(self.default_context, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
            self.entry_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.syscallHap, None, self.entry_break)
            if self.track_params:
                self.exit_break = SIM_breakpoint(self.default_context, Sim_Break_Linear, Sim_Access_Execute, self.param.sysret64, 1, 0)
                self.exit_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.exitHap, None, self.exit_break)
                self.lgr.debug('win7CallParams tracking params, exit set along with sysenter haps')
            else:
                self.lgr.debug('win7CallParams not tracking params')

    def getComputed(self, callnum):
        ''' given a call number, compute the address of the kernel code that handles the call
            based on observations made walking the instructions that follow syscall entry.''' 
        # looks like  cs:0xfffff800034f1e1d p:0x0034f1e1d  movsx r11,dword ptr [r10+rax*4]
        #             cs:0xfffff800034f1e24 p:0x0034f1e24  sar r11,4
        #             cs:0xfffff800034f1e28 p:0x0034f1e28  add r10,r11
        #                                          ....    call r10
        # syscall_jump is the r10 value.  TBD, this may change based on different call tables, e.g., 
        # windows has separate gui calls?  
        val = callnum * 4 + self.param.syscall_jump
        val = self.mem_utils.getUnsigned(val)
        self.lgr.debug('getComputed syscall_jump 0x%x  val 0x%x  callnum %d' % (self.param.syscall_jump, val, callnum))
        entry = self.mem_utils.readPtr(self.cpu, val)
        if entry is None:
            self.lgr.error('getComputed entry is None reading from 0x%x' % val)
            return None
        entry = entry & 0xffffffff
        entry_shifted = entry >> 4
        computed = self.param.syscall_jump + entry_shifted
        self.lgr.debug('getComputed call 0x%x val 0x%x entry 0x%x entry_shifted 0x%x computed 0x%x' % (callnum, val, entry, entry_shifted, computed))
        return computed

    def getCurPid(self):
        ''' TBD replace this and references to call to taskUtils'''
        pid = None
        comm = None
        cur_thread = SIM_read_phys_memory(self.cpu, self.current_task_phys, self.mem_utils.WORD_SIZE)
        if cur_thread is not None:
            cur_proc = self.mem_utils.readPtr(self.cpu, cur_thread+self.param.proc_ptr)
            if cur_proc is not None:
                pid_ptr = cur_proc + self.param.ts_pid
                pid = self.mem_utils.readWord(self.cpu, pid_ptr)
                if pid is not None:
                    #self.lgr.debug('getCurPid cur_proc, 0x%x pid_offset %d pid_ptr 0x%x pid %d' % (cur_proc, self.param.ts_pid, pid_ptr, pid))
                    comm = self.mem_utils.readString(self.cpu, cur_proc+self.param.ts_comm, 16)
            else:
                self.lgr.debug('getCurPid cur_proc is None reading cur_thread 0x%x' % cur_thread)
        else:
            self.lgr.debug('getCurPid cur_thread is None')
        return cur_proc, pid, comm

    def doParamTrack(self, rcx, rdx, r8, r9, rsp, call_name): 
        ''' Track kernel references to user space, recording which of the given parameter pointers the reference is relative to '''
        if self.do_context_switch:
            self.cpu.current_context = self.resim_context
        self.exit_break = SIM_breakpoint(self.resim_context, Sim_Break_Linear, Sim_Access_Execute, self.param.sysret64, 1, 0)
        self.exit_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.exitTrackHap, None, self.exit_break)

        self.user_break = SIM_breakpoint(self.resim_context, Sim_Break_Linear, Sim_Access_Read, 0, (self.param.kernel_base-1),  0)
        self.user_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.userReadHap, None, self.user_break)

        self.user_write_break = SIM_breakpoint(self.resim_context, Sim_Break_Linear, Sim_Access_Write, 0, (self.param.kernel_base-1),  0)
        self.user_write_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.userWriteHap, None, self.user_write_break)
        self.lgr.debug('doParamTrack exit and user breaks set, get a param tracker')
        self.param_ref_tracker = paramRefTracker.ParamRefTracker(rsp, rcx, rdx, r8, r9, self.mem_utils, self.cpu, call_name, self.lgr)
        #SIM_break_simulation('oneCallHap')

    def reverseToSyscall(self):
        ''' Call setReverse breaks after removing all breaks and haps '''
        self.lgr.debug('win7CallParams reverseToCall')
        SIM_run_alone(self.rmAllBreaks, self.setReverseBreaks) 

    def setReverseBreaks(self):
        ''' Set a breakpoint on the sysenter, set a stop hap and reverse'''
        if self.do_context_switch:
            self.cpu.current_context = self.resim_context
        self.lgr.debug('win7CallParams setReverseBreaks on 0x%x' % self.param.sysenter)
        self.rev_entry_break = SIM_breakpoint(self.resim_context, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
        self.rev_stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", self.stoppedAtSyscall, None)
        dumb, comm, pid = self.task_utils.curProc()
        #dumb, cur_addr, comm, pid = self.task_utils.currentProcessInfo()
        self.lgr.debug('setReverseBreaks do reverse comm %s pid:%d' % (comm, pid))
        SIM_run_command('reverse')

    def stoppedAtSyscall(self, stop_action, one, exception, error_string):
        ''' Should be stopped at the entry to the kernel'''
        dumb, comm, pid = self.task_utils.curProc()
        if pid is None:
            self.lgr.error('win7CallParams stoppedAtSyscall, pid is None?')
            #dumb, cur_addr, comm, pid = self.task_utils.currentProcessInfo()
            #self.lgr.debug('win7CallParams stoppedAtSyscall, TRIED again and pid is %s?' % pid)
        else:
            rip = self.mem_utils.getRegValue(self.cpu, 'rip')
            self.lgr.debug('win7CallParams stoppedAtSyscall pid:%d (%s) rip: 0x%x' % (pid,comm,rip))
            SIM_run_alone(self.rmAllBreaks, self.trackFromSysEntry)

    def oneCallHap(self, dumb, third, forth, memory):
        ''' Invoked when the "only" system call is hit at its computed entry '''
        #SIM_run_alone(SIM_run_command, 'enable-reverse-execution')
        dumb, comm, pid = self.task_utils.curProc()
        self.lgr.debug('oneCallHap only: %s pid:%d (%s)' % (self.only, pid, comm))

        if self.reverse_to_call:
            ''' Initiate a chain to cause simulation to reverse to the system call
                so that we can gather all parameter references '''
            self.lgr.debug('oneCallHap call stopAndGo to reverseToCall')
            self.top.stopAndGo(self.reverseToSyscall)
        else:
            self.lgr.warning('win7CallParams oneCallHap will not see references to pointers in stack!')
            gs_base = self.cpu.ia32_gs_base
            ptr2stack = gs_base+0x6008
            stack_val = self.mem_utils.readPtr(self.cpu, ptr2stack)
            user_stack = self.mem_utils.readPtr(self.cpu, stack_val-16)
            #r10 = self.mem_utils.getRegValue(self.cpu, 'rcx')
            #rcx = self.mem_utils.readPtr(self.cpu, stack_val-40)
            rcx = self.mem_utils.getRegValue(self.cpu, 'rcx')
            rdx = self.mem_utils.getRegValue(self.cpu, 'rdx')
            r8 = self.mem_utils.getRegValue(self.cpu, 'r8')
            r9 = self.mem_utils.getRegValue(self.cpu, 'r9')
            self.lgr.debug('oneCallHap ptr2stack 0x%x stack_val 0x%x user_stack 0x%x, rcx: 0x%x rdx: 0x%x, r8:0x%x, r9:0x%x cycles: 0x%x' % (ptr2stack, stack_val, 
                  user_stack, rcx, rdx, r8, r9, self.cpu.cycles))
            self.doParamTrack(rcx, rdx, r8, r9, rsp, self.only)
            #SIM_break_simulation('onecall userstack 0x%x' % user_stack)

    def trackFromSysEntry(self, call_name=None):
        ''' Assuming we are at the sysentry, track kernel references to user space'''
        self.lgr.debug('trackFromSysEntry')
        rsp = self.mem_utils.getRegValue(self.cpu, 'rsp')
        rcx = self.mem_utils.getRegValue(self.cpu, 'r10')
        rdx = self.mem_utils.getRegValue(self.cpu, 'rdx')
        r8 = self.mem_utils.getRegValue(self.cpu, 'r8')
        r9 = self.mem_utils.getRegValue(self.cpu, 'r9')
        self.doParamTrack(rcx, rdx, r8, r9, rsp, call_name)
        status = SIM_simics_is_running()
        if not status:
            self.lgr.debug('trackFromSysEntry Simics not running, go')
            SIM_continue(0)

    def syscallHap(self, dumb, third, forth, memory):
        ''' hit when kernel is entered due to sysenter '''
        self.lgr.debug('sycallHap')
        dumb, comm, pid = self.task_utils.curProc()
        #SIM_break_simulation(pid)
        #return
        #if pid is None:
        #    print('oh no')
        #    return
        if pid is not None:
            rax = self.mem_utils.getRegValue(self.cpu, 'rax')
            self.lgr.debug('syscallHap pid:%d (%s) call %d' % (pid, comm, rax))
            ''' Use the call map to get the call name, and strip off "nt" '''
            if rax in self.call_map:
                call_name = self.call_map[rax][2:]

                if call_name == 'RaiseException':
                    ''' This will just bounce to a user space exception handler.
                        Do not track or confusion will reign. '''
                    self.lgr.debug('syscallHap got RaiseException, just return')
                    return

                computed = self.getComputed(rax)
                if computed is not None:
                    self.lgr.debug('syscallHap pid:%d (%s) call %s computed is 0x%x' % (pid, comm, call_name, computed))
                else:
                    self.lgr.error('syscallHap pid:%d could not compute syscall entry for call %d' % (pid, rax))

                #if call_name == 'OpenFile':
                #    SIM_break_simulation('open file') 
                #if not self.got_one and call_name != 'OpenFile':
                #    #self.lgr.debug('syscallHap looking for Open got %s' % call_name)
                #    return
                #self.got_one = True
                self.current_call[pid] = rax
                rsp = self.mem_utils.getRegValue(self.cpu, 'rsp')
                self.entry_rsp[pid] = rsp
                self.lgr.debug('syscallHap pid:%d (%s) rsp: 0x%x rax: %d call: %s' % (pid, comm, rsp, rax, call_name)) 
                if call_name == self.stop_on:
                    SIM_break_simulation('syscall stop on call')

                self.all_reg_values[pid] = self.allRegValues()
                if self.track_params:
                    self.trackFromSysEntry(call_name=call_name)
 
            self.lgr.debug('call number %d not in call map, pid:%d' % (rax, pid))
        else:
            self.lgr.error('win7CallParam syscallHap Got no pid')

    def allRegValues(self):
        msg = ''
        for reg in self.mem_utils.ia64_regs:
            value = self.mem_utils.getRegValue(self.cpu, reg)
            msg_add = '%s: 0x%x ' % (reg, value)
            msg = msg+msg_add
        return msg
 
    class DelRec():
        def __init__(self, break_num, hap, pid):
            self.break_num = break_num
            self.hap = hap
            self.pid = pid

    def rmAllBreaks(self, and_then=None):
        ''' Remove all breakpionts/haps and then call a given function,
            which may set some of the breaks we deleted.  This avoids a race
            when rmAllBreaks is called from SIM_run_alone. 
        '''
           
        self.lgr.debug('win7CallParams rmAllBreaks')
        self.rmUserBreaks()
        if self.exit_hap is not None:
            self.lgr.debug('win7CallParams remove exit breaks')
            self.stopWatchExit(self.exit_hap)
            self.exit_hap = None
        if self.entry_hap is not None:
            self.lgr.debug('win7CallParams remove entry breaks')
            SIM_delete_breakpoint(self.entry_break)
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.entry_hap)
            self.entry_hap = None
        if self.rev_entry_break is not None:
            self.lgr.debug('win7CallParams remove rev_entry breaks')
            SIM_delete_breakpoint(self.rev_entry_break)
            self.rev_entry_break = None
        if self.rev_stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.rev_stop_hap)
            self.rev_stop_hap = None
        if and_then is not None:
            and_then()
        
 
    def rmUserBreaks(self):
        if self.user_hap is not None:
            self.lgr.debug('win7CallParams rmUserBreaks')
            SIM_run_alone(self.rmUserHap, self.user_hap)
            self.user_hap = None
            SIM_run_alone(self.rmUserWriteHap, self.user_write_hap)
            self.user_write_hap = None

    def exitTrackHap(self, dumb, third, forth, memory):
        ''' Hit when exiting kernel from call whose parameters were tracked '''
        if self.exit_hap is not None:
            self.lgr.debug('exitTrackHap, return to default context and remove exit hap')
            SIM_run_alone(self.stopWatchExit, self.exit_hap)
            self.exit_hap = None

        self.rmUserBreaks()   

        #params = self.param_ref_tracker.toString()
        #print(params)
        #self.lgr.debug(params)
        self.param_ref_tracker.mergeRef()
        self.lgr.debug('after merge')
        params = self.param_ref_tracker.toString()
        dumb, comm, pid = self.task_utils.curProc()
        if pid is not None:
            if self.track_log is None:
                print('pid:%d (%s) %s' % (pid, comm, params))
            else:
                self.track_log.write('pid:%d (%s) %s\n' % (pid, comm, params))
        else:
            self.lgr.error('exitTrackHap got pid of None')
            SIM_break_simulation('fix this')
        self.lgr.debug(params)
        exit_frame = self.task_utils.frameFromRegs()
        #frame_string = taskUtils.stringFromFrame(exit_frame)
        rax = self.mem_utils.getRegValue(self.cpu, 'rax')
        #print(frame_string)
        if self.track_log is None:
            print('rax return 0x%x\n\n' % rax)
        else:
            self.track_log.write('rax return 0x%x\n\n' % rax)
        #self.track_log.flush()
        if self.only_proc is not None and self.only == 'CreateUserProcess' and self.only_proc not in params:
            self.lgr.debug('exitTrackHap did not find proc we were looking for')
        else:
            if self.only is not None:
                SIM_break_simulation('exitTrackHap rax 0x%x' % rax)
                if self.reverse_to_call:
                    self.doBreaks()
            else:
                pass
                #SIM_break_simulation('exitTrackHap rax 0x%x' % rax)
            self.lgr.debug('win7CallParams exitTrackHap rax 0x%x' % rax)

    def rmUserHap(self, user_hap):
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", user_hap)
        if self.user_break is not None:
            SIM_delete_breakpoint(self.user_break)
            self.user_break = None
     
    def rmUserWriteHap(self, user_write_hap):
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", user_write_hap)
        if self.user_write_break is not None:
            SIM_delete_breakpoint(self.user_write_break)
            self.user_write_break = None
     
 
    def exitHap(self, dumb, third, forth, memory):
        ''' hit when kernel is about to exit back to user space via sysret64 '''
        #self.lgr.debug('exitHap')
        if self.exit_hap is None:
            return
        dumb, comm, pid = self.task_utils.curProc()
        call_name = None
        if pid is None:
            return
        if pid is not None:
            rax = self.mem_utils.getRegValue(self.cpu, 'rax')
            if pid is not None:
                self.lgr.debug('exitHap pid:%d (%s) rax: 0x%x' % (pid, comm, rax))
            if pid in self.all_reg_values:
                self.lgr.debug(self.all_reg_values[pid])

            if pid in self.current_call and self.current_call[pid] in self.call_map:
                call_name = self.call_map[self.current_call[pid]][2:]
                #self.lgr.debug('exitHap callname %s' % call_name)
            if self.stop_on is not None:
                #self.lgr.debug('exitHap stopon is %s and pid' % self.stop_on)
                if call_name is not None:
                    if call_name == self.stop_on:
                        SIM_break_simulation('exitHap stop on call')


    def stopWatchExit(self, exit_hap):
        if self.do_context_switch:
            self.cpu.current_context = self.default_context
            self.lgr.debug('stopWatchExit cpu reset to %s'  % str(self.cpu.current_context))
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", exit_hap)
        if self.exit_break is not None:
            SIM_delete_breakpoint(self.exit_break)
            self.exit_break = None
 
    def userReadHap(self, dumb, third, forth, memory):
        if self.user_hap is None:
            return
        cpl = memUtils.getCPL(self.cpu)
        if cpl != 0:
            self.lgr.error('userReadHap not in kernel???')
            SIM_break_simulation('fix this')
            return
        dumb, comm, pid = self.task_utils.curProc()
        #self.lgr.debug('win7CallParams pid:%d userReadHap memory 0x%x len %d current_context %s' % (pid, memory.logical_address, memory.size, str(self.cpu.current_context)))
        orig_value = self.mem_utils.readBytes(self.cpu, memory.logical_address, memory.size)
        if orig_value is not None:
            value = bytearray(orig_value)
            value.reverse()
            other_ptr = None
            if memory.size == 8:
                param_ptr = struct.unpack(">Q", value)[0]
                #self.lgr.debug('\tuserReadHap paramPtr  0x%x' % param_ptr)
                if param_ptr is not None and param_ptr != 0:
                    test = self.mem_utils.readWord(self.cpu, param_ptr)
                    if test is not None:
                        #self.lgr.debug('\tuserReadHap good paramPtr 0x%x' % param_ptr)
                        other_ptr = param_ptr    
                
            hexstring = binascii.hexlify(value)
            rip = self.mem_utils.getRegValue(self.cpu, 'rip')
            ref_count = self.param_ref_tracker.numRefs()
            #self.lgr.debug('\tuserReadHap pid:%d (%s) read value 0x%s from 0x%x, cycles:0x%x rip: 0x%x ref_count %d' % (pid, comm, hexstring, 
            #      memory.logical_address, self.cpu.cycles, rip, ref_count))
            ok = self.param_ref_tracker.addRef(memory.logical_address, orig_value, hexstring, memory.size, other_ptr)
            if not ok:
                self.lgr.debug('userReadHap addRef says it is got a reference on the moon, bail')
                self.rmUserBreaks()


    def userWriteHap(self, dumb, third, forth, memory):
        if self.user_write_hap is None:
            return
        cpl = memUtils.getCPL(self.cpu)
        if cpl != 0:
            self.lgr.error('userWriteHap not in kernel???')
            SIM_break_simulation('fix this')
            return
        dumb, comm, pid = self.task_utils.curProc()
        if memory.size <= 8:
            new_value = SIM_get_mem_op_value_le(memory)
        else:
            self.lgr.error('Simics error reading memory, size %d' % memory.size)
            new_value = bytes(0)
        #self.lgr.debug('userWriteHap pid:%d (%s) wrote 0x%x to memory address 0x%x len %d context %s' % (pid, comm, new_value, memory.logical_address, memory.size, str(self.cpu.current_context)))
        hexstring = '0x%x' % new_value
        ok = self.param_ref_tracker.addWrote(memory.logical_address, new_value, hexstring, memory.size)
        if not ok:
            self.lgr.debug('userWriteHap addWrote says it looks like a data read, bail')
            self.rmUserBreaks()

    def flushTrace(self):
        if self.track_log is not None: 
            self.track_log.flush()
