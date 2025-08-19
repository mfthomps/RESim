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
import resimSimicsUtils
import memUtils
import taskUtils
import winSocket
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
ignore_sp_for_calls = ['ReadFile', 'WriteFile', 'RECV', 'RECV_DATAGRAM', 'SEND', 'SEND_DATAGRAM']
watch_stack_params = 6
class Win7CallParams():
    def __init__(self, top, cpu, cell, cell_name, mem_utils, task_utils, context_manager, current_task_phys, 
                 param, lgr, stop_on=None, only=None, only_proc=None, track_params=False, this_tid=False):
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
        self.only_call_num = None
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
        self.context_manager = context_manager
        self.cell = cell
        self.cell_name = cell_name
        self.cpu = cpu
        self.stop_on = stop_on
        resim_dir = os.getenv('RESIM_DIR')
        ''' track parameters to different calls '''
        self.call_param_offsets = {}
        if this_tid:
            ''' only watch this thread '''
            dumb_cpu, comm, self.this_tid = self.task_utils.curThread()
        else:
            self.this_tid = None

        context = 'RESim_%s' % self.cell_name
        try:
            obj = SIM_get_object(context)
        except:
            obj = None
  
        if obj is None:
            cmd = 'new-context %s' % context
            self.lgr.debug('win7CallParams cmd is %s' % cmd)
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
      
        self.starting_pid_list = []
        # single computed syscall.  May have an only call but with traceAll.
        self.one_entry = None
        if only is not None:
            call_num = self.task_utils.syscallNumber(only)
            if call_num is not None:
                if not self.top.tracingAll(self.cell_name):
                    self.one_entry = self.task_utils.getSyscallEntry(call_num)
                self.only_call_num = call_num
            else:
                self.lgr.error('%s not found in syscall map' % only)
                return
            if only == 'CreateUserProcess':
                self.starting_pid_list = self.task_utils.getPidList()
                

        self.reverse_to_call = self.top.isReverseExecutionEnabled()
        self.rev_entry_break = None
        self.rev_entry_hap = None
        self.rev_stop_hap = None


        if self.reverse_to_call and only is not None:
            self.lgr.debug('win7CallParams enable reverse')
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
            #self.entry_break = SIM_breakpoint(self.default_context, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
            #self.entry_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.syscallHap, None, self.entry_break)
            self.entry_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
            self.entry_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.syscallHap, None, self.entry_break, 'win7CallParams_enter')
            if self.track_params:
                #self.exit_break = SIM_breakpoint(self.default_context, Sim_Break_Linear, Sim_Access_Execute, self.param.sysret64, 1, 0)
                #self.exit_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.exitHap, None, self.exit_break)
                self.exit_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.sysret64, 1, 0)
                self.exit_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitHap, None, self.exit_break, 'win7CallParams_exit')
                self.lgr.debug('win7CallParams tracking params, exit set along with sysenter haps')
            else:
                self.lgr.debug('win7CallParams not tracking params')

    def doParamTrack(self, rcx, rdx, r8, r9, rsp, call_name, ignore_sp): 
        ''' Track kernel references to user space, recording which of the given parameter pointers the reference is relative to '''
        self.lgr.debug('win7CallParams doParamTrack')
        if self.do_context_switch:
            self.cpu.current_context = self.resim_context
        tid = self.task_utils.curTID()
        self.exit_break = SIM_breakpoint(self.resim_context, Sim_Break_Linear, Sim_Access_Execute, self.param.sysret64, 1, 0)
        self.exit_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.exitTrackHap, tid, self.exit_break)

        self.user_break = SIM_breakpoint(self.resim_context, Sim_Break_Linear, Sim_Access_Read, 0, (self.param.kernel_base-1),  0)
        self.user_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.userReadHap, tid, self.user_break)

        self.user_write_break = SIM_breakpoint(self.resim_context, Sim_Break_Linear, Sim_Access_Write, 0, (self.param.kernel_base-1),  0)
        self.user_write_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.userWriteHap, tid, self.user_write_break)
        self.lgr.debug('win7CallParams doParamTrack exit and user breaks set, get a param tracker')
        self.param_ref_tracker = paramRefTracker.ParamRefTracker(rsp, rcx, rdx, r8, r9, self.mem_utils, self.task_utils, self.cpu, call_name, ignore_sp, self.lgr)
        #SIM_break_simulation('oneCallHap')

    def doParamTrackAll(self, rcx, rdx, r8, r9, rsp, call_name, ignore_sp): 
        ''' Track kernel references to user space, recording which of the given parameter pointers the reference is relative to 
            NOTE may only be tracking one syscall.
        '''
        
        self.lgr.debug('win7CallParams doParamTrackAll')
        tid = self.task_utils.curTID()
        #self.exit_break = SIM_breakpoint(self.resim_context, Sim_Break_Linear, Sim_Access_Execute, self.param.sysret64, 1, 0)
        #self.exit_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.exitTrackHap, tid, self.exit_break)
        if self.exit_hap is not None:
            self.context_manager.genDeleteHap(self.exit_hap, immediate=True)
        self.exit_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.sysret64, 1, 0)
        self.exit_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.exitTrackHap, tid, self.exit_break, 'win7CallParams_track_exit')

        #self.user_break = SIM_breakpoint(self.resim_context, Sim_Break_Linear, Sim_Access_Read, 0, (self.param.kernel_base-1),  0)
        #self.user_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.userReadHap, tid, self.user_break)
        self.user_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Read, 0, (self.param.kernel_base-1), 0)
        self.user_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.userReadHap, tid, self.user_break, 'win7CallParams_track_read')

        #self.user_write_break = SIM_breakpoint(self.resim_context, Sim_Break_Linear, Sim_Access_Write, 0, (self.param.kernel_base-1),  0)
        #self.user_write_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.userWriteHap, tid, self.user_write_break)
        self.user_write_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Write, 0, (self.param.kernel_base-1), 0)
        self.user_write_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.userWriteHap, tid, self.user_write_break, 'win7CallParams_track_write')
        self.lgr.debug('win7CallParams doParamTrackAll exit and user breaks set, get a param tracker for tid %s' % tid)
        self.param_ref_tracker = paramRefTracker.ParamRefTracker(rsp, rcx, rdx, r8, r9, self.mem_utils, self.task_utils, self.cpu, call_name, ignore_sp, self.lgr)
        #SIM_break_simulation('oneCallHap')

    def reverseToSyscall(self):
        debugging_tid, dumb = self.context_manager.getDebugTid()
        if debugging_tid is None:
            ''' Call setReverse breaks after removing all breaks and haps '''
            self.lgr.debug('win7CallParams reverseToCall')
            SIM_run_alone(self.rmAllBreaks, self.setReverseBreaks) 
        else:
            ''' debugging, skip back to entry '''
            frame, cycle = self.top.getPreviousEnterCycle()
            resimSimicsUtils.skipToTest(self.cpu, cycle, self.lgr)
            self.lgr.debug('win7Callparams reverseToSyscall was debug, so skipped to cycle 0x%x' % cycle)
            SIM_run_alone(self.rmAllBreaks, self.trackFromSysEntry)

    def setReverseBreaks(self):
        ''' Set a breakpoint on the sysenter, set a stop hap and reverse'''
        if self.do_context_switch:
            self.cpu.current_context = self.resim_context
        self.lgr.debug('win7CallParams setReverseBreaks on 0x%x current context %s' % (self.param.sysenter, self.cpu.current_context))
        self.rev_entry_break = SIM_breakpoint(self.resim_context, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
        self.rev_stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", self.stoppedAtSyscall, None)
        dumb, comm, tid = self.task_utils.curThread()
        self.lgr.debug('setReverseBreaks do reverse comm %s tid:%s' % (comm, tid))
        SIM_run_command('reverse')

    def stoppedAtSyscall(self, stop_action, one, exception, error_string):
        ''' Should be stopped at the entry to the kernel'''
        dumb, comm, tid = self.task_utils.curThread()
        if self.this_tid is None or tid == self.this_tid:
            if tid is None:
                self.lgr.error('win7CallParams stoppedAtSyscall, tid is None?')
                #self.lgr.debug('win7CallParams stoppedAtSyscall, TRIED again and tid is %s?' % tid)
            else:
                rip = self.mem_utils.getRegValue(self.cpu, 'rip')
                self.lgr.debug('win7CallParams stoppedAtSyscall tid:%s (%s) rip: 0x%x' % (tid,comm,rip))
                SIM_run_alone(self.rmAllBreaks, self.trackFromSysEntry)

    def getCallName(self, call_num, computed=False):
        call_name = self.task_utils.syscallName(call_num)
        if call_name == 'DeviceIoControlFile':
            if computed:
                frame = self.task_utils.frameFromRegsComputed()
            else:
                frame = self.task_utils.frameFromRegs()
            operation = frame['param6']
            ioctl_op_map = winSocket.getOpMap()
            op_cmd = None
            if operation in ioctl_op_map:
                call_name = ioctl_op_map[operation]
        return call_name

    def oneCallHap(self, dumb, third, forth, memory):
        ''' Invoked when the "only" system call is hit at its computed entry '''
        #SIM_run_alone(SIM_run_command, 'enable-reverse-execution')
        dumb, comm, tid = self.task_utils.curThread()

        if self.this_tid is not None and tid != self.this_tid:
            return

        self.lgr.debug('oneCallHap only: %s tid:%s (%s)' % (self.only, tid, comm))
        if self.only in ignore_sp_for_calls:
            ignore_sp = True
        else:
            ignore_sp = False

        if self.reverse_to_call:
            ''' Initiate a chain to cause simulation to reverse to the system call
                so that we can gather all parameter references '''
            call_name = self.getCallName(self.only_call_num, computed=True)
            if call_name == self.only:
                self.lgr.debug('oneCallHap call stopAndGo to reverseToCall')
                self.top.stopAndGo(self.reverseToSyscall)
        else:
            self.lgr.error('win7CallParams oneCallHap will not see references to pointers in stack!')
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
            rsp = self.mem_utils.getRegValue(self.cpu, 'rsp')
            self.lgr.debug('oneCallHap ptr2stack 0x%x stack_val 0x%x user_stack 0x%x, rcx: 0x%x rdx: 0x%x, r8:0x%x, r9:0x%x cycles: 0x%x' % (ptr2stack, stack_val, 
                  user_stack, rcx, rdx, r8, r9, self.cpu.cycles))
            self.doParamTrack(rcx, rdx, r8, r9, rsp, self.only, ignore_sp)
            #SIM_break_simulation('onecall userstack 0x%x' % user_stack)

    def trackFromSysEntry(self, call_name=None):
        ''' Assuming we are at the sysentry, track kernel references to user space'''
        if call_name is None:
            rax = self.mem_utils.getRegValue(self.cpu, 'rax')
            call_name = self.getCallName(rax)

        self.lgr.debug('trackFromSysEntry')
        if call_name in ignore_sp_for_calls:
            ignore_sp = True
        else:
            ignore_sp = False
        rsp = self.mem_utils.getRegValue(self.cpu, 'rsp')
        rcx = self.mem_utils.getRegValue(self.cpu, 'r10')
        rdx = self.mem_utils.getRegValue(self.cpu, 'rdx')
        r8 = self.mem_utils.getRegValue(self.cpu, 'r8')
        r9 = self.mem_utils.getRegValue(self.cpu, 'r9')
        if self.one_entry is not None:
            self.doParamTrack(rcx, rdx, r8, r9, rsp, call_name, ignore_sp)
            status = SIM_simics_is_running()
            if not status:
                self.lgr.debug('trackFromSysEntry Simics not running, go')
                SIM_continue(0)
        else:
            self.doParamTrackAll(rcx, rdx, r8, r9, rsp, call_name, ignore_sp)

    def syscallHap(self, dumb, third, forth, memory):
        ''' hit when kernel is entered due to sysenter '''
        self.lgr.debug('win7CallParams syscallHap')
        dumb, comm, tid = self.task_utils.curThread()
        if self.this_tid is not None and tid != self.this_tid:
            return
        #SIM_break_simulation(tid)
        #return
        #if pid is None:
        #    print('oh no')
        #    return
        if tid is not None:
            rax = self.mem_utils.getRegValue(self.cpu, 'rax')
            ''' Use the call map to get the call name, and strip off "nt" '''
            call_name = self.getCallName(rax)
            self.lgr.debug('win7CallParams syscallHap tid:%s (%s) call %d name %s' % (tid, comm, rax, call_name))
            if self.only_call_num is not None and call_name != self.only:
                self.lgr.debug('win7CallParams call call_name %s looking for %s' % (call_name, self.only))
                return

            if call_name == 'Continue':
                return

            if call_name is not None:

                if call_name == 'RaiseException':
                    ''' This will just bounce to a user space exception handler.
                        Do not track or confusion will reign. '''
                    self.lgr.debug('win7CallParams syscallHap got RaiseException, just return')
                    return

                computed = self.task_utils.getSyscallEntry(rax)
                #if computed is not None:
                #    self.lgr.debug('win7CallParams syscallHap tid:%s (%s) call %s computed is 0x%x' % (tid, comm, call_name, computed))
                #else:
                #    self.lgr.error('win7CallParams syscallHap tid:%s could not compute syscall entry for call %d' % (tid, rax))

                #if call_name == 'OpenFile':
                #    SIM_break_simulation('open file') 
                #if not self.got_one and call_name != 'OpenFile':
                #    #self.lgr.debug('syscallHap looking for Open got %s' % call_name)
                #    return
                #self.got_one = True
                self.current_call[tid] = rax
                rsp = self.mem_utils.getRegValue(self.cpu, 'rsp')
                self.entry_rsp[tid] = rsp
                self.lgr.debug('win7CallParams syscallHap tid:%s (%s) rsp: 0x%x rax: %d call: %s' % (tid, comm, rsp, rax, call_name)) 
                if call_name == self.stop_on:
                    SIM_break_simulation('syscall stop on call')

                self.all_reg_values[tid] = self.allRegValues()
                if self.track_params:
                    self.trackFromSysEntry(call_name=call_name)
            else: 
                self.lgr.debug('call number %d not in call map, tid:%s' % (rax, tid))
        else:
            self.lgr.error('win7CallParam syscallHap Got no tid')

    def allRegValues(self):
        msg = ''
        for reg in self.mem_utils.ia64_regs:
            value = self.mem_utils.getRegValue(self.cpu, reg)
            msg_add = '%s: 0x%x ' % (reg, value)
            msg = msg+msg_add
        return msg
 
    class DelRec():
        def __init__(self, break_num, hap, tid):
            self.break_num = break_num
            self.hap = hap
            self.tid = tid

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
            if self.one_entry is not None:
                SIM_delete_breakpoint(self.entry_break)
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.entry_hap)
            else:
                self.context_manager.genDeleteHap(self.entry_hap)
            self.entry_hap = None
        if self.rev_entry_break is not None and self.one_entry is not None:
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
            if self.one_entry is None:
                # catching sysenter
                hap = self.user_hap
                self.context_manager.genDeleteHap(hap)
                self.lgr.debug('win7CallParams back from genDelteHap for hap %d' % self.user_hap)
            else:
                # catching computed entry.  TBD why not use context manager?
                SIM_delete_breakpoint(self.user_break)
                self.lgr.debug('win7CallParams user_break is deleted')
                SIM_run_alone(self.rmUserHap, self.user_hap)
            self.user_break = None
            self.user_hap = None
            SIM_run_alone(self.rmUserWriteHap, self.user_write_hap)
            self.user_write_hap = None

    def exitTrackHap(self, dumb, third, forth, memory):
        self.lgr.debug('exitTrackHap')
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
        dumb, comm, tid = self.task_utils.curThread()
        if tid is not None:
            if self.track_log is None:
                print('tid:%s (%s) %s' % (tid, comm, params))
            else:
                self.track_log.write('tid:%s (%s) %s\n' % (tid, comm, params))
        else:
            self.lgr.error('exitTrackHap got tid of None')
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
            if self.one_entry is not None:
                SIM_break_simulation('exitTrackHap rax 0x%x' % rax)
                if self.reverse_to_call:
                    self.doBreaks()
            elif self.only is not None:
                SIM_break_simulation('Done with parameter track of %s results in logs/call_params.log' % self.only)
            else:
                pass
                #SIM_break_simulation('exitTrackHap rax 0x%x' % rax)
            self.lgr.debug('win7CallParams exitTrackHap rax 0x%x' % rax)

    def rmUserHap(self, user_hap):
        if self.one_entry is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", user_hap)
        else: 
            self.context_manager.genDeleteHap(user_hap)
     
    def rmUserWriteHap(self, user_write_hap):
        if self.one_entry is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", user_write_hap)
            if self.user_write_break is not None:
                SIM_delete_breakpoint(self.user_write_break)
                self.user_write_break = None
        else:
            self.context_manager.genDeleteHap(user_write_hap)
            self.lgr.debug('win7CallParams removed user_write_hap')
 
    def exitHap(self, tid_in, third, forth, memory):
        ''' hit when kernel is about to exit back to user space via sysret64 '''
        self.lgr.debug('exitHap')
        if self.exit_hap is None:
            return
        dumb, comm, tid = self.task_utils.curThread()
        if tid != tid_in:
            return
        call_name = None
        if tid is None:
            return
        if tid is not None:
            rax = self.mem_utils.getRegValue(self.cpu, 'rax')
            if tid is not None:
                self.lgr.debug('exitHap tid:%s (%s) rax: 0x%x' % (tid, comm, rax))
            if tid in self.all_reg_values:
                self.lgr.debug(self.all_reg_values[tid])

            if tid in self.current_call:
                call_name = self.task_utils.syscallName(self.current_call[tid])
                #self.lgr.debug('exitHap callname %s' % call_name)
            if self.stop_on is not None:
                #self.lgr.debug('exitHap stopon is %s and tid' % self.stop_on)
                if call_name is not None:
                    if call_name == self.stop_on:
                        SIM_break_simulation('exitHap stop on call')


    def stopWatchExit(self, exit_hap):
        self.lgr.debug('win7CallParams stopWatchExit')
        if self.one_entry is not None:
            if self.do_context_switch:
                self.cpu.current_context = self.default_context
                self.lgr.debug('stopWatchExit cpu reset to %s'  % str(self.cpu.current_context))
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", exit_hap)
            if self.exit_break is not None:
                SIM_delete_breakpoint(self.exit_break)
                self.exit_break = None
        else:
            self.context_manager.genDeleteHap(exit_hap)
 
    def userReadHap(self, tid_in, third, forth, memory):
        if self.user_hap is None:
            return
        dumb, comm, tid = self.task_utils.curThread()
        if tid != tid_in:
            pid = tid.split('-')[0]    
            if self.only == 'CreateUserProcess' and pid not in self.starting_pid_list:
                self.lgr.debug('win7CallParams userReadHap in %s which should be new proc' % pid)
            else:
                return
        cpl = memUtils.getCPL(self.cpu)
        if cpl != 0:
            self.lgr.error('userReadHap not in kernel???')
            #SIM_break_simulation('fix this')
            return
        #self.lgr.debug('win7CallParams tid:%s userReadHap memory 0x%x len %d current_context %s' % (tid, memory.logical_address, memory.size, str(self.cpu.current_context)))
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
            elif memory.size == 4:
                param_ptr = struct.unpack(">L", value)[0]
                #self.lgr.debug('\tuserReadHap paramPtr  0x%x' % param_ptr)
                if param_ptr is not None and param_ptr != 0:
                    test = self.mem_utils.readWord(self.cpu, param_ptr)
                    if test is not None:
                        #self.lgr.debug('\tuserReadHap good paramPtr 0x%x' % param_ptr)
                        other_ptr = param_ptr    
                
            hexstring = binascii.hexlify(value)
            rip = self.mem_utils.getRegValue(self.cpu, 'rip')
            ref_count = self.param_ref_tracker.numRefs()
            #self.lgr.debug('\tuserReadHap tid:%s (%s) read value 0x%s from 0x%x, cycles:0x%x rip: 0x%x ref_count %d' % (tid, comm, hexstring, 
            #      memory.logical_address, self.cpu.cycles, rip, ref_count))
            ok = self.param_ref_tracker.addRef(memory.logical_address, orig_value, hexstring, memory.size, other_ptr)
            if not ok:
                self.lgr.debug('userReadHap addRef says it is got a reference on the moon, bail')
                self.rmUserBreaks()


    def userWriteHap(self, tid_in, third, forth, memory):
        if self.user_write_hap is None:
            return
        dumb, comm, tid = self.task_utils.curThread()
        if tid != tid_in:
            return
        cpl = memUtils.getCPL(self.cpu)
        if cpl != 0:
            self.lgr.error('userWriteHap not in kernel???  tid is %s' % tid)
            #SIM_break_simulation('fix this')
            return
        if memory.size <= 8:
            new_value = memUtils.memoryValue(self.cpu, memory)
        else:
            self.lgr.error('Simics error reading memory, size %d' % memory.size)
            new_value = 0
        #self.lgr.debug('userWriteHap tid:%s (%s) wrote 0x%x to memory address 0x%x len %d context %s' % (tid, comm, new_value, memory.logical_address, memory.size, str(self.cpu.current_context)))
        hexstring = '0x%x' % new_value
        ok = self.param_ref_tracker.addWrote(memory.logical_address, new_value, hexstring, memory.size)
        if not ok:
            self.lgr.debug('userWriteHap addWrote says it looks like a data read, bail')
            self.rmUserBreaks()

    def flushTrace(self):
        if self.track_log is not None: 
            self.track_log.flush()
