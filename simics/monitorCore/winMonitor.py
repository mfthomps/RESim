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
Windows general monitoring functions (keep from polluting genMonitor even more)
'''
from simics import *
import os
import pickle
import osUtils
import memUtils
import stopFunction
import win7CallParams
import syscall
from resimHaps import *
class WinMonitor():
    def __init__(self, top, cpu, cell_name, param, mem_utils, task_utils, syscallManager, traceMgr, traceProcs, context_manager, run_from_snap, lgr):
        self.top = top
        self.cpu = cpu
        self.cell_name = cell_name
        self.lgr = lgr
        self.param = param
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.traceMgr = traceMgr
        self.traceProcs = traceProcs
        self.syscallManager = syscallManager
        self.context_manager = context_manager
        self.run_from_snap = run_from_snap
        if run_from_snap is not None:
            self.snap_start_cycle = cpu.cycles
        else:
            self.snap_start_cycle = None
        self.cell = self.top.getCell(cell_name)


        ''' dict of dict of syscall.SysCall keyed cell and context'''
        ''' TBD remove these '''
        self.call_traces = {}
        self.trace_all = None
        self.w7_call_params = None


    def getWin7CallParams(self, stop_on, only, only_proc, track_params):
        current_task_phys = self.task_utils.getPhysCurrentTask()
        self.w7_call_params = win7CallParams.Win7CallParams(self.top, self.cpu, self.cell, self.cell_name, self.mem_utils, self.task_utils, current_task_phys, self.param, self.lgr, 
                stop_on=stop_on, only=only, only_proc=only_proc, track_params=track_params)

    def rmCallParamBreaks(self):
        self.lgr.debug('winMonitor rmCallparamBreaks')
        self.w7_call_params.rmAllBreaks()
 

    def toCreateProc(self, comm=None, flist=None, binary=False):
        if comm is not None:    
            params = syscall.CallParams('toCreateProc', 'CreateUserProcess', comm, break_simulation=True) 
            if binary:
                params.param_flags.append('binary')
            call_params = [params]
        else:
            call_params = []
            self.traceMgr.open('/tmp/execve.txt', self.cpu)

        self.syscallManager.watchSyscall(None, ['CreateUserProcess'], call_params, 'CreateUserProcess', flist=flist)
        #self.top.setCommandCallback(self.toNewProc)
        #self.top.setCommandCallbackParam(comm)
        SIM_continue(0)

    def debugProc(self, proc, final_fun=None, pre_fun=None):
        self.lgr.debug('winMonitor debugProc call toCreateProc %s' % proc)
        #f1 = stopFunction.StopFunction(self.toNewProc, [proc], nest=False)
        f1 = stopFunction.StopFunction(self.top.debug, [], nest=False)
        #flist = [f1, f2]
        flist = [f1]
        self.toCreateProc(proc, flist=flist) 


    def tasks(self):
        plist = {}
        self.lgr.debug('tasks ts_next is 0x%x (%d)' % (self.param.ts_next, self.param.ts_next))
        got = self.task_utils.getTaskList()
        self.lgr.debug('tasks ts_next is 0x%x (%d) got %d tasks' % (self.param.ts_next, self.param.ts_next, len(got)))
        for task_ptr in got:
            pid_ptr = task_ptr + self.param.ts_pid
            pid = self.mem_utils.readWord(self.cpu, pid_ptr)
            ''' TBD need better test for undefined pid '''
            if pid is not None and pid < 0xfffff:
                #self.lgr.debug('getCurPid task_ptr, 0x%x pid_offset %d pid_ptr 0x%x pid %d' % (task_ptr, self.param.ts_pid, pid_ptr, pid))
                comm = self.mem_utils.readString(self.cpu, task_ptr+self.param.ts_comm, 16)
                if pid in plist and pid != 0:
                    #print('pid %d already in plist' % pid)
                    self.lgr.debug('pid %d already in plist as comm %s' % (pid, plist[pid]))
                plist[pid] = comm
                #print('pid:%d  %s' % (pid , comm))
            else:
                print('got no pid for pid_ptr 0x%x' % pid_ptr)
                #break
        for pid in sorted(plist):
            print('pid: %d  %s' % (pid, plist[pid]))

    def traceAll(self, record_fd=False, swapper_ok=False):

        ''' trace all system calls. if a program selected for debugging, watch only that program '''
        self.lgr.debug('traceAll')
        if True:
            context = self.context_manager.getDefaultContext()
            pid, cpu = self.context_manager.getDebugPid() 
            if pid is not None:
                tf = '/tmp/syscall_trace-%s-%d.txt' % (self.cell_name, pid)
                context = self.context_manager.getRESimContext()
            else:
                tf = '/tmp/syscall_trace-%s.txt' % self.cell_name
                cpu, comm, pid = self.task_utils.curProc() 

            self.traceMgr.open(tf, cpu)
            if not self.context_manager.watchingTasks():
                self.traceProcs.watchAllExits()
            self.lgr.debug('traceAll, create syscall hap')
            self.trace_all = self.syscallManager.watchAllSyscalls(None, 'traceAll', trace=True, 
                                      record_fd=record_fd, linger=True, swapper_ok=swapper_ok)

            if self.run_from_snap is not None and self.snap_start_cycle == cpu.cycles:
                ''' running from snap, fresh from snapshot.  see if we recorded any calls waiting in kernel '''
                p_file = os.path.join('./', self.run_from_snap, self.cell_name, 'sharedSyscall.pickle')
                if os.path.isfile(p_file):
                    exit_info_list = pickle.load(open(p_file, 'rb'))
                    if exit_info_list is None:
                        self.lgr.error('No data found in %s' % p_file)
                    else:
                        ''' TBD rather crude determination of context.  Assuming if debugging, then all from pickle should be resim context. '''
                        self.trace_all.setExits(exit_info_list, context_override = context)

            frames = self.top.getDbgFrames()
            self.lgr.debug('traceAll, call to setExits')
            self.trace_all.setExits(frames, context_override=self.context_manager.getRESimContext()) 
            ''' TBD not handling calls made prior to trace all without debug?  meaningful?'''

    def getSyscall(self, callname):
        ''' find the most specific syscall for the given callname '''
        retval = None
        if  callname == 'exit_group':
            #self.lgr.debug('is exit group')
            retval = self.exit_group_syscall
        elif callname in self.call_traces:
            #self.lgr.debug('is given callname %s' % callname)
            retval = self.call_traces[callname]
        else:
            retval = self.trace_all
        return retval

    def flushTrace(self):
        if self.w7_call_params is not None: 
            self.w7_call_params.flushTrace()
