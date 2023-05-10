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
import win7CallParams
import syscall
class WinMonitor():
    def __init__(self, top, cpu, cell_name, param, mem_utils, task_utils, syscall_manager, trace_manager, lgr):
        self.top = top
        self.cpu = cpu
        self.cell_name = cell_name
        self.lgr = lgr
        self.param = param
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.trace_manager = trace_manager
        self.syscall_manager = syscall_manager
        self.cell = self.top.getCell(cell_name)

    def getWin7CallParams(self, stop_on, only):
        current_task_phys = self.task_utils.getPhysCurrentTask()
        self.w7_call_params = win7CallParams.Win7CallParams(self.cpu, self.cell, self.cell_name, self.mem_utils, current_task_phys, self.param, self.lgr, stop_on=stop_on, only=only)

    def toCreateProc(self, comm=None, flist=None, binary=False):
        if comm is not None:    
            params = syscall.CallParams('toCreateProc', 'CreateUserProcess', comm, break_simulation=True) 
            if binary:
                params.param_flags.append('binary')
            call_params = [params]
        else:
            call_params = []
            self.trace_manager.open('/tmp/execve.txt', self.cpu)

        self.syscall_manager.watchSyscall(None, ['CreateUserProcess'], call_params, 'CreateUserProcess', flist=flist)
        SIM_continue(0)

    def debugProc(self, proc, final_fun=None, pre_fun=None):
        self.lgr.debug('winMonitor toCreateProc %s' % proc)
        self.toCreateProc(proc) 


    def tasks(self):
        self.lgr.debug('tasks ts_next is 0x%x (%d)' % (self.param.ts_next, self.param.ts_next))
        got = []
        done = False
        cur_proc = self.task_utils.getCurTaskRec()
        task_ptr = cur_proc
        while not done:
            pid_ptr = task_ptr + self.param.ts_pid
            pid = self.mem_utils.readWord(self.cpu, pid_ptr)
            if pid is not None:
                #self.lgr.debug('getCurPid cur_proc, 0x%x pid_offset %d pid_ptr 0x%x pid %d' % (cur_proc, self.param.ts_pid, pid_ptr, pid))
                comm = self.mem_utils.readString(self.cpu, task_ptr+self.param.ts_comm, 16)
                print('pid:%d  %s' % (pid , comm))
                if pid == 0:
                    break
            else:
                print('got no pid for pid_ptr 0x%x' % pid_ptr)
                break
            task_next = task_ptr + self.param.ts_next
            val = self.mem_utils.readWord(self.cpu, task_next)
            if val is None:
                print('died on task_next 0x%x' % task_next)
                break
            else:
                next_head = val
            
            task_ptr = next_head - self.param.ts_prev

            if task_ptr in got:
                print('already got')
                #lgr.debug('already got')
                break
            else:
                got.append(task_ptr)
                #lgr.debug('append got 0x%x' % task_ptr)

        task_next = cur_proc + self.param.ts_prev
        val = self.mem_utils.readWord(self.cpu, task_next)
        if val is None:
            print('died on task_prev 0x%x' % task_next)
            return
        else:
            next_head = val
            
        task_ptr = next_head - self.param.ts_prev
        while not done:
            pid_ptr = task_ptr + self.param.ts_pid
            pid = self.mem_utils.readWord(self.cpu, pid_ptr)
            if pid is not None:
                if pid == 0:
                    break
                #self.lgr.debug('getCurPid cur_proc, 0x%x pid_offset %d pid_ptr 0x%x pid %d' % (cur_proc, self.param.ts_pid, pid_ptr, pid))
                comm = self.mem_utils.readString(self.cpu, task_ptr+self.param.ts_comm, 16)
                print('pid:%d  %s' % (pid , comm))
            else:
                print('got no pid for pid_ptr 0x%x' % pid_ptr)
                break
            task_next = task_ptr + self.param.ts_prev
            val = self.mem_utils.readWord(self.cpu, task_next)
            if val is None:
                print('died on task_next 0x%x' % task_next)
                break
            else:
                next_head = val
            
            task_ptr = next_head - self.param.ts_prev

            if task_ptr in got:
                print('already got')
                #lgr.debug('already got')
                break
            else:
                got.append(task_ptr)
                #lgr.debug('append got 0x%x' % task_ptr)
