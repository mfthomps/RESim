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
Use the stackTrack class to interpret and walk stack frames
TBD remind me why stackTrace is per-call and not per target?
'''
from simics import *
import stackTrace
import elfText
from resimHaps import *
import os
import pickle
class StackFrameManager():
    def __init__(self, top, cpu, cell_name, task_utils, mem_utils, context_manager, soMap, targetFS, run_from_snap, lgr):
        self.top = top
        self.cpu = cpu
        self.cell_name = cell_name
        self.task_utils = task_utils
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.targetFS = targetFS
        self.soMap = soMap
        self.lgr = lgr
        self.relocate_funs = []
        self.stack_base = {}
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)

    def stackTrace(self, verbose=False, in_pid=None):
        cpu, comm, cur_pid = self.task_utils.curProc() 
        if in_pid is not None:
            pid = in_pid
        else:
            pid = cur_pid
        if pid not in self.stack_base:
            stack_base = None
        else:
            stack_base = self.stack_base[pid]
        if pid == cur_pid:
            reg_frame = self.task_utils.frameFromRegs()
        else:
            reg_frame, cycles = self.top.rev_to_call[self.cell_name].getRecentCycleFrame(pid)
       
        st = stackTrace.StackTrace(self.top, cpu, pid, self.soMap, self.mem_utils, 
                 self.task_utils, stack_base, self.top.getIdaFuns(), self.targetFS, 
                 self.relocate_funs, reg_frame, self.lgr)
        st.printTrace(verbose)

    def getStackTraceQuiet(self, max_frames=None, max_bytes=None):
        pid, cpu = self.context_manager.getDebugPid() 
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
        else:
            cpu, comm, cur_pid = self.task_utils.curProc() 
            if pid != cur_pid:
                if not self.context_manager.amWatching(cur_pid):
                    self.lgr.debug('getSTackTraceQuiet not in expected pid %d, current is %d' % (pid, cur_pid))
                    return None
                else:
                    pid = cur_pid
        if pid not in self.stack_base:
            stack_base = None
        else:
            stack_base = self.stack_base[pid]
        reg_frame = self.task_utils.frameFromRegs()
        st = stackTrace.StackTrace(self.top, cpu, pid, self.soMap, self.mem_utils, 
                self.task_utils, stack_base, self.top.getIdaFuns(), self.targetFS, self.relocate_funs, 
                reg_frame, self.lgr, max_frames=max_frames, max_bytes=max_bytes)
        return st

    def getStackTrace(self):
        ''' used by IDA client '''
        pid, cpu = self.context_manager.getDebugPid() 
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
        else:
            cpu, comm, cur_pid = self.task_utils.curProc() 
            if pid != cur_pid:
                if not self.context_manager.amWatching(cur_pid):
                    self.lgr.debug('stackFrameManager getSTackTrace not expected pid %d, current is %d  -- not a thread?' % (pid, cur_pid))
                    return "{}"
                else:
                    pid = cur_pid
        self.lgr.debug('stackFrameManager getStackTrace pid %d' % pid)
        if pid not in self.stack_base:
            stack_base = None
        else:
            stack_base = self.stack_base[pid]
        reg_frame = self.task_utils.frameFromRegs()
        st = stackTrace.StackTrace(self.top, cpu, pid, self.soMap, self.mem_utils, 
                  self.task_utils, stack_base, self.top.getIdaFuns(), self.targetFS, 
                  self.relocate_funs, reg_frame, self.lgr)
        j = st.getJson() 
        self.lgr.debug(j)
        #print j
        return j

    def pickleit(self, name):
        stack_base_file = os.path.join('./', name, self.cell_name, 'stack_base.pickle')
        pickle.dump( self.stack_base, open(stack_base_file, "wb" ) )
        self.lgr.debug('stackFrameManager pickleit saved %d stack bases' % len(self.stack_base))

    def loadPickle(self, name):
        stack_base_file = os.path.join('./', name, self.cell_name, 'stack_base.pickle')
        if os.path.isfile(stack_base_file):
            self.lgr.debug('stackFrameManager stack_base pickle from %s' % stack_base_file)
            self.stack_base = pickle.load( open(stack_base_file, 'rb') ) 

    def setRelocateFuns(self, full_path, ida_funs):
        if self.top.isWindows():
            ''' TBD fix for windows'''
            self.relocate_funs = []
        else:
            self.relocate_funs = elfText.getRelocate(full_path, self.lgr, ida_funs)

    def setStackBase(self):
        ''' debug cpu not yet set.  TBD align with debug cpu selection strategy '''
        esp = self.mem_utils.getRegValue(self.cpu, 'esp')
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        cpu, comm, pid  = self.task_utils.curProc()
        self.stack_base[pid] = esp
        self.lgr.debug('setStackBase pid:%d to 0x%x init eip is 0x%x' % (pid, esp, eip))

    def modeChangeForStack(self, want_pid, one, old, new):
        if self.mode_hap is None:
            return
        cpu, comm, pid = self.task_utils.curProc() 
        self.lgr.debug('modeChangeForStack pid:%d wanted: %d old: %d new: %d' % (pid, want_pid, old, new))
        RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
        self.mode_hap = None
        
        if new != Sim_CPU_Mode_Supervisor:
            self.setStackBase()

    def recordStackBase(self, pid, sp):
        self.lgr.debug('recordStackBase pid:%d 0x%x' % (pid, sp))
        self.stack_base[pid] = sp

    def recordStackClone(self, pid, parent):
        self.lgr.debug('recordStackClone pid: %d parent: %d' % (pid, parent))
        self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChangeForStack, pid)

    ''' TBD remove, only here for compatability with old snapshots'''
    def initStackBase(self, stack_base):
        self.stack_base = stack_base

    def up(self):
        st = self.top.getStackTraceQuiet(max_frames=2, max_bytes=1000)
        frames = st.getFrames(2)
        print(frames[1].dumpString())

    def down(self):
        st = self.top.getStackTraceQuiet(max_frames=2, max_bytes=1000)
        frames = st.getFrames(2)
        #print(frames[1].dumpString())
        self.top.revToAddr(frames[1].ip)

    def dumpStack(self, count=80):
        esp = self.mem_utils.getRegValue(self.cpu, 'esp')
        ptr = esp
        offset = self.mem_utils.wordSize(self.cpu)
        ida_funs = self.top.getIdaFuns()
        cpu, comm, pid = self.task_utils.curProc() 
        for i in range(count):
            value = self.mem_utils.readWord(self.cpu, ptr) 
            name = ''
            if self.soMap.isCode(value, pid):
                self.lgr.debug('stackFrameManager dumpStack 0x%x is code' % value)
                fun_addr = ida_funs.getFun(value)
                if fun_addr is not None:
                    name = ida_funs.getName(fun_addr)
                    self.lgr.debug('stackFrameManager fun_addr 0x%x %s' % (fun_addr, name))
            print('%16x   %16x %s' % (ptr, value, name))
            ptr = ptr + offset
