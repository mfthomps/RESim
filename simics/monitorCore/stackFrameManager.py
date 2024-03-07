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
import json
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
        self.stack_base = {}
        self.stack_cache = {}
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)

    def stackTrace(self, verbose=False, in_tid=None, use_cache=True):
        fun_mgr = self.top.getFunMgr()
        if fun_mgr is None:
            self.lgr.error('No function manager defined.  Debugging?')
            return
        cycle = self.cpu.cycles
        if cycle in self.stack_cache and use_cache:
            st = self.stack_cache[cycle]
        else:
            cpu, comm, cur_tid = self.task_utils.curThread() 
            if in_tid is not None:
                tid = in_tid
            else:
                tid = cur_tid
            if tid not in self.stack_base:
                stack_base = None
            else:
                stack_base = self.stack_base[tid]
            if tid == cur_tid:
                reg_frame = self.task_utils.frameFromRegs()
            else:
                reg_frame, cycles = self.top.rev_to_call[self.cell_name].getRecentCycleFrame(tid)
           
            st = stackTrace.StackTrace(self.top, cpu, tid, self.soMap, self.mem_utils, 
                     self.task_utils, stack_base, fun_mgr, self.targetFS, 
                     reg_frame, self.lgr)
            self.stack_cache[cycle] = st
        st.printTrace(verbose)

    def getStackTraceQuiet(self, max_frames=None, max_bytes=None, skip_recurse=False):
        fun_mgr = self.top.getFunMgr()
        if fun_mgr is None:
            self.lgr.error('No function manager defined.  Debugging?')
            return
        cycle = self.cpu.cycles
        if cycle in self.stack_cache:
            st = self.stack_cache[cycle]
        else:
            tid, cpu = self.context_manager.getDebugTid() 
            if tid is None:
                cpu, comm, tid = self.task_utils.curThread() 
            else:
                cpu, comm, cur_tid = self.task_utils.curThread() 
                if tid != cur_tid:
                    if not self.context_manager.amWatching(cur_tid):
                        self.lgr.debug('getSTackTraceQuiet not in expected tid:%s, current is %s' % (tid, cur_tid))
                        return None
                    else:
                        tid = cur_tid
            if tid not in self.stack_base:
                stack_base = None
            else:
                stack_base = self.stack_base[tid]
            reg_frame = self.task_utils.frameFromRegs()
            st = stackTrace.StackTrace(self.top, cpu, tid, self.soMap, self.mem_utils, 
                    self.task_utils, stack_base, fun_mgr, self.targetFS, 
                    reg_frame, self.lgr, max_frames=max_frames, max_bytes=max_bytes, skip_recurse=skip_recurse)
            self.stack_cache[cycle] = st
        return st

    def getStackTrace(self):
        ''' used by IDA client '''
        fun_mgr = self.top.getFunMgr()
        if fun_mgr is None:
            self.lgr.error('No function manager defined.  Debugging?')
            return
        cycle = self.cpu.cycles
        if cycle in self.stack_cache:
            st = self.stack_cache[cycle]
        else:
            tid, cpu = self.context_manager.getDebugTid() 
            if tid is None:
                cpu, comm, tid = self.task_utils.curThread() 
            else:
                cpu, comm, cur_tid = self.task_utils.curThread() 
                if tid != cur_tid:
                    if not self.context_manager.amWatching(cur_tid):
                        self.lgr.debug('stackFrameManager getSTackTrace not expected tid %s, current is %s  -- not a thread?' % (tid, cur_tid))
                        return "{}"
                    else:
                        tid = cur_tid
            self.lgr.debug('stackFrameManager getStackTrace tid %s' % tid)
            if tid not in self.stack_base:
                stack_base = None
            else:
                stack_base = self.stack_base[tid]
            reg_frame = self.task_utils.frameFromRegs()
            st = stackTrace.StackTrace(self.top, cpu, tid, self.soMap, self.mem_utils, 
                      self.task_utils, stack_base, fun_mgr, self.targetFS, 
                      reg_frame, self.lgr)
            self.stack_cache[cycle] = st
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

    def setStackBase(self):
        ''' debug cpu not yet set.  TBD align with debug cpu selection strategy '''
        esp = self.mem_utils.getRegValue(self.cpu, 'esp')
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        cpu, comm, tid  = self.task_utils.curThread()
        self.stack_base[tid] = esp
        self.lgr.debug('setStackBase tid:%s to 0x%x init eip is 0x%x' % (tid, esp, eip))

    def modeChangeForStack(self, want_tid, one, old, new):
        if self.mode_hap is None:
            return
        cpu, comm, tid = self.task_utils.curThread() 
        self.lgr.debug('modeChangeForStack tid:%s wanted: %s old: %d new: %d' % (tid, want_tid, old, new))
        RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
        self.mode_hap = None
        
        #if new != Sim_CPU_Mode_Supervisor:
        ''' catch entry into kernel so that we can read SP without breaking simulation '''
        if new == Sim_CPU_Mode_Supervisor:
            esp = self.mem_utils.getRegValue(self.cpu, 'esp')
            eip = self.mem_utils.getRegValue(self.cpu, 'eip')
            self.lgr.debug('stackFrameManager modeChangedForStack, calling into  kernel mode eip: 0x%x esp: 0x%x' % (eip, esp))
            self.setStackBase()

    def recordStackBase(self, tid, sp):
        if tid is not None and sp is not None:
            self.lgr.debug('recordStackBase tid:%s 0x%x' % (tid, sp))
            self.stack_base[tid] = sp

    def recordStackClone(self, tid, parent):
        self.lgr.debug('recordStackClone tid: %s parent: %s' % (tid, parent))
        self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChangeForStack, tid)

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

    def dumpStack(self, count=80, fname=None):
        cpu, comm, tid = self.task_utils.curThread() 
        offset = self.soMap.wordSize(tid)
        esp = self.mem_utils.getRegValue(self.cpu, 'sp')
        ptr = esp
        fun_mgr = self.top.getFunMgr()
        fh = None
        if fname is not None:
            fh = open(fname, 'w')
        for i in range(count):
            if offset == 4:
                value = self.mem_utils.readWord32(self.cpu, ptr) 
            else:
                value = self.mem_utils.readWord(self.cpu, ptr) 
            name = ''
            if self.soMap.isCode(value, tid):
                self.lgr.debug('stackFrameManager dumpStack 0x%x is code' % value)
                fun_addr = fun_mgr.getFun(value)
                if fun_addr is not None:
                    name = fun_mgr.getName(fun_addr)
                    self.lgr.debug('stackFrameManager fun_addr 0x%x %s' % (fun_addr, name))
            print('%16x   %16x %s' % (ptr, value, name))
            if fh is not None:
                fh.write('%16x   %16x %s\n' % (ptr, value, name))
            ptr = ptr + offset
        if fh is not None:
            fh.close()
