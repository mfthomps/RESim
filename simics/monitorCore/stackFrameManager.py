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
    def __init__(self, top, cpu, cell_name, task_utils, mem_utils, context_manager, soMap, targetFS, run_from_snap, disassembler, lgr):
        self.top = top
        self.cpu = cpu
        self.cell_name = cell_name
        self.task_utils = task_utils
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.targetFS = targetFS
        self.soMap = soMap
        self.lgr = lgr
        self.disassembler = disassembler
        self.stack_base = {}
        self.stack_cache = {}
        self.stack2_cache = {}
        self.best_stack_base = {}
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)

    def stackTrace(self, verbose=False, in_tid=None, use_cache=True):
        fun_mgr = self.top.getFunMgr()
        if fun_mgr is None:
            self.lgr.error('No function manager defined.  Debugging?')
            return
        cpu, comm, cur_tid = self.task_utils.curThread() 
        if in_tid is not None:
            tid = in_tid
        else:
            tid = cur_tid
        st = self.checkIpSpCache(tid)
        if st is None:
            cycle = self.cpu.cycles
            if cycle in self.stack_cache and use_cache:
                st = self.stack_cache[cycle]
            else:
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
                         reg_frame, self.disassembler, self.lgr)
                if stack_base is None:
                    self.recordMissingStackBase(tid, st.frames[-1].sp)
                self.stack_cache[cycle] = st
                key = self.cacheKey()
                self.lgr.debug('stackFrameManager added key %s' % key)
                if key not in self.stack2_cache:
                    self.stack2_cache[key] = []
                self.stack2_cache[key].append(st)
        st.printTrace(verbose)

    def getStackTraceQuiet(self, max_frames=None, max_bytes=None, skip_recurse=False):
        fun_mgr = self.top.getFunMgr()
        if fun_mgr is None:
            self.lgr.error('No function manager defined.  Debugging?')
            return
        tid, cpu = self.context_manager.getDebugTid() 
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        else:
            cpu, comm, cur_tid = self.task_utils.curThread() 
            if tid != cur_tid:
                if fun_mgr.hasIDAFuns():
                    self.lgr.debug('stackFrameManager getStackTraceQuiet not in debug tid:%s, current is %s, but we have funs, use it' % (tid, cur_tid))
                    tid = cur_tid
                else:
                    self.lgr.debug('stackFrameManager getStackTraceQuiet, no ida funs for comm %s' % comm)
                    return None
        st = self.checkIpSpCache(tid)
        if st is None:
            cycle = self.cpu.cycles
            if cycle in self.stack_cache:
                st = self.stack_cache[cycle]
            else:
                if tid not in self.stack_base:
                    stack_base = None
                else:
                    stack_base = self.stack_base[tid]
                reg_frame = self.task_utils.frameFromRegs()
                st = stackTrace.StackTrace(self.top, cpu, tid, self.soMap, self.mem_utils, 
                        self.task_utils, stack_base, fun_mgr, self.targetFS, 
                        reg_frame, self.disassembler, self.lgr, max_frames=max_frames, max_bytes=max_bytes, skip_recurse=skip_recurse)
                if stack_base is None:
                    self.recordMissingStackBase(tid, st.frames[-1].sp)
                self.stack_cache[cycle] = st
                key = self.cacheKey()
                self.lgr.debug('stackFrameManager added key %s' % key)
                if key not in self.stack2_cache:
                    self.stack2_cache[key] = []
                self.stack2_cache[key].append(st)
        return st

    def getStackTrace(self):
        ''' used by IDA client '''
        st = self.getStackTraceQuiet()
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
            for tid in self.stack_base:
                self.lgr.debug('stackFrameManager loadPickle tid:%s stack_base 0x%x' % (tid, self.stack_base[tid]))

    def setStackBase(self):
        ''' debug cpu not yet set.  TBD align with debug cpu selection strategy '''
        esp = self.mem_utils.getRegValue(self.cpu, 'sp')
        eip = self.mem_utils.getRegValue(self.cpu, 'pc')
        cpu, comm, tid  = self.task_utils.curThread()
        self.stack_base[tid] = esp
        self.lgr.debug('setStackBase tid:%s to 0x%x init eip is 0x%x' % (tid, esp, eip))

    def modeChangeForStack(self, want_tid, one, old, new):
        if self.mode_hap is None:
            return
        cpu, comm, tid = self.task_utils.curThread() 
        #rcx = self.mem_utils.getRegValue(self.cpu, 'rcx')
        #self.lgr.debug('stackFrameManager modeChangeForStack tid:%s wanted: %s old: %d new: %d rcx 0x%x' % (tid, want_tid, old, new, rcx))
        if tid != want_tid:
            self.lgr.debug('stackFrameManager modeChangeForStack tid:%s wanted: %s old: %d new: %d bail' % (tid, want_tid, old, new))
            return 
        #if new != Sim_CPU_Mode_Supervisor:
        ''' catch entry into kernel so that we can read SP without breaking simulation '''
        if new == Sim_CPU_Mode_Supervisor:
            esp = self.mem_utils.getRegValue(self.cpu, 'sp')
            eip = self.mem_utils.getRegValue(self.cpu, 'pc')
            self.lgr.debug('stackFrameManager modeChangedForStack tid:%s , calling into kernel mode eip: 0x%x esp: 0x%x cycle: 0x%x' % (tid, eip, esp, self.cpu.cycles))
            self.setStackBase()
            RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
            self.mode_hap = None
        #else:
        #    SIM_break_simulation('remove this')

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
                else:
                    name = 'unknown'
            print('%16x   %16x %s' % (ptr, value, name))
            if fh is not None:
                fh.write('%16x   %16x %s\n' % (ptr, value, name))
            ptr = ptr + offset
        if fh is not None:
            fh.close()

    def recordMissingStackBase(self, tid, base):
        if tid not in self.best_stack_base:
            self.best_stack_base[tid] = {}
        if base not in self.best_stack_base[tid]:
            self.best_stack_base[tid][base] = 1
        else:
            self.best_stack_base[tid][base] = self.best_stack_base[tid][base] + 1
        if self.best_stack_base[tid][base] >= 5:
            self.stack_base[tid] = base
            self.lgr.debug('stackFrameManager recordStackBase decided base is 0x%x for tid:%s' % (base, tid))

    def cacheKey(self):
        sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        ip = self.mem_utils.getRegValue(self.cpu, 'ip')
        key = '0x%x-0x%x' % (sp, ip)
        return key

    def checkIpSpCache(self, tid):
        retval = None
        matched = False
        key = self.cacheKey()
        self.lgr.debug('stackFrameManager check key %s' % key)
        if key in self.stack2_cache:
            #st = self.stack2_cache[key]
            for st in self.stack2_cache[key]:
                matched = True
                for frame in st.frames:
                    if frame.ret_to_addr is not None and frame.ip is not None and frame.ret_addr is not None:
                       my_ret_to = self.readAppPtr(tid, frame.ret_to_addr)
                       if my_ret_to is not None:
                           if my_ret_to == frame.ret_addr:
                               pass
                           else:
                               self.lgr.debug('stackFrameManager checkIpSpCache mismatch in frame with ip 0x%x key %s my_ret_to 0x%x frame_ret_addr 0x%x' % (frame.ip, key, my_ret_to, frame.ret_addr))
                               matched = False
                               break
                       else:
                           self.lgr.debug('stackFrameManager checkIpSpCache failed to read my_ret_to from 0x%x' % frame.ret_to_addr)
                           matched = False
                           break
                if matched:
                    retval = st
                    self.lgr.debug('stackFrameManager checkIpSpCached found match for key %s' % key)
                    break
        return retval

    def readAppPtr(self, tid, addr):
        word_size = self.soMap.wordSize(tid)
        if word_size == 4: 
            retval = self.mem_utils.readWord32(self.cpu, addr)
        else:
            retval = self.mem_utils.readWord(self.cpu, addr)
        return retval

