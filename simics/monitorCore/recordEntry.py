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
import syscall
import taskUtils
import net
import os
import pickle
class RecordEntry():
    def __init__(self, top, cpu, cell_name, mem_utils, task_utils, context_manager, param, compat32, snap_name, lgr):
        self.top = top
        self.cpu = cpu
        self.cell_name = cell_name
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.param = param
        self.context_manager = context_manager
        self.compat32 = compat32
        self.lgr = lgr
        self.sysenter_cycles = {}
        self.recent_cycle = {}
        self.sysenter_hap = None
        self.sysenter64_hap = None
        if snap_name is not None:
            self.loadPickle(snap_name)

    def noWatchSysenter(self):
        if self.sysenter_hap is not None:
            self.lgr.debug('recordEntry noWatchSystenter, remove sysenter breaks and hap handle %d' % self.sysenter_hap)
            self.context_manager.genDeleteHap(self.sysenter_hap, immediate=True)
            self.sysenter_hap = None
        else:
           self.lgr.debug('recordEntry noWatchSysenter, NO ENTER BREAK')
        if self.sysenter64_hap is not None:
            self.lgr.debug('recordEntry noWatchSystenter, remove sysenter64 breaks and hap handle %d' % self.sysenter64_hap)
            self.context_manager.genDeleteHap(self.sysenter64_hap, immediate=True)
            self.sysenter64_hap = None

    def watchSysenter(self, dumb=None):
        if self.cpu is None:
            return
        self.lgr.debug('recordEntry watchSysenter context of cpu %s' % self.cpu.current_context)
        cell = self.top.getCell()
        if self.sysenter_hap is None:
            if self.top.isVxDKM(self.cell_name):
                # TBD fix this
                #return
                bp_start = None
                self.global_sym = self.task_utils.getGlobalSymDict()
                for addr in self.global_sym:
                    bp = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
                    if bp_start is None:
                        bp_start = bp
                self.sysenter_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.sysenterHap, None, bp_start, bp, 'recordEntry sysenter')
                self.lgr.debug('vxKSyscall setGlobal set bp range %d %d' % (bp_start, bp))
            elif self.cpu.architecture.startswith('arm'):
                if self.param.arm_entry is not None:
                    self.lgr.debug('recordEntry watchSysenter set linear break at 0x%x' % (self.param.arm_entry))
                    enter_break1 = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_entry, 1, 0)
                    self.sysenter_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.sysenterHap, None, enter_break1, 'recordEntry sysenter')
                if self.cpu.architecture == 'arm64' and hasattr(self.param, 'arm64_entry'):
                    self.lgr.debug('recordEntry watchSysenter set arm64 linear break at 0x%x' % (self.param.arm64_entry))
                    enter_break1 = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.arm64_entry, 1, 0)
                    self.sysenter64_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.sysenterHap, None, enter_break1, 'recordEntry sysenter')
            else:
                if self.param.sysenter is not None and self.param.sys_entry is not None:
                    self.lgr.debug('recordEntry watchSysenter set linear breaks at 0x%x and 0x%x' % (self.param.sysenter, self.param.sys_entry))
                    enter_break1 = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
                    enter_break2 = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, 1, 0)
                    self.sysenter_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.sysenterHap, None, enter_break1, enter_break2, 'recordEntry sysenter')
                elif self.param.sysenter is not None:
                    self.lgr.debug('recordEntry watchSysenter sysenter set linear breaks at 0x%x ' % (self.param.sysenter))
                    enter_break1 = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.sysenter, 1, 0)
                    self.sysenter_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.sysenterHap, None, enter_break1, 'recordEntry sysenter')
                elif self.param.sys_entry is not None:
                    self.lgr.debug('recordEntry watchSysenter sys_entry set linear breaks at 0x%x ' % (self.param.sys_entry))
                    enter_break1 = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.param.sys_entry, 1, 0)
                    self.sysenter_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.sysenterHap, None, enter_break1, 'recordEntry sys_entry')

    def sysenterHap(self, prec, the_object, the_break, memory):
        cur_cpu, comm, tid  = self.task_utils.curThread()
        self.lgr.debug('recordEntry sysenterHap tid:%s' % tid)
        if tid is not None:
            if True:
                cycles = self.cpu.cycles
                if tid not in self.sysenter_cycles:
                    self.sysenter_cycles[tid] = {}
                if cycles not in self.sysenter_cycles[tid]:
                    self.lgr.debug('the_object: %s  breaknum: %s' % (str(the_object), str(the_break)))
                    frame = self.task_utils.frameFromRegs(compat32=self.compat32)
                    if not self.top.isVxDKM(target=self.cell_name):
                        call_num = self.mem_utils.getCallNum(self.cpu)
                        frame['syscall_num'] = call_num
                        #self.lgr.debug(taskUtils.stringFromFrame(frame))
                        #SIM_break_simulation('debug me')
                        callname = self.task_utils.syscallName(call_num, self.compat32)
                        if callname is None:
                            self.lgr.debug('recordEntry sysenterHap bad call num %d, ignore' % call_num)
                            return
                        self.lgr.debug('recordEntry sysenterHap tid:%s frame %s callnum %d callname %s cycles: 0x%x' % (tid, taskUtils.stringFromFrame(frame), call_num, callname, self.cpu.cycles))
                    else:
                        pc = self.top.getEIP(self.cpu)
                        callname = self.task_utils.getGlobalSym(pc)
                        if callname is None:
                            self.lgr.debug('recordEntry sysenterHap pc 0x%x not a vxwork symbol' % pc)
                            return
                    if callname == 'select' or callname == '_newselect':        
                        select_info = syscall.SelectInfo(frame['param1'], frame['param2'], frame['param3'], frame['param4'], frame['param5'], 
                             self.cpu, self.mem_utils, self.lgr)
                        frame['select'] = select_info.getFDList()
                    elif callname == 'socketcall':        
                        ''' must be 32-bit get params from struct '''
                        socket_callnum = frame['param1']
                        if socket_callnum < len(net.callname):
                            socket_callname = net.callname[socket_callnum].lower()
                            #self.lgr.debug('recordEntry sysenterHap socket_callnum is %d name %s' % (socket_callnum, socket_callname))
                            if socket_callname != 'socket' and socket_callname != 'setsockopt':
                                ss = net.SockStruct(self.cpu, frame['param2'], self.mem_utils)
                                frame['ss'] = ss
                        else:
                            self.lgr.error('recordEntry sysenterHap socket_callnum %d out of range for net.callname len %d' % (socket_callnum, len(net.callname)))

                    self.sysenter_cycles[tid][cycles] = frame 
                    if tid in self.recent_cycle:
                        recent_cycle, recent_frame = self.recent_cycle[tid]
                        if cycles > recent_cycle:
                            self.recent_cycle[tid] = [cycles, frame]
                            self.lgr.debug('recordEntry sysenterHap setting most recent cycle')
                    else:
                        self.recent_cycle[tid] = [cycles, frame]
                        self.lgr.debug('recordEntry sysenterHap setting first recent cycle')
                else:
                    self.lgr.debug('recordEntry sysenterHap, cycles already there for tid %s cycles: 0x%x' % (tid, cycles)) 

    def getEnterCycles(self, tid):
        retval = []
        if tid in self.sysenter_cycles:
            for cycle in sorted(self.sysenter_cycles[tid]):
                retval.append(cycle)
        return retval

    def clearEnterCycles(self):
        self.lgr.debug('clearEnterCycles')
        self.sysenter_cycles.clear()

    def getRecentCycleFrame(self, tid):
        ''' 
            This returns the most recent  frame and cycle entry,
            whose cycle is not related to the current cycle.
        '''
        ''' NOTE these frames do not reflect socket call decoding '''
        frame = None
        ret_cycles = None
        if self.cpu is not None:
            cur_cycles = self.cpu.cycles
            self.lgr.debug('getRecentCycleFrame tid %s' % tid)
            if tid in self.recent_cycle:
                ret_cycles, frame = self.recent_cycle[tid]
            else:
                self.lgr.debug('getRecentCycleFrame tid %s not there' % tid)
        else:
            self.lgr.debug('getRecentCycleFrame cpu was None')
        return frame, ret_cycles

    def getPreviousCycleFrame(self, tid, cpu=None):
        ''' NOTE these frames do not reflect socket call decoding '''
        frame = None
        ret_cycles = None
        if cpu is None:
            cur_cycles = self.cpu.cycles
            self.lgr.debug('getPreviousCycleFrame tid %s cur_cycles 0x%x' % (tid, cur_cycles))
        else:
            cur_cycles = cpu.cycles
            self.lgr.debug('getPreviousCycleFrame tid %s cur_cycles 0x%x from given cpu' % (tid, cur_cycles))
        cycles = None
        prev_cycles = None
        if tid in self.sysenter_cycles:
            got_it = None
            for cycles in sorted(self.sysenter_cycles[tid]):
                if prev_cycles is not None and cycles > cur_cycles:
                    self.lgr.debug('getPreviousCycleFrame found cycle 0x%x just prior to current 0x%x' % (prev_cycles, cur_cycles))
                    got_it = prev_cycles
                    break
                else:
                    prev_cycles = cycles

            if got_it is not None:
                frame = self.sysenter_cycles[tid][got_it] 
                ret_cycles = got_it
            else:
                frame = self.sysenter_cycles[tid][cycles] 
                ret_cycles = cycles
                self.lgr.debug('getPreviousCycleFrame did not find cycle greater than 0x%x, returning newest cycle 0x%x' % (cur_cycles, cycles))
        else:
            self.lgr.debug('getPreviousCycleFrame tid not in sysenter_cycles')
        return frame, ret_cycles

    def loadPickle(self, name):
        self.lgr.debug('recordEntry load pickle for %s  cell_name %s' % (name, self.cell_name))
        record_entry_file = os.path.join('./', name, self.cell_name, 'recordEntry.pickle')
        if os.path.isfile(record_entry_file):
            self.lgr.debug('recordEntry pickle from %s' % record_entry_file)
            self.recent_cycle = pickle.load( open(record_entry_file, 'rb') ) 
            pickle_cycle = pickle.load( open(record_entry_file, 'rb') ) 
            for tid in pickle_cycle:
                self.recent_cycle[str(tid)] = pickle_cycle[tid]
                self.lgr.debug('loadPickle tid %s frame %s' % (tid, str(self.recent_cycle[tid])))
            #self.recent_cycle = rev_call_pickle['recent_cycle']

    def pickleit(self, name, cell_name):
        record_entry_file = os.path.join('./', name, cell_name, 'recordEntry.pickle')
        self.lgr.debug('recordEntry pickleit to %s ' % (record_entry_file))
        save_cycles = {}
        for tid in self.sysenter_cycles:
            frame, cycles = self.getPreviousCycleFrame(tid)
            save_cycles[tid] = [cycles, frame]
            self.lgr.debug('recordEntry pickleit tid %s cycle 0x%x f %s' % (tid, cycles, str(frame)))
        try:
            pickle.dump( save_cycles, open( record_entry_file, "wb") ) 
        except TypeError as ex:
            self.lgr.error('trouble dumping pickle of cycle fames')
