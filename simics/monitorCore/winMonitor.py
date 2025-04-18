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
import traceBuffer
from resimHaps import *
def pidFromTID(tid):
    return tid.split('-')[0]                    

class WinMonitor():
    def __init__(self, top, cpu, cell_name, param, mem_utils, task_utils, syscallManager, traceMgr, traceProcs, context_manager, soMap, sharedSyscall, run_from_snap, rev_to_call, lgr):
        self.top = top
        self.cpu = cpu
        self.cell_name = cell_name
        self.lgr = lgr
        self.param = param
        # remove this hack
        if self.param.ptr2stack is None:
            self.param.ptr2stack = 16
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.traceMgr = traceMgr
        self.traceProcs = traceProcs
        self.syscallManager = syscallManager
        self.context_manager = context_manager
        self.soMap = soMap
        self.sharedSyscall = sharedSyscall
        self.run_from_snap = run_from_snap
        self.rev_to_call = rev_to_call
        if run_from_snap is not None:
            self.snap_start_cycle = cpu.cycles
        else:
            self.snap_start_cycle = None
        self.cell = self.top.getCell(cell_name)

        self.kbuffer = {}

        self.terminate_syscall = None

        ''' dict of dict of syscall.SysCall keyed cell and context'''
        ''' TBD remove these '''
        self.call_traces = {}
        self.trace_all = None
        self.w7_call_params = None


    def getWin7CallParams(self, stop_on, only, only_proc, track_params, this_tid=False):
        #self.top.allowReverse()
        current_task_phys = self.task_utils.getPhysCurrentTask()
        self.top.stopThreadTrack()
        self.w7_call_params = win7CallParams.Win7CallParams(self.top, self.cpu, self.cell, self.cell_name, self.mem_utils, self.task_utils, self.context_manager, current_task_phys, self.param, self.lgr, 
                stop_on=stop_on, only=only, only_proc=only_proc, track_params=track_params, this_tid=this_tid)

    def rmCallParamBreaks(self):
        self.lgr.debug('winMonitor rmCallparamBreaks')
        self.w7_call_params.rmAllBreaks()
 

    def toCreateProc(self, comm=None, flist=None, binary=False, break_simulation=True, run=True):
        ''' Use syscallManager to catch a CreateUserProcess '''
        if comm is not None:    
            params = syscall.CallParams('toCreateProc', 'CreateUserProcess', comm, break_simulation=break_simulation) 
            if binary:
                params.param_flags.append('binary')
            call_params = [params]
        else:
            call_params = []
            self.traceMgr.open('/tmp/execve.txt', self.cpu)

        self.syscallManager.watchSyscall(None, ['CreateUserProcess'], call_params, 'CreateUserProcess', flist=flist)
        self.lgr.debug('winMonitor toCreateProc did call to watch createUserProcess')
        if run:
            SIM_continue(0)

    def debugAlone(self, dumb):
        self.lgr.debug('winMonitor debugAlone, call top debug')
        SIM_run_alone(self.top.debug, False)

    def debugProc(self, proc, final_fun=None, pre_fun=None, new=False):
        ''' called to debug a windows process.  Set up a stop function to call debug after the process has hit the text section'''

        plist = self.task_utils.getTidsForComm(proc)
        if not new and len(plist) > 0 and not (len(plist)==1 and self.task_utils.isExitTid(plist[0])):
            self.lgr.debug('winMonitor debugProc plist len %d plist[0] %s  exittid %s' % (len(plist), plist[0], self.task_utils.getExitTid()))

            self.lgr.debug('winMonitor debugProc process %s found, run until some instance is scheduled' % proc)
            print('%s is running.  Will continue until some instance of it is scheduled' % proc)
            f1 = stopFunction.StopFunction(self.top.toUser, [], nest=True)
            f2 = stopFunction.StopFunction(self.top.debugExitHap, [], nest=False)
            f3 = stopFunction.StopFunction(self.top.debug, [], nest=False)
            flist = [f1, f3, f2]
            if final_fun is not None:
                f4 = stopFunction.StopFunction(final_fun, [], nest=False)
                flist.append(f4)
            if pre_fun is not None:
                fp = stopFunction.StopFunction(pre_fun, [], nest=False)
                flist.insert(0, fp)
            ''' If not yet loaded SO files, e.g., we just did a toProc, then execToText ''' 
            self.top.toRunningProc(proc, plist, flist)
        else:
            self.lgr.debug('winMonitor debugProc call toCreateProc %s' % proc)
            #f1 = stopFunction.StopFunction(self.toNewProc, [proc], nest=False)
            f1 = stopFunction.StopFunction(self.debugAlone, [None], nest=False)
            flist = []
            #flist = [f1]
            self.toCreateProc(proc, flist=flist, break_simulation=False) 

    def tasks(self, filter=None, file=None):
        plist = {}
        self.lgr.debug('tasks ts_next is 0x%x (%d)' % (self.param.ts_next, self.param.ts_next))
        got = self.task_utils.getTaskList()
        self.lgr.debug('tasks ts_next is 0x%x (%d) got %d tasks' % (self.param.ts_next, self.param.ts_next, len(got)))
        if file is not None:
            fh = open(file, 'w')
        else:
            fh = None
        for task_ptr in got:
            pid_ptr = task_ptr + self.param.ts_pid
            pid = self.mem_utils.readWord(self.cpu, pid_ptr)
            ''' TBD need better test for undefined pid '''
            if pid is not None and pid < 0xfffff:
                #self.lgr.debug('getCurTid task_ptr, 0x%x pid_offset %d pid_ptr 0x%x pid %d' % (task_ptr, self.param.ts_pid, pid_ptr, pid))
                comm = self.mem_utils.readString(self.cpu, task_ptr+self.param.ts_comm, 16)
                if filter is None or filter in comm:
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
            if fh is not None:
                fh.write('pid: %d  %s\n' % (pid, plist[pid]))

    def traceAll(self, record_fd=False, swapper_ok=False, no_gui=False):

        ''' trace all system calls. if a program selected for debugging, watch only that program '''
        self.lgr.debug('traceAll')
        if True:
            context = self.context_manager.getDefaultContext()
            tid, dumb = self.context_manager.getDebugTid() 
            if tid is not None:
                pid = pidFromTID(tid)
                tf = 'logs/syscall_trace-%s-%s.txt' % (self.cell_name, pid)
                context = self.context_manager.getRESimContext()
            else:
                tf = 'logs/syscall_trace-%s.txt' % self.cell_name
                dumb, comm, tid = self.task_utils.curThread() 

            self.traceMgr.open(tf, self.cpu)
            if not self.context_manager.watchingTasks():
                self.traceProcs.watchAllExits()
            self.lgr.debug('traceAll, create syscall hap')
            self.trace_all = self.syscallManager.watchAllSyscalls(None, 'traceAll', trace=True, 
                                      record_fd=record_fd, linger=True, swapper_ok=swapper_ok, no_gui=no_gui)

            if self.run_from_snap is not None and self.snap_start_cycle == self.cpu.cycles:
                ''' running from snap, fresh from snapshot.  see if we recorded any calls waiting in kernel '''
                p_file = os.path.join('./', self.run_from_snap, self.cell_name, 'sharedSyscall.pickle')
                if os.path.isfile(p_file):
                    exit_info_list = pickle.load(open(p_file, 'rb'))
                    if exit_info_list is None:
                        self.lgr.error('No data found in %s' % p_file)
                    else:
                        ''' TBD rather crude determination of context.  Assuming if debugging, then all from pickle should be resim context. '''
                        self.trace_all.setExits(exit_info_list, context_override = context)

            frames = self.getDbgFrames()
            self.lgr.debug('traceAll, call to setExits')
            self.trace_all.setExits(frames, context_override=self.context_manager.getRESimContext()) 
            ''' TBD not handling calls made prior to trace all without debug?  meaningful?'''
        return self.trace_all


    def getSyscall(self, callname):
        ''' find the most specific syscall for the given callname '''
        retval = None
        if  callname == 'exit_group':
            #self.lgr.debug('is exit group')
            retval = self.terminate_syscall
        elif callname in self.call_traces:
            #self.lgr.debug('is given callname %s' % callname)
            retval = self.call_traces[callname]
        else:
            retval = self.trace_all
        return retval

    def flushTrace(self):
        if self.w7_call_params is not None: 
            self.w7_call_params.flushTrace()

    def traceWindows(self):
        tf = 'logs/trace_windows.txt'
        self.traceMgr.open(tf, self.cpu)
        call_list = ['CreateUserProcess', 'CreateThread', 'CreateThreadEx', 'ConnectPort', 'AlpcConnectPort', 'OpenFile', 'CreateFile', 'CreateSection', 'MapViewOfSection',
                         #'CreatePort', 'AcceptConnectPort', 'ListenPort', 'AlpcAcceptConnectPort', 'RequestPort', 'DeviceIoControlFile', 'WaitForMultipleObjects32',
                         'CreatePort', 'AcceptConnectPort', 'ListenPort', 'AlpcAcceptConnectPort', 'RequestPort', 'DeviceIoControlFile', 
                         'DuplicateObject', 'ReadFile', 'WriteFile', 'TerminateProcess', 'TerminateThread']
        ''' Use cell of None so only our threads get tracked '''
        call_params = []
        retval = self.syscallManager.watchSyscall(None, call_list, call_params, 'traceWindows', stop_on_call=False, trace=True, linger=True)
        self.lgr.debug('traceWindows')
        return retval

    def runToIO(self, fd, linger, break_simulation, count, flist_in, origin_reset, run_fun, proc, run, kbuf, call_list, sub_match=None, just_input=False):

        call_params = syscall.CallParams('runToIO', None, fd, break_simulation=break_simulation, proc=proc, sub_match=sub_match)        
        ''' nth occurance of syscalls that match params '''
        call_params.nth = count
       
        if 'runToIO' in self.call_traces:
            self.lgr.debug('runToIO already in call_traces, add param')
            self.call_traces['runToIO'].addCallParams([call_params])
        else:
            self.lgr.debug('runToIO on FD %s count %s sub_match %s' % (str(fd), count, sub_match))

            if True:
                skip_and_mail = True
                if flist_in is not None:
                    ''' Given callback functions, use those instead of skip_and_mail '''
                    skip_and_mail = False
                self.lgr.debug('winMonitor runToIO, add new syscall')
                kbuffer_mod = None
                if kbuf is not None:
                    kbuffer_mod = kbuf
                    self.sharedSyscall.setKbuffer(kbuffer_mod)
                if call_list is None:
                    if just_input:
                        calls = ['RECV', 'RECV_DATAGRAM', 'ReadFile', 'QueryValueKey', 'EnumerateValueKey', 'Close', 'GET_PEER_NAME']
                    else:
                        calls = ['BIND', 'CONNECT', 'RECV', 'SEND', 'RECV_DATAGRAM', 'SEND_DATAGRAM', 'ReadFile', 'WriteFile', 'QueryValueKey', 'EnumerateValueKey', 'Close', 'GET_PEER_NAME']
                else:
                    calls = call_list
                the_syscall = self.syscallManager.watchSyscall(None, calls, [call_params], 'runToIO', linger=linger, flist=flist_in, 
                                 skip_and_mail=skip_and_mail, kbuffer=kbuffer_mod)
                ''' find processes that are in the kernel on IO calls '''
                frames = self.getDbgFrames()
                skip_calls = []
                for tid in list(frames):
                    if frames[tid] is None:
                        self.lgr.error('frames[%s] is None' % tid)
                        continue
                    call = self.task_utils.syscallName(frames[tid]['syscall_num'], False) 
                    self.lgr.debug('winMonitor runToIO found %s in kernel for pid:%s' % (call, tid))
                    if call != 'DeviceIoControlFile' and (call not in calls or call in skip_calls):
                       del frames[tid]
                       self.lgr.debug('winMonitor runToIO removed %s in kernel for tid:%s' % (call, tid))
                    else:
                       self.lgr.debug('winMonitor runToIO kept frames for tid %s' % tid)
                if len(frames) > 0:
                    self.lgr.debug('wnMonitor runToIO, call to setExits')
                    the_syscall.setExits(frames, origin_reset=origin_reset, context_override=self.context_manager.getRESimContext()) 
                #self.copyCallParams(the_syscall)
    
    
            if run_fun is not None:
                SIM_run_alone(run_fun, None) 
            if run:
                self.lgr.debug('runToIO now run')
                SIM_continue(0)


    def debugExitHap(self, flist=None, context=None): 
        if self.terminate_syscall is None:
            if context is None:
                context=self.context_manager.getRESimContextName()
            exit_calls = ['TerminateProcess', 'TerminateThread']
            self.terminate_syscall = self.syscallManager.watchSyscall(context, exit_calls, [], 'debugExit')
            self.lgr.debug('winMonitor debugExitHap')

    def rmDebugExitHap(self, immediate=False, context=None):
        ''' Intended to be called if a SEGV or other cause of death occurs, in which case we assume that is caught by
            the contextManager and we do not want this rudundant stopage. '''
        if self.terminate_syscall is not None:
            self.lgr.debug('winMonitory rmDebugExitHap')
            self.syscallManager.rmSyscall('debugExit', immediate=immediate, context=context)
            self.terminate_syscall = None

    def getDbgFrames(self):
        ''' Get stack frames from kernel entries as recorded by the reverseToCall module 
            Do this for all siblings of the currently scheduled thread.
        '''
        retval = {}
        plist = {}
        tid_dict = self.task_utils.findThreads()
        for tid in tid_dict:
            frame, cycles = self.top.getRecentEnterCycle(tid)
            if frame is not None:
                retval[tid] = frame
        return retval
