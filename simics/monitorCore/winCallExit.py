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
import pageUtils
import memUtils
import net
import ipc
import allWrite
import syscall
import resimUtils
import epoll
from resimHaps import *
'''
Handle returns to user space from system calls.  May result in call_params matching.  NOTE: stop actions (stop_action) for 
matched parameters are handled by the stopHap in the syscall module that handled the call.
'''
class WinCallExit():
    def __init__(self, top, cpu, cell, cell_name, param, mem_utils, task_utils, context_manager, traceProcs, traceFiles, soMap, dataWatch, traceMgr, lgr):
        self.pending_execve = []
        self.lgr = lgr
        self.cpu = cpu
        self.cell = cell
        self.cell_name = cell_name
        self.task_utils = task_utils
        self.param = param
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.traceProcs = traceProcs
        self.exit_info = {}
        self.matching_exit_info = None
        self.exit_pids = {}
        self.trace_procs = []
        self.exit_hap = {}
        self.exit_names = {} 
        self.debugging = False
        self.traceMgr = traceMgr
        self.traceFiles = traceFiles
        self.dataWatch = dataWatch
        self.soMap = soMap
        self.top = top
        self.track_so = True
        self.all_write = False
        self.allWrite = allWrite.AllWrite()
        ''' used for origin reset'''
        self.stop_hap = None
        ''' used by writeData to make application think fd has no more data '''
        self.fool_select = None
        ''' piggyback datawatch kernel returns '''
        self.callback = None
        self.callback_param = None
   
        self.kbuffer = None
        ''' Adjust read return counts using writeData '''
        self.read_fixup_callback = None

    def handleExit(self, exit_info, pid, comm):
        ''' 
           Invoked on (almost) return to user space after a system call.
           Includes parameter checking to see if the call meets criteria given in
           a paramter buried in exit_info (see ExitInfo class).
        '''
        if exit_info is None:
            ''' TBD why does this get called, windows and linux?'''
            return False
        if pid == 0:
            #self.lgr.debug('winCallExit cell %s pid is zero' % (self.cell_name))
            return False
        eip = self.top.getEIP(self.cpu)

        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
        ueax = self.mem_utils.getUnsigned(eax)
        eax = self.mem_utils.getSigned(eax)
        callname = self.task_utils.syscallName(exit_info.callnum, exit_info.compat32)
        #self.lgr.debug('winCallExit cell %s callnum %d name %s  pid %d  parm1: 0x%x' % (self.cell_name, exit_info.callnum, callname, pid, exit_info.frame['param1']))
        pid_thread = self.task_utils.getPidAndThread()
        trace_msg = 'pid:%s (%s) return from %s' % (pid_thread, comm, callname)
        if eax != 0:
            trace_msg = trace_msg+ ' returned error 0x%x' % (eax)
            self.lgr.debug('winCallExit %s' % (trace_msg))
        elif callname in ['OpenFile', 'OpenKeyEx', 'OpenKey']:
            if exit_info.retval_addr is not None:
                fd = self.mem_utils.readWord(self.cpu, exit_info.retval_addr)
                if fd is None:
                     SIM_break_simulation('bad fd read from 0x%x' % exit_info.retval_addr)
                     return
                trace_msg = trace_msg + ' fname_addr 0x%x fname %s handle: 0x%x' % (exit_info.fname_addr, exit_info.fname, fd)
                self.lgr.debug('winCallExit %s' % (trace_msg))
               
                if self.soMap is not None and (exit_info.fname.lower().endswith('.dll') or exit_info.fname.lower().endswith('.so')):
                    self.soMap.addFile(exit_info.fname, fd, pid)
            else:
                self.lgr.debug('%s retval addr is none' % trace_msg)
            if exit_info.call_params is not None and type(exit_info.call_params.match_param) is str:
                self.lgr.debug('winCallExit open check string %s against %s' % (exit_info.fname, exit_info.call_params.match_param))
                #if eax < 0 or exit_info.call_params.match_param not in exit_info.fname:
                if exit_info.call_params.match_param not in exit_info.fname:
                    ''' no match, set call_param to none '''
                    exit_info.call_params = None
                else:
                    self.lgr.debug('winCallExit got match')

        elif callname == 'CreateFile':
            if exit_info.retval_addr is not None:
                fd = self.mem_utils.readWord(self.cpu, exit_info.retval_addr)
                if fd is not None:
                    trace_msg = trace_msg + ' fname_addr 0x%x fname %s handle: 0x%x' % (exit_info.fname_addr, exit_info.fname, fd)
                    self.lgr.debug('winCallExit %s' % (trace_msg))
                else:
                    self.lgr.debug('%s handle is none' % trace_msg)
            else:
                self.lgr.debug('%s retval addr is none' % trace_msg)

        elif callname == 'CreateSection':
            fd = exit_info.old_fd
            section_handle = exit_info.syscall_instance.paramOffPtr(1, [0], exit_info.frame) 
            self.soMap.createSection(fd, section_handle, pid)
            trace_msg = trace_msg+' handle: 0x%x section_handle: 0x%x' % (fd, section_handle)
            self.lgr.debug('winCallExit '+trace_msg)

        elif callname == 'MapViewOfSection':
            section_handle = exit_info.old_fd
            load_address = exit_info.syscall_instance.paramOffPtr(3, [0], exit_info.frame)
            size = exit_info.syscall_instance.stackParamPtr(3, 0, exit_info.frame) 
            if load_address is not None and size is not None:
                trace_msg = trace_msg+' section_handle: 0x%x load_address: 0x%x  size 0x%x' % (section_handle, load_address, size)
                self.lgr.debug('winCallExit '+trace_msg)
                self.soMap.mapSection(pid, section_handle, load_address, size)
            else:
                self.lgr.debug('winCallExit %s pid:%d (%s) returned bad load address or size?' % (callname, pid, comm))

        elif callname in ['CreateEvent', 'OpenProcessToken']:
            fd = self.mem_utils.readWord(self.cpu, exit_info.retval_addr)
            if fd is not None:
                trace_msg = trace_msg+' handle: 0x%x' % (fd)
            else:
                self.lgr.debug('%s handle is none' % trace_msg)

        elif callname in ['ConnectPort', 'AlpcConnectPort']:
            #self.lgr.debug('winCallExit retval_addr 0x%x' % exit_info.retval_addr)
            fd = self.mem_utils.readWord(self.cpu, exit_info.retval_addr)
            if fd is None:
                 SIM_break_simulation('bad fd read from 0x%x' % exit_info.retval_addr)
                 return
            trace_msg = trace_msg+' fname_addr 0x%x fname %s handle: 0x%x' % (exit_info.fname_addr, exit_info.fname, fd)
            #self.lgr.debug('winCallExit %s' % (trace_msg))

        elif callname in ['AlpcSendWaitReceivePort']:
            got_count = self.mem_utils.readWord16(self.cpu, exit_info.retval_addr)
            if exit_info.count is not None:
                trace_msg = trace_msg+' returned count: 0x%x' % got_count
            
        elif callname == 'QueryValueKey': 
            timer_syscall = self.top.getSyscall(self.cell_name, 'QueryValueKey')
            if timer_syscall is not None:
                timer_syscall.checkTimeLoop('gettimeofday', pid)

        elif callname in ['CreateThread', 'CreateThreadEx']:
            if exit_info.retval_addr is not None:
                self.lgr.debug('winCallExit retval_addr 0x%x' % exit_info.retval_addr)
                fd = self.mem_utils.readWord(self.cpu, exit_info.retval_addr)
                if fd is None:
                     self.lgr.warning('bad handle read from 0x%x' % exit_info.retval_addr)
                else:
                    trace_msg = trace_msg+' handle: 0x%x' % (fd)
                    self.lgr.debug('winCallExit %s' % (trace_msg))
            else:
                self.lgr.debug('winCallExit %s bad retval_addr?' % (trace_msg))

        elif callname in ['DeviceIoControlFile']:
            if exit_info.socket_callname == 'RECV':
                return_count = self.mem_utils.readWord32(self.cpu, exit_info.fname_addr)
                max_read = min(return_count, 100)
                buf_addr = exit_info.retval_addr
                read_data = self.mem_utils.readString(self.cpu, buf_addr, max_read)
                trace_msg = trace_msg+' read count 0x%x data %s' % (return_count, read_data)
                self.lgr.debug(trace_msg)

        else:
            self.lgr.debug('winCallExit %s returned: 0x%x' % (trace_msg, eax)) 
        trace_msg=trace_msg+'\n'

        if exit_info.call_params is not None and exit_info.call_params.break_simulation:
            '''  Use syscall module that got us here to handle stop actions '''
            self.lgr.debug('winCallExit found matching call parameter %s' % str(exit_info.call_params.match_param))
            self.matching_exit_info = exit_info
            self.context_manager.setIdaMessage(trace_msg)
            #self.lgr.debug('winCallExit found matching call parameters callnum %d name %s' % (exit_info.callnum, callname))
            #my_syscall = self.top.getSyscall(self.cell_name, callname)
            my_syscall = exit_info.syscall_instance
            if not my_syscall.linger: 
                self.stopTrace()
            if my_syscall is None:
                self.lgr.error('sharedSyscall could not get syscall for %s' % callname)
            else:
                SIM_run_alone(my_syscall.stopAlone, callname)
    
        if trace_msg is not None and len(trace_msg.strip())>0:
            #self.lgr.debug('cell %s %s'  % (self.cell_name, trace_msg.strip()))
            self.traceMgr.write(trace_msg) 

        return True

    def stopTrace(self):
        for context in self.exit_pids:
            #self.lgr.debug('sharedSyscall stopTrace context %s' % str(context))
            for eip in self.exit_hap:
                self.context_manager.genDeleteHap(self.exit_hap[eip], immediate=True)
                #self.lgr.debug('sharedSyscall stopTrace removed exit hap for eip 0x%x context %s' % (eip, str(context)))
            self.exit_pids[context] = {}
        for eip in self.exit_hap:
            self.exit_info[eip] = {}
