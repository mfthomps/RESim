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
import binascii 
import ipc
import allWrite
import syscall
import resimUtils
from resimHaps import *
import winNTSTATUS
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
        self.exit_tids = {}
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
   
        ''' Adjust read return counts using writeData '''
        self.read_fixup_callback = None

        ''' track socket types (tcp/udp) for tids and their handles'''
        self.tid_sockets = {}

    def watchData(self, exit_info):
        if exit_info.matched_param is not None and (exit_info.matched_param.break_simulation or exit_info.syscall_instance.linger) and self.dataWatch is not None:
            return True
        else:
            return False

    def handleExit(self, exit_info, tid, comm):
        ''' 
           Invoked on (almost) return to user space after a system call.
           Includes parameter checking to see if the call meets criteria given in
           a paramter buried in exit_info (see ExitInfo class).
        '''
        if exit_info is None:
            ''' TBD why does this get called, windows and linux?'''
            #self.lgr.debug('winCallExit cell %s exit_info is None' % (self.cell_name))
            return False
        if tid == 0:
            #self.lgr.debug('winCallExit cell %s tid is zero' % (self.cell_name))
            return False

        if self.dataWatch is not None and not self.dataWatch.disabled:
            self.lgr.debug('winCallExit handleExit restore data watch')
            self.dataWatch.watch()

        eip = self.top.getEIP(self.cpu)

        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
        ueax = self.mem_utils.getUnsigned(eax)
        eax = self.mem_utils.getSigned(eax)
        callname = self.task_utils.syscallName(exit_info.callnum, exit_info.compat32)
        if callname is None:
            self.lgr.debug('winCallExit bad callnum %d' % exit_info.callnum)
            return
        #self.lgr.debug('winCallExit cell %s callnum %d name %s  tid:%s  parm1: 0x%x' % (self.cell_name, exit_info.callnum, callname, tid, exit_info.frame['param1']))
        status = "Unknown - not mapped"
        if eax in winNTSTATUS.ntstatus_map:
            status = winNTSTATUS.ntstatus_map[eax]
        
        trace_msg = 'tid:%s (%s) return from %s with status %s (0x%x)' % (tid, comm, callname, status, eax)
        if exit_info.append_msg is not None: 
            trace_msg = trace_msg + ' '+exit_info.append_msg

        ''' who taught bill about error codes? '''
        #if eax == STATUS_IMAGE_NOT_AT_BASE:  this one if for NtMapViewOfSection
        not_ready = False
        async_was_ready = True
        if eax == 0x103:
            not_ready = True
            eax = 0
        #if eax in [0x40000003, 0x80000005, 0xc000023f, 0xc00000a3]:
        if eax in [0x40000003, 0x80000005]:
            # windows has  a lot of garbage ruturn values.
            self.lgr.debug('winSyscall modifying eax back to zero from 0x%x' % eax)
            eax = 0
        
        # variable to determine if we are going to be doing 32 or 64 bit syscall
        word_size = exit_info.word_size
        exit_info.syscall_instance.rmPendingCall(tid)
        if eax != 0:
            if exit_info.matched_param is not None and exit_info.matched_param.subcall == 'BIND':
                ''' TBD why does this need special case?  remove it?''' 
                trace_msg = trace_msg+' BIND on Handle 0x%x' % exit_info.old_fd
                #self.top.rmSyscall(exit_info.matched_param.name, cell_name=self.cell_name)
            else:
                if exit_info.old_fd is not None:
                    trace_msg = trace_msg + " handle: 0x%x" % exit_info.old_fd  
                #trace_msg = trace_msg+ ' with error: 0x%x' % (eax)
                self.lgr.debug('winCallExit %s' % (trace_msg))
            exit_info.matched_param = None
            #if eax == 0xc00000a3 and exit_info.asynch_handler is not None:
            #    self.lgr.debug('winCallExit is STATUS_DEVICE_NOT_READY tid: %s fd: 0x%x' % (tid, exit_info.old_fd))
            #    exit_info.asynch_handler.deviceNotReady()

        elif callname in ['OpenFile', 'OpenKeyEx', 'OpenKey', 'OpenSection']:
            #self.lgr.debug('winCallExit is %s' % callname)
            if exit_info.retval_addr is not None:
                #self.lgr.debug('winCallExit retval_addr 0x%x' % exit_info.retval_addr)
                fd = self.mem_utils.readWord(self.cpu, exit_info.retval_addr)
                if fd is None:
                     self.lgr.error('winCallExit bad fd read from 0x%x' % exit_info.retval_addr)
                     SIM_break_simulation('bad fd read from 0x%x' % exit_info.retval_addr)
                     return
                trace_msg = trace_msg + ' fname_addr: 0x%x fname: %s Handle: 0x%x' % (exit_info.fname_addr, exit_info.fname, fd)
                self.lgr.debug('winCallExit %s' % (trace_msg))
               
                if self.soMap is not None and (exit_info.fname.lower().endswith('.nls') or exit_info.fname.lower().endswith('.dll') or exit_info.fname.lower().endswith('.so')):
                    self.lgr.debug('winCallExit adding fname: %s with fd: %d to tid:%s' % (exit_info.fname, fd, tid))
                    self.soMap.addFile(exit_info.fname, fd, tid)

                    if callname == 'OpenSection':
                        self.lgr.debug('this is an OpenSection WITHOUT an Open/CreateFile --> make section')
                        self.soMap.createSection(fd, fd, tid)
                self.openCallParams(exit_info)
            else:
                exit_info.matched_param = None
                self.lgr.debug('winCallExit %s retval addr is none' % trace_msg)
            

        elif callname == 'CreateFile':
            if exit_info.retval_addr is not None:
                fd = self.mem_utils.readWord(self.cpu, exit_info.retval_addr)
                if fd is not None:
                    trace_msg = trace_msg + ' fname_addr 0x%x fname: %s Handle: 0x%x' % (exit_info.fname_addr, exit_info.fname, fd)
                    self.lgr.debug('winCallExit %s' % (trace_msg))

                    if self.soMap is not None and (exit_info.fname.lower().endswith('.nls') or exit_info.fname.lower().endswith('.dll') or exit_info.fname.lower().endswith('.so')):
                        self.lgr.debug('adding fname: %s with fd: %d to tid:%s' % (exit_info.fname, fd, tid))
                        self.soMap.addFile(exit_info.fname, fd, tid)
        
                    elif exit_info.fname.endswith('Endpoint'):
                        # gross speculation based on observation
                        socket_type = exit_info.sock_struct[36]
                        if tid not in self.tid_sockets:
                            self.tid_sockets[tid] = {}
                        self.tid_sockets[tid][fd] = socket_type
                        self.lgr.debug('winCallExit CreateFile Endpoint set tid_sockets[%s][0x%x] to socket type %d' % (tid, fd, socket_type))
                    elif exit_info.fname.endswith('AsyncConnectHlp'):
                        self.tid_sockets[tid][fd] = 0xbaabaa
                        self.lgr.debug('winCallExit CreateFile set tid_sockets[%s][0x%x] to Async' % (tid, fd))
                    self.openCallParams(exit_info)

                else:
                    self.lgr.debug('%s handle is none' % trace_msg)
                    exit_info.matched_param = None
            else:
                self.lgr.debug('%s retval addr is none' % trace_msg)
                exit_info.matched_param = None

        elif callname == 'ReadFile':
            ''' delay_count_addr has address of return count'''
            if exit_info.delay_count_addr is None:
                self.lgr.debug('winCallExit %s: Returned count address is None' % exit_info.socket_callname)
            else:
                # TBD hack to let prepInject get the exit info
                self.matching_exit_info = exit_info
                if exit_info.asynch_handler is not None:
                    async_was_ready = exit_info.asynch_handler.exitingKernel(trace_msg, not_ready, self.read_fixup_callback)
                if not async_was_ready:
                    self.lgr.debug('winCallExit ReadFile: not ready ')
                    trace_msg = trace_msg+' - Device not ready'

            self.lgr.debug('winCallExit %s' % (trace_msg))
 
        elif callname == 'AllocateVirtualMemory':
            if exit_info.retval_addr is not None and exit_info.fname_addr is not None:
                base_addr = self.mem_utils.readWord(self.cpu, exit_info.retval_addr)
                size = self.mem_utils.readWord(self.cpu, exit_info.fname_addr) 
                trace_msg = trace_msg + ' base_addr: 0x%x size: 0x%x' % (base_addr, size)
                self.lgr.debug('winCallExit %s' % (trace_msg))
            else:
                self.lgr.debug('%s buffer pointer addr is none' % trace_msg)

        elif callname == 'CreateSection':
            fd = exit_info.old_fd
            if fd is not None:
                section_handle = exit_info.syscall_instance.paramOffPtr(1, [0], exit_info.frame, word_size) 
                self.soMap.createSection(fd, section_handle, tid)
                trace_msg = trace_msg+' Handle: 0x%x section_handle: 0x%x' % (fd, section_handle)
            else:
                trace_msg = trace_msg+' handle was None'
            self.lgr.debug('winCallExit '+trace_msg)

        elif callname == 'MapViewOfSection':
            section_handle = exit_info.old_fd
            load_address = exit_info.syscall_instance.paramOffPtr(3, [0], exit_info.frame, word_size)
            size = exit_info.syscall_instance.stackParamPtr(3, 0, exit_info.frame) 
            if load_address is not None and size is not None:
                trace_msg = trace_msg+' section_handle: 0x%x load_address: 0x%x size: 0x%x' % (section_handle, load_address, size)
                self.lgr.debug('winCallExit '+trace_msg)
                if self.top.trackingThreads():
                    self.soMap.mapSection(tid, section_handle, load_address, size)
            else:
                #self.lgr.debug('winCallExit %s tid:%s (%s) fd: 0x%x returned bad load address or size?' % (callname, tid, comm, exit_info.old_fd))
                trace_msg = trace_msg+' section_handle: 0x%x bad load address or size' % (section_handle)
                self.lgr.debug('winCallExit not tracking threads '+trace_msg)

        elif callname in ['CreateEvent', 'OpenProcessToken', 'OpenProcess']:
            fd = self.mem_utils.readWord(self.cpu, exit_info.retval_addr)
            if fd is not None:
                trace_msg = trace_msg+' Handle: 0x%x' % (fd)
                self.lgr.debug('winCallExit %s' % (trace_msg))
            else:
                self.lgr.debug('%s handle is none' % trace_msg)

        elif callname in ['ConnectPort', 'AlpcConnectPort']:
            fd = self.mem_utils.readWord(self.cpu, exit_info.retval_addr)
            if fd is None:
                 SIM_break_simulation('bad fd read from 0x%x' % exit_info.retval_addr)
                 return
            trace_msg = trace_msg+' fname_addr 0x%x fname %s Handle: 0x%x' % (exit_info.fname_addr, exit_info.fname, fd)
            self.lgr.debug('winCallExit %s' % (trace_msg))

        elif callname in ['AlpcSendWaitReceivePort']:
            got_count = self.mem_utils.readWord16(self.cpu, exit_info.retval_addr)
            if exit_info.count is not None:
                trace_msg = trace_msg+' returned count: 0x%x' % got_count
            
        elif callname in ['QueryValueKey', 'EnumerateValueKey']: 
            timer_syscall = self.top.getSyscall(self.cell_name, 'QueryValueKey')
            if timer_syscall is not None:
                timer_syscall.checkTimeLoop('gettimeofday', tid)
            if self.dataWatch is not None:
                self.lgr.debug('winCallExit %s doDataWatch call setRange for 0x%x count 0x%x' % (callname, exit_info.retval_addr, exit_info.count))
                self.dataWatch.setRange(exit_info.retval_addr, exit_info.count, msg=trace_msg, 
                       max_len=exit_info.count, recv_addr=exit_info.retval_addr, fd=exit_info.old_fd)
                my_syscall = exit_info.syscall_instance
                if my_syscall.linger: 
                    self.dataWatch.stopWatch() 
                    self.dataWatch.watch(break_simulation=False, i_am_alone=True)

        elif callname == 'QueryInformationProcess':
            if exit_info.retval_addr is not None:
                if exit_info.count == 4:
                    data = self.mem_utils.readWord32(self.cpu, exit_info.retval_addr)
                    trace_msg = trace_msg + ('returned data: 0x%x' % data)

        elif callname in ['CreateThread', 'CreateThreadEx']:
            if exit_info.retval_addr is not None:
                self.lgr.debug('winCallExit retval_addr 0x%x' % exit_info.retval_addr)
                fd = self.mem_utils.readWord(self.cpu, exit_info.retval_addr)
                if fd is None:
                     self.lgr.warning('bad handle read from 0x%x' % exit_info.retval_addr)
                else:
                    trace_msg = trace_msg+' Handle: 0x%x' % (fd)
                    self.lgr.debug('winCallExit %s' % (trace_msg))
            else:
                self.lgr.debug('winCallExit %s bad retval_addr?' % (trace_msg))

        elif callname == 'DuplicateObject': 
            if exit_info.retval_addr is not None:
                new_handle = self.mem_utils.readWord(self.cpu, exit_info.retval_addr)
                if new_handle is None:
                     self.lgr.warning('bad handle read from 0x%x' % exit_info.retval_addr)
                else:
                    trace_msg = trace_msg+' old_handle: 0x%x new_handle: 0x%x' % (exit_info.old_fd, new_handle)
                    self.lgr.debug('winCallExit %s' % (trace_msg))
                    if exit_info.matched_param is not None and type(exit_info.matched_param.match_param) is int:
                        if (exit_info.matched_param.subcall == 'accept' or self.name=='runToIO') and \
                           (exit_info.matched_param.match_param < 0 or exit_info.matched_param.match_param == exit_info.old_fd):
                            self.lgr.debug('winCallExit %s MODIFIED handle in call params to new handle' % trace_msg)
                            exit_info.matched_param.match_param = new_handle
                            exit_info.matched_param = None

        elif callname in ['FindAtom', 'AddAtom']: 
            atom_hex = self.mem_utils.readWord16(self.cpu, exit_info.retval_addr)
            trace_msg = trace_msg+' atom hex: 0x%x' % atom_hex

        elif callname == 'Close': 
            if exit_info.matched_param is not None and self.dataWatch is not None:
                   self.dataWatch.close(exit_info.old_fd)

        elif callname in ['DeviceIoControlFile'] and exit_info.socket_callname is not None:
            trace_msg = trace_msg + ' ' + exit_info.socket_callname

            if exit_info.socket_callname in ['BIND', 'GET_SOCK_NAME']:
                sock_addr = exit_info.retval_addr
                sock_type = self.getSockType(tid, exit_info.old_fd)
                sock_struct = net.SockStruct(self.cpu, sock_addr, self.mem_utils, exit_info.old_fd, sock_type=sock_type)
                if exit_info.sock_struct is not None and sock_struct.dottedPort() != exit_info.sock_struct.dottedPort():
                    rand = ' (random)'
                else:
                    rand = ''
                to_string = sock_struct.getString()
                trace_msg = trace_msg+' '+to_string+rand

            elif exit_info.socket_callname in ['RECV', 'RECV_DATAGRAM', 'SEND', 'SEND_DATAGRAM']:
                
                ''' delay_count_addr has address of return count'''
                call_return_not_ready = not_ready
                not_ready = False
                if exit_info.delay_count_addr is None:
                    self.lgr.debug('winCallExit %s: Returned count address is None' % exit_info.socket_callname)
                    trace_msg = trace_msg+' handle: 0x%x' % exit_info.old_fd
                
                else: 
                    if self.read_fixup_callback is not None:
                        self.read_fixup_callback(exit_info.old_fd, exit_info.retval_addr)

                    if exit_info.asynch_handler is not None:
                        self.matching_exit_info = exit_info
                        # hack to avoid duplicate call names
                        trace_msg = trace_msg.rsplit(' ', 1)[0]
                        self.lgr.debug('winCallExit %s call exitingKernel with trace_msg %s' % (exit_info.socket_callname, trace_msg))
                        async_was_ready = exit_info.asynch_handler.exitingKernel(trace_msg, call_return_not_ready, self.read_fixup_callback)

                        ''' Call params satisfied in winDelay'''
                        #exit_info.call_params = None
                        self.lgr.debug('winCallExit asynch_handler was ready? %r' % async_was_ready)
                        if not async_was_ready:
                            not_ready = True
                    else:
                        trace_msg = trace_msg+' handle: 0x%x' % exit_info.old_fd
                    if not_ready:
                        trace_msg = trace_msg+' - Device not ready'
                        self.lgr.debug('winCallExit %s' % trace_msg)
                    else:
                        # why was this being set to nothing?
                        self.lgr.debug('winCallExit %s  was ready and trace_msg was %s, remove because already recorded' % (exit_info.socket_callname, trace_msg))
                        trace_msg = ''
                        pass
 
            elif exit_info.socket_callname in ['ACCEPT', '12083_ACCEPT']:
                trace_msg = trace_msg+' bind socket: 0x%x connect socket: 0x%x' % (exit_info.old_fd, exit_info.new_fd)

            elif exit_info.socket_callname in ['GET_PEER_NAME']:
                count = self.mem_utils.readWord(self.cpu, exit_info.retval_addr)
                trace_msg = trace_msg+' count 0x%x from addr 0x%x fd: 0x%x' % (count, exit_info.retval_addr, exit_info.old_fd)
                self.lgr.debug(trace_msg)
                if exit_info.matched_param is not None and type(exit_info.matched_param.match_param) is int and exit_info.matched_param.match_param == exit_info.old_fd:
                    self.lgr.debug('winCallExit %s doDataWatch call setRange for 0x%x count 0x%x' % (exit_info.socket_callname, exit_info.retval_addr, count))
                    self.dataWatch.setRange(exit_info.retval_addr, word_size, msg=trace_msg, 
                           max_len=word_size, recv_addr=exit_info.retval_addr, fd=exit_info.old_fd, ignore_commence=True)
                    my_syscall = exit_info.syscall_instance
                    if my_syscall.linger: 
                        self.dataWatch.stopWatch() 
                        self.dataWatch.watch(break_simulation=False, i_am_alone=True)
            elif exit_info.socket_callname in ['CONNECT']:
                sock_type = self.getSockType(tid, exit_info.old_fd)
                if sock_type == 0xbaabaa:
                    bind_handle = exit_info.syscall_instance.paramOffPtr(7, [8], exit_info.frame, word_size) 
                    trace_msg = trace_msg + " %s is Async bind connect fd: 0x%x bind handle: 0x%x" % (exit_info.sock_struct.dottedPort(), exit_info.old_fd, bind_handle)
                else:
                    bind_handle = exit_info.syscall_instance.paramOffPtr(7, [8], exit_info.frame, word_size) 
                    trace_msg = trace_msg + " %s fd: 0x%x  bind handle??: 0x%x" % (exit_info.sock_struct.getString(), exit_info.old_fd, bind_handle)
                   
                self.lgr.debug('winCallExit %s' % (trace_msg)) 

            else:
                max_count = min(exit_info.count, 100)
                output_data = self.mem_utils.readBytes(self.cpu, exit_info.retval_addr, max_count)
                odata_hx = None
                if output_data is not None and exit_info.count > 0:
                    odata_hx = binascii.hexlify(output_data)
                    trace_msg = trace_msg + ' output_data: %s' % (odata_hx)

        else:
            self.lgr.debug('winCallExit %s' % (trace_msg)) 
        trace_msg=trace_msg+'\n'

        if exit_info.matched_param is not None and exit_info.matched_param.break_simulation:
            self.lgr.debug('winCallExit found matching call parameter %s' % str(exit_info.matched_param.match_param))
            self.matching_exit_info = exit_info
            if  exit_info.asynch_handler is not None and exit_info.asynch_handler.trace_msg is not None:
                trace_msg = exit_info.asynch_handler.trace_msg
            self.context_manager.setIdaMessage(trace_msg)
            print(trace_msg)
            self.lgr.debug(trace_msg)
            #self.lgr.debug('winCallExit found matching call parameters callnum %d name %s' % (exit_info.callnum, callname))
            #my_syscall = self.top.getSyscall(self.cell_name, callname)
            my_syscall = exit_info.syscall_instance
            #async_waiting = False
            #if  exit_info.asynch_handler is not None and exit_info.asynch_handler.exit_info is not None:
            #    async_waiting = True
            #    self.lgr.debug('winCallExit think async still waiting so do not stop')
            #if not async_waiting and (not my_syscall.linger or (my_syscall.name == 'traceAll' and exit_info.matched_param.name.startswith('runTo'))):
            if async_was_ready and (not my_syscall.linger or (my_syscall.name == 'traceAll' and exit_info.matched_param.name.startswith('runTo'))):
                self.lgr.debug('winCallExit linger is false, call stopTrace')
                self.stopTrace()
                if my_syscall is None:
                    self.lgr.error('winCallExit could not get syscall for %s' % callname)
                else:
                    if eax != 0:
                        new_msg = exit_info.trace_msg + ' ' + trace_msg
                        self.context_manager.setIdaMessage(new_msg)
                    self.lgr.debug('winCallExit call stopAlone of syscall')

                    stop_param = callname
                    if callname in ['DeviceIoControlFile'] and exit_info.socket_callname is not None:
                        stop_param = exit_info.socket_callname
                    self.lgr.debug('winCallExit add call param %s to syscall remove list' % exit_info.matched_param.name)
                    my_syscall.appendRmParam(exit_info.matched_param.name)
                    SIM_run_alone(my_syscall.stopAlone, stop_param)
                    self.top.idaMessage() 
                    # remove it from syscall else there will be stop hap to execute
                    #if not my_syscall.linger: 
                    #    self.top.rmSyscall(exit_info.call_params.name, cell_name=self.cell_name)
    
        if trace_msg is not None and len(trace_msg.strip())>0:
            #self.lgr.debug('cell %s %s'  % (self.cell_name, trace_msg.strip()))
            self.traceMgr.write(trace_msg) 
        return True

    def stopTrace(self):
        for context in self.exit_tids:
            #self.lgr.debug('sharedSyscall stopTrace context %s' % str(context))
            for eip in self.exit_hap:
                self.context_manager.genDeleteHap(self.exit_hap[eip], immediate=True)
                #self.lgr.debug('sharedSyscall stopTrace removed exit hap for eip 0x%x context %s' % (eip, str(context)))
            self.exit_tids[context] = {}
        for eip in self.exit_hap:
            self.exit_info[eip] = {}

    def openCallParams(self, exit_info):
            if exit_info.matched_param is not None and type(exit_info.matched_param.matched_param) is str:
                self.lgr.debug('winCallExit openCallParams open check string %s against %s' % (exit_info.fname, exit_info.matched_param.match_param))
                #if eax < 0 or exit_info.call_params.match_param not in exit_info.fname:
                if exit_info.matched_param.match_param not in exit_info.fname:
                    ''' no match, set call_param to none '''
                    exit_info.matched_param = None

    def getMatchingExitInfo(self):
        return self.matching_exit_info 


    def getSockType(self, tid, fd):
        sock_type = None
        if tid in self.tid_sockets and fd in self.tid_sockets[tid]:
            sock_type = self.tid_sockets[tid][fd]
        return sock_type

    def setReadFixup(self, callback):
        self.lgr.debug('winCallExit setReadFixup to %s' % callback)
        self.read_fixup_callback = callback

    def setSelectFixup(self, callback):
        self.lgr.debug('winCall exit setSelectFixup TBD not yet used')

