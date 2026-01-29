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
Intercept use of AF_NETLINK failures, e.g., due to use of custom kernel modules
and mask some of the failures while documenting them for analysis.
RESim must be run with traceAll for this to work, e.g., trackThreads does not
watch bind/sendmsg...
'''
import struct
import net
import resimUtils
import os
import binascii
from simics import *
class NetLink():
    def __init__(self, pid, group):
        self.pid = pid
        self.group = group

class MyIPC():
    def __init__(self, top, cpu, cell_name, mem_utils, param, lgr):
        self.lgr = lgr
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.param = param
        self.top = top
        self.syscallManager = None
        self.good_binds = {}
        self.failed_binds = {}
        self.sockets = {}
        self.no_select_list = []
        self.pending_recv = {}
        self.ignore_comm = resimUtils.getListFromComponentFile(top, cell_name, 'IPC_IGNORE_COMM', lgr)
        self.fake_ipc = resimUtils.getListFromComponentFile(top, cell_name, 'IPC_FAKE', lgr)

    def socket(self, tid, comm, fd, socket_info):
        if comm in self.ignore_comm:
            return
        if socket_info is not None and socket_info.domain == net.AF_NETLINK:
            self.lgr.debug('myIPC socket is AF_NETLINK tid: %s fd %d' % (tid, fd))
            if tid not in self.sockets:
                self.sockets[tid] = {}
            self.sockets[tid][fd] = socket_info

    def bindOK(self, tid, comm, fd, ss):
        if comm in self.ignore_comm:
            return
        self.lgr.debug('myIPC bindOK tid:%s fd: %d' % (tid, fd))
        if ss.sa_family == net.AF_NETLINK:
            self.lgr.debug('myIPC bindOK is NETLINK')
            if tid not in self.good_binds:
                self.good_binds[tid] = {}
            self.good_binds[tid][fd] = ss

    def bindFailed(self, tid, comm, fd, ss):
        ''' return 0 if the bind failure is to be masked. '''
        if comm in self.ignore_comm:
            return None
        retval = None
        self.lgr.debug('myIPC bindFailed tid:%s fd: %d' % (tid, fd))
        if ss.sa_family == net.AF_NETLINK:
            self.lgr.debug('myIPC bindFailed is NETLINK')
            if tid not in self.failed_binds:
                self.failed_binds[tid] = {}
            self.failed_binds[tid][fd] = ss
            retval = 0
        return retval

    def select(self, exit_info):
        ''' return true if we will handle change in execution '''
        retval = None
        self.lgr.debug('myIPC select tid:%s' % exit_info.tid) 
        tid = exit_info.tid 
        comm = exit_info.comm 
        eret_addr = self.param.arm_ret
        if tid in self.failed_binds and comm in self.fake_ipc and comm not in self.no_select_list:
            for fd in self.failed_binds[tid]:
                if self.failed_binds[tid][fd] is not None: 
                    #check_fd = self.failed_binds[tid][fd]
                    has_fd = exit_info.select_info.hasReadFD(fd)
                    self.lgr.debug('myIPC tid:%s (%s) select fd: %d  does select read have it? %r' % (tid, comm, fd, has_fd))
                    if has_fd:
                        retval = fd
                        self.lgr.debug('myIPC select return address 0x%x' % eret_addr)
                        exit_info.select_info.clearAll()
                        exit_info.select_info.setReadFD(fd)
                        self.lgr.debug('myIPC select cleared FDs and set read for %d' % fd)
                        self.mem_utils.setRegValue(self.cpu, 'pc', eret_addr)
                        self.mem_utils.setRegValue(self.cpu, 'syscall_ret', 1)
                        #self.top.writeRegValue('syscall_ret', 1)
                        self.no_select_list.append(comm)
                        self.pending_recv[tid] = fd
                        break
        return retval        

    def recvmsg(self, exit_info):
        ''' return true if we will handle change in execution '''
        retval = False
        self.lgr.debug('myIPC recvmsg tid:%s' % exit_info.tid) 
        tid = exit_info.tid 
        comm = exit_info.comm 
        peek = False
        if exit_info.flags is not None:
            self.lgr.debug('myIPC recvmsg is peek')
            peek = exit_info.flags & net.MSG_PEEK
        eret_addr = self.param.arm_ret
        x='DEADBEEFBABABABA00'
        dog = binascii.unhexlify(x)
        dog_array=bytearray(dog)
        if tid in self.pending_recv and self.pending_recv[tid] == exit_info.old_fd:
            self.lgr.debug('myIPC recvmsg pending recieve for tid:%s FD: %d' % (tid, exit_info.old_fd))
            exit_info.msghdr.setByteArray(dog_array)
            retval = True
            self.mem_utils.setRegValue(self.cpu, 'pc', eret_addr)
            #self.mem_utils.setRegValue(self.cpu, 'syscall_ret', len(dog))
            self.top.writeRegValue('syscall_ret', len(dog))
            if not peek:
                self.pending_recv[tid] = None
            else:
                self.lgr.debug('myIPC recvmsg was peek, repeat for next recvmsg call')
        return retval    

    def doSyscalls(self):
        #NOT USED
        call_list = ['socket', 'bind', 'sendmsg', 'recvmsg']
        call_params = []
        self.sys_calls = self.syscallManager.watchSyscall(None, call_list, call_params, 'myIPC', stop_on_call=False, linger=True)
        self.lgr.debug('myIPC doSyscalls')

    def setSyscallManager(self, syscallManager):
        self.syscallManager = syscallManager

    def sendmsg(self, tid, comm, fd, msghdr, eax):
        if comm in self.ignore_comm:
            return None
        # return True if we should force return value to return length
        if eax == -1 or eax == -111:
            return None
        retval = None
        self.lgr.debug('myIPC sendmsg tid:%s fd: %d' % (tid, fd))
        if tid in self.good_binds:
            if fd in self.good_binds[tid]:
                self.lgr.debug('myIPC sendmsg tid:%s fd: %d in good_binds eax on sendmsg was 0x%x' % (tid, fd, eax))
                byte_array = msghdr.getByteArray()
                self.lgr.debug('myIPC sendmsg byte_array len %d' % len(byte_array))
                retval = len(byte_array)
       
        return retval
              
                 
