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
'''
import net
import resimUtils
import os
class NetLink():
    def __init__(self, pid, group):
        self.pid = pid
        self.group = group

class MyIPC():
    def __init__(self, top, cpu, cell_name, lgr):
        self.lgr = lgr
        self.cpu = cpu
        self.top = top
        self.syscallManager = None
        self.good_binds = {}
        self.failed_binds = {}
        self.sockets = {}
        self.ignore_comm = resimUtils.getListFromComponentFile(top, cell_name, 'IPC_IGNORE_COMM', lgr)

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
            
    def doSyscalls(self):
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
        if eax == -1:
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
              
                 
