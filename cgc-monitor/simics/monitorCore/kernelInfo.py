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
import getSymbol
import logging
import os
import bsdUtils
'''
    Obtain a set of kernel symbol offsets for Linux and FreeBSD
    TBD open the file once?
'''
class kernelInfo():
    syscall_offset = None
    userret_offset = None
    sysenter_exit = None
    sig_offset = None
    syscall_exit = None
    sig_user = None
    current_task = None
    execve_offset = None
    sys_clone = None
    sysentry_offset = None
    default_se_exit = None
    cgc_bytes_offset = None
    # range of addresses that might call do_exit as part of an exit
    exit_range_min = None
    exit_range_max = None
    do_group_exit = None

    do_exit = None
    do_exit_max = None
       
  
    def __init__(self, lgr, os_type, param, system_map, cgc_bytes):
        self.lgr = lgr
        fname = system_map
        if not os.path.isfile(fname):
            print('kernelInfo, system map not found at %s' % system_map)
            self.lgr.critical('kernelInfo, system map not found at %s' % system_map)
            exit(1)
        else:
            lgr.debug('using system map: %s' % system_map)
        self.os_type = os_type
        if os_type == 'freeBSD':
            #fname = 'kernel.symbols'
            self.syscall_offset = getSymbol.getSymbol(fname, 'syscall', True)
            lgr.info('freeBSD syscall offset found at %x' % self.syscall_offset)
            self.userret_offset = getSymbol.getSymbol(fname, 'userret', True)
            lgr.info('freeBSD userret offset found at %x' % self.userret_offset)
            self.sig_offset = getSymbol.getSymbol(fname, 'postsig', True)
            lgr.info('freeBSD postsig offset found at %x' % self.sig_offset)
            self.sigexit_offset = getSymbol.getSymbol(fname, 'sigexit', True)
            lgr.info('freeBSD sigexit offset found at %x' % self.sigexit_offset)
            self.execve_offset = getSymbol.getSymbol(fname, 'kern_execve', True)
            #self.execve_offset = getSymbol.getSymbol(fname, 'pre_execve', True)
            lgr.info('freeBSD sys_execve found at %x' % self.execve_offset)
            self.do_exit = getSymbol.getSymbol(fname, 'sys_sys_exit', True)
            lgr.info('freeBSD sys_sys_exit found at %x' % self.do_exit)
            self.current_task = 0
        elif os_type == 'freeBSD64':
            #fname = 'kernel.symbols'
            #self.syscall_offset = getSymbol.getSymbol(fname, 'amd64_syscall', True)
            self.syscall_offset = getSymbol.getSymbol(fname, 'ia32_syscall', True)
            lgr.info('freeBSD syscall offset found at %x' % self.syscall_offset)
            self.userret_offset = getSymbol.getSymbol(fname, 'userret', True)
            lgr.info('freeBSD userret offset found at %x' % self.userret_offset)
            self.sig_offset = getSymbol.getSymbol(fname, 'postsig', True)
            lgr.info('freeBSD postsig offset found at %x' % self.sig_offset)
            self.sigexit_offset = getSymbol.getSymbol(fname, 'sigexit', True)
            lgr.info('freeBSD sigexit offset found at %x' % self.sigexit_offset)
            self.execve_offset = getSymbol.getSymbol(fname, 'kern_execve', True)
            #self.execve_offset = getSymbol.getSymbol(fname, 'pre_execve', True)
            lgr.info('freeBSD sys_execve found at %x' % self.execve_offset)
            self.do_exit = getSymbol.getSymbol(fname, 'sys_sys_exit', True)
            lgr.info('freeBSD sys_sys_exit found at %x' % self.do_exit)
            self.current_task = 0
        elif os_type == 'linux':
            self.exit_range_min = getSymbol.getSymbol(fname, 'sys_exit', True)
            self.exit_range_max = getSymbol.getSymbol(fname, 'sys_exit_group', True)
            self.do_group_exit = getSymbol.getSymbol(fname, 'do_group_exit', True)
            self.do_exit = getSymbol.getSymbol(fname, 'do_exit', True)
            self.do_exit_max = getSymbol.getSymbol(fname, 'complete_and_exit', True)+0x20
            lgr.debug('linux exit_range is %x to %x' % (self.exit_range_min, self.exit_range_max))
            self.sig_seccomp = getSymbol.getSymbol(fname, 'seccomp_send_sigsys', True)
            lgr.debug('linux sig_seccomp is %x' % self.sig_seccomp)
            #fname = 'System.map-3.13.2'
            #c1304944 T ia32_sysenter_target
            #self.syscall_offset = 0xc1304944
            self.syscall_offset = getSymbol.getSymbol(fname, 'syscall_call', True)
            lgr.info('linux syscall_call offset found at %x' % self.syscall_offset)
            #self.sysentry_offset = getSymbol.getSymbol(fname, 'sysenter_past_esp', True)
            self.sysentry_offset = getSymbol.getSymbol(fname, 'ia32_sysenter_target', True)
            #self.sysentry_offset = getSymbol.getSymbol(fname, 'sysenter_do_call', True)
            lgr.info('linux ia32_sysenter_target offset found at %x' % self.sysentry_offset)

            #resume_userspace
            self.userret_offset = getSymbol.getSymbol(fname, 'resume_userspace', True)
            lgr.info('linux resume_userspace found at %x' % self.userret_offset)
            #self.userret_offset = 0xc1300358
            #0xc13003d7 t syscall_exit
            #self.userret_offset = 0xc13003d7
            # sysenter_exit
            #self.userret_offset = 0xc13049e9
            #do_signal
            #self.sig_offset = 0xc1001503
            # hackage, do_signal is c1001503, then find call to get_signal from there 
            # after call to get_signal, sig number in edx at 0xc1001536
            # ONLY used for user sigs to get player going.  TBD replace with other signaling?
            #self.sig_user = 0xc1001536
            self.sig_user = getSymbol.getSymbol(fname, 'do_signal', True)
            self.sig_user = self.sig_user + 0x33
            lgr.info('linux get_signal found at %x' % self.sig_user)

            #c103877a T get_signal_to_deliver

            #c1001a08 T signal_fault

            #self.signal_fault = 0xc1001a08
            #c103877a T get_signal_to_deliver
            #c1038321 T kill_pid
            # default_handler c102d02f
            #c102e9b1 T do_exit
            # stop linux at do exit for fatal faults
            #self.sig_offset = 0xc102e9b1
            self.do_exit = getSymbol.getSymbol(fname, 'do_exit', True)
            lgr.info('linux do_exit found at %x' % self.do_exit)
            self.sig_offset = getSymbol.getSymbol(fname, 'do_exit', True)
            lgr.info('linux using do_exit as sig_offset')

            #c1304f64 T iret_exc

            #c13049e9 t sysenter_exit
            #self.sysenter_exit = 0xc13049e9
            self.sysenter_exit = getSymbol.getSymbol(fname, 'sysenter_exit', True)
            lgr.info('linux sysenter_exit found at %x' % self.sysenter_exit)
            #self.iret_exc = 0xc1304f64
            #self.resume_userspace = 0xc1300358

            #0xc13003d7 t syscall_exit
            #self.syscall_exit = 0xc13003d7
            self.syscall_exit = getSymbol.getSymbol(fname, 'syscall_exit', True)
            lgr.info('linux syscall_exit found at %x' % self.syscall_exit)

            #self.current_task = 0xc14f166c
            self.current_task = getSymbol.getSymbol(fname, 'current_task', True)
            lgr.info('linux current_task found at %x' % self.current_task)

            #self.execve_offset = getSymbol.getSymbol(fname, 'do_execve', True)
            self.execve_offset = getSymbol.getSymbol(fname, 'SyS_execve', True)
            lgr.info('linux sys_execve found at %x' % self.execve_offset)

            # punch a hole in the kernel rop for this address
            self.default_se_exit = getSymbol.getSymbol(fname, 'default_se_exit', True)
            if self.default_se_exit is not None:
                lgr.info('linux default_se_exit found at %x' % self.default_se_exit)

            with open(cgc_bytes, 'rb') as f_in:
                s = f_in.read()
                try:
                    self.cgc_bytes_offset = int(s)
                    lgr.debug('kernelInfo, cgc_bytes is %d' % self.cgc_bytes_offset)
                except:
                    lgr.error('could not turn cgc_bytes to int %s' % s)

        elif os_type == 'linux64':
            print('map file is %s' % fname)
            #self.execve_offset = getSymbol.getSymbol(fname, 'sys_execve', True)
            #self.execve_offset = getSymbol.getSymbol(fname, 'do_execve_common.isra.25', True)
            self.execve_offset = getSymbol.getSymbol(fname, 'do_execve', True)
            lgr.info('linux64 sys_execve found at %x' % self.execve_offset)
            self.do_exit = getSymbol.getSymbol(fname, 'do_exit', True)
            lgr.info('linux64 do_exit found at %x' % self.do_exit)
            self.sig_offset = getSymbol.getSymbol(fname, 'do_exit', True)
            lgr.info('linux64 using do_exit as sig_offset')
            # note current_task is not used for 64-bit, here for debug messages
            self.current_task = getSymbol.getSymbol(fname, 'current_task', True)
            lgr.info('linux64 current_task found at %x' % self.current_task)

            self.syscall_offset = getSymbol.getSymbol(fname, 'system_call', True)
            #self.sysentry_offset = getSymbol.getSymbol(fname, 'system_call', True)
            lgr.info('linux64 system_call offset found at %x' % self.syscall_offset)
            self.userret_offset = getSymbol.getSymbol(fname, 'ret_from_sys_call', True)
            lgr.info('linux64 ret_from_sys_call found at %x' % self.userret_offset)
            #resume_userspace
            self.exit_range_min = getSymbol.getSymbol(fname, 'sys_exit', True)
            self.exit_range_max = getSymbol.getSymbol(fname, 'sys_exit_group', True)
            self.do_group_exit = getSymbol.getSymbol(fname, 'do_group_exit', True)
            self.do_exit = getSymbol.getSymbol(fname, 'do_exit', True)
            self.sys_clone = getSymbol.getSymbol(fname, 'sys_clone', True)
            self.ret_from_fork = getSymbol.getSymbol(fname, 'ret_from_fork', True)
        else:
             print 'kernelInfo unknown os type %s' % os_type
             lgr.error('kernelInfo unknown os type %s' % os_type)
 
    
    def isExit(self, addr):
        if self.os_type.startswith('freeBSD'):
            return False
        if addr <= self.exit_range_max and addr >= self.exit_range_min:
            self.lgr.debug('is an exit %x' % addr)
            return True
        elif addr < self.do_exit_max and addr >= self.do_exit:
            self.lgr.debug('is an do_exit %x' % addr)
            return True
        else:
            self.lgr.debug('not an exit, %x not between %x and %x' % (addr, self.exit_range_min, self.exit_range_max))
            return False
        
    def isSysExit(self, addr):
        if self.os_type.startswith('freeBSD'):
            return False
        if addr < self.do_group_exit and addr >= self.exit_range_min:
            self.lgr.debug('is an sys exit %x' % addr)
            return True
        elif addr < self.do_exit_max and addr >= self.do_exit:
            self.lgr.debug('is an do_exit %x' % addr)
            return True
        else:
            self.lgr.debug('not a sys exit, %x not between %x and %x' % (addr, self.exit_range_min, self.do_group_exit))
            return False

