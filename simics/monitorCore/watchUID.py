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
import procInfo
import memUtils
P_CRED_ADDR = 'credential address'
CRED_ADDR = 'credential address'
E_CRED = 'effective uid'
R_CRED = 'real uid'
'''
watch BSD user credentials
'''
class watchUID():
    watching_pids = {}
    def __init__(self, top, cell_name, param, cell_info, os_p_utils, lgr):
        self.haps_added = 0
        self.haps_removed = 0
        self.lgr = lgr
        self.top = top
        self.param = param
        self.cell_name = cell_name

        self.os_p_utils = os_p_utils
        self.cb_num = {}
        self.break_num = {}
        self.cell_info = cell_info
        self.cb_num = {}
        self.break_num = {}

    class credInfo():
        def __init__(self, cell_name, cpu, pid, comm, area_type, value, r_uid, e_uid, addr):
            self.cell_name = cell_name
            self.cpu = cpu
            self.pid = pid
            self.comm = comm
            self.area_type = area_type
            self.value = value
            self.r_uid = r_uid
            self.e_uid = e_uid
            self.addr = addr

    def credChanged(self, cred_info, third, forth, memory):
        cpu, cur_addr, comm, pid = self.os_p_utils.getPinfo(cred_info.cpu)
        thread_addr = self.os_p_utils.getCurrentThreadAddr(cred_info.cpu)
        td_ucred = self.os_p_utils.mem_utils.readPtr(cred_info.cpu, thread_addr + self.param.td_ucred)
        if cred_info.area_type == CRED_ADDR:
            self.lgr.debug('uidChanged td_ucred address of %d (%s) changing by  %s %d (%s)' % (cred_info.pid, cred_info.comm, self.cell_name, pid, comm))
            r_uid, e_uid = self.getIds(td_ucred, cpu)
            value = SIM_get_mem_op_value_le(memory)
            new_r_uid, new_e_uid = self.getIds(value, cpu)
            self.lgr.debug('recorded ids: %d %d  current: %d %d  to be: %d %d' % (cred_info.e_uid, cred_info.r_uid, e_uid, r_uid, new_e_uid, new_r_uid))
            self.lgr.debug('address was %x, changing to %x'  % (td_ucred, value))
        elif cred_info.area_type == E_CRED:
            self.lgr.debug('uidChanged td_ucred e_uid value of %d (%s) changing by  %s %d (%s)' % (cred_info.pid, cred_info.comm, self.cell_name, pid, comm))
            r_uid, e_uid = self.getIds(td_ucred, cpu)
            new_e_uid = SIM_get_mem_op_value_le(memory)
            self.lgr.debug('recorded ids: %d  current: %d  to be: %d' % (cred_info.e_uid, e_uid, new_e_uid))
        
        
       
    def getIds(self, address, cpu):
        e_uid_addr = address + self.os_p_utils.mem_utils.WORD_SIZE
        e_uid = self.os_p_utils.mem_utils.readWord32(cpu, e_uid_addr)
        r_uid_addr = address + 2*self.os_p_utils.mem_utils.WORD_SIZE
        r_uid = self.os_p_utils.mem_utils.readWord32(cpu, r_uid_addr)
        return e_uid, r_uid

    def addHap(self, pid, comm, addr, length, area_type, cpu):
        #cell = cpu.physical_memory
        #phys_block = cpu.iface.processor_info.logical_to_physical(addr, Sim_Access_Read)
        #if phys_block.address == 0:
        #    self.lgr.debug('watchUID, addHap, add 0x%x has physical address of zero' % addr)
        #    return
        cell = self.cell_info.cell_context[self.cell_name]
        break_num = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Write, 
                        addr, length, 0)
        #break_num = SIM_breakpoint(cell, Sim_Break_Physical, Sim_Access_Write, 
        #                phys_block.address, length, 0)
        self.break_num[pid].append(break_num)
        value = None
        r_uid = None
        e_uid = None
        if area_type == CRED_ADDR:
            value = addr
            cred_addr = self.os_p_utils.mem_utils.readPtr(cpu, addr)
            e_uid, r_uid = self.getIds(cred_addr, cpu)
        elif area_type == E_CRED:
            e_uid = self.os_p_utils.mem_utils.readWord32(cpu, addr)
        elif area_type == R_CRED:
            r_uid = self.os_p_utils.mem_utils.readWord32(cpu, addr)

        cred_info = self.credInfo(self.cell_name, cpu, pid, comm, area_type, value, r_uid, e_uid, addr)
        hap_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.credChanged, cred_info, break_num)
        self.lgr.debug('watchUID addHap for %s:%d (%s) break_num: %d hap_num: %d addr %x area_type: %s' % (self.cell_name, pid, comm, 
           break_num, hap_num, addr, area_type))
        self.cb_num[pid].append(hap_num)
    ''' MFT TBD: add user id watch address determination to os utils and fix for Linux
        Also: watch the pointer to the credential as well as the credential itself?
    ''' 
    def addPid(self, pid, comm, cur_addr, cpu):
        # TBD put this offset in param!
        self.break_num[pid] = [] 
        self.cb_num[pid] = [] 
        thread_addr = self.os_p_utils.getCurrentThreadAddr(cpu)
        td_ucred = thread_addr + self.param.td_ucred
        td_ucred_addr = self.os_p_utils.mem_utils.readPtr(cpu, td_ucred)
        self.addHap(pid, comm, td_ucred, self.os_p_utils.mem_utils.WORD_SIZE, CRED_ADDR, cpu)

        td_ucred_e_uid_addr = td_ucred_addr + self.os_p_utils.mem_utils.WORD_SIZE
        self.addHap(pid, comm, td_ucred_e_uid_addr, self.os_p_utils.mem_utils.WORD_SIZE, E_CRED, cpu)
        td_ucred_r_uid_addr = td_ucred_e_uid_addr + self.os_p_utils.mem_utils.WORD_SIZE
        self.addHap(pid, comm, td_ucred_r_uid_addr, self.os_p_utils.mem_utils.WORD_SIZE, R_CRED, cpu)

    def cleanAlone(self, pid):
        if pid in self.cb_num:
            for cb_num in self.cb_num[pid]:
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop", cb_num)
            for break_num in self.break_num[pid]:
                self.lgr.debug('watchUID cleanAlone for %s:%d break_num: %d' % (self.cell_name, pid, break_num))
                SIM_delete_breakpoint(break_num)
            del self.cb_num[pid]
            del self.break_num[pid]

    def cleanPid(self, pid):
        self.lgr.debug('cleanPid in watchUID do clean pid for %s:%d' % (self.cell_name, pid))
        if pid in self.cb_num:
            SIM_run_alone(self.cleanAlone, pid)
