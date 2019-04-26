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
import memUtils
from monitorLibs import forensicEvents 
'''
   Watch per-process Linux credentials for modification
   TBD put offsets (e.g., uid) into parameter file
'''
CRED_ADDR = 'credential address'
REAL_CRED_ADDR = 'real credential address'
CRED_STRUCT = 'credential structure'
REAL_CRED_STRUCT = 'real credential structure'
PERSONALITY_FIELD = 'personality field'
# offset into credential struct to get us past counters and such
# current just one word
# offset before pid of the personality value
PERSONALITY_OFFSET = -7
class watchLinuxCreds():
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
        self.cred_struct = {}
        self.cell_info = cell_info
        self.ID_OFFSET = os_p_utils.mem_utils.WORD_SIZE
        self.cb_num = {}
        self.break_num = {}
        self.cred_struct = {}
        self.EIP = self.os_p_utils.mem_utils.getEIP()
        self.lgr.debug('watchLinuxCreds, init for %s' % cell_name)

    def getIds(self, address, cpu):
        uid_addr = address + 4*self.os_p_utils.mem_utils.WORD_SIZE
        uid = memUtils.readWord32(cpu, uid_addr)
        e_uid_addr = address + 8*self.os_p_utils.mem_utils.WORD_SIZE
        e_uid = memUtils.readWord32(cpu, e_uid_addr)
        return uid, e_uid

    def personalityChanged(self, cred_info, third, breakpoint, memory):
        cpu, cur_addr, comm, pid = self.os_p_utils.getPinfo(cred_info.cpu)
        current_cell_name = self.top.getTopComponentName(cpu)
        if cred_info.pid in self.cb_num:
            value = SIM_get_mem_op_value_le(memory)
            self.lgr.critical('watchLinuxCreds, personality changed, %d (%s)  new value %x' % (pid, comm, value))
        else:
            self.lgr.debug('lingering watchLinuxCreds personality Hap for %s:%d (%s) type: %s addr %x' % \
              (self.cell_name, cred_info.pid, cred_info.comm, cred_info.area_type, 
               memory.physical_address))
            SIM_break_simulation('lingering hap in credChanged')

    def credChanged(self, cred_info, third, breakpoint, memory):
        cpu, cur_addr, comm, pid = self.os_p_utils.getPinfo(cred_info.cpu)
        current_cell_name = self.top.getTopComponentName(cpu)
        if cred_info.pid in self.cb_num:
            value = SIM_get_mem_op_value_le(memory)
            if cred_info.area_type == CRED_ADDR:
                ''' the credential pointed to by this field can be switched '''
                uid, e_uid = self.getIds(value, cpu)
                if uid == cred_info.uid and e_uid == cred_info.e_uid:
                    ''' switched to credential for same user.  '''
                    ''' returning remove the previous if any '''
                    if pid not in self.break_num:
                        self.lgr.debug('credChanged, cellname: %s pid %d not in break_num list for %s' % (self.cell_name, pid, comm))
                        return
                    num_breaks = len(self.break_num[pid])
                    if num_breaks > 4:
                        self.lgr.debug('credChanged, cell_name: %s  current_cell_name: %s pid: %d comm: %s' % (self.cell_name,
                            current_cell_name, pid, comm))
                        self.lgr.debug('credChanged delete hap %d break %d' % (self.cb_num[pid][num_breaks-1],
                           self.break_num[pid][num_breaks-1]))
                        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.cb_num[pid][num_breaks-1])
                        self.lgr.debug('back from delete hap')
                        SIM_delete_breakpoint(self.break_num[pid][num_breaks-1])
                        self.lgr.debug('back from delete break')
                        self.break_num[pid].pop()
                        self.cb_num[pid].pop()
                    ''' If not the original crediential, watch the new one.'''
                    if (value+self.ID_OFFSET) == self.cred_struct[cred_info.pid]:
                        self.lgr.debug('credChanged, not original cred, watch new one, do addhap %s %d (%s)' % (self.cell_name, pid, comm))
                        self.addHap(pid, comm, value+self.ID_OFFSET, 
                            8*self.os_p_utils.mem_utils.WORD_SIZE, CRED_STRUCT, cpu)
                    return
            eip = self.os_p_utils.mem_utils.getRegValue(cpu, 'eip')
            if cred_info.value is not None:
                o_uid, o_e_uid = self.getIds(cred_info.value, cpu)
                ''' TBD wtf? is process starting as root? Some kinda cache thing were not updated until referenced?'''
                if o_uid != 0:
                    self.lgr.critical('cred changed by %s:%d (%s) for %s:%d (%s) type: %s ; addr writtn to: %x at eip %x  break_num: %d' % \
                        (current_cell_name, pid, comm, self.cell_name, cred_info.pid, 
                         cred_info.comm, cred_info.area_type, memory.physical_address, eip, breakpoint))
                    ''' the address of the credential within the task_struct is what changed '''
                    self.lgr.critical('old value was %x new may be %x ' % (cred_info.value, value))
                    uid, e_uid = self.getIds(value, cpu)
                    self.lgr.critical('new uid %d  new e_uid %d old was %d %d' % (uid, e_uid, o_uid, o_e_uid))                
                    if cred_info.uid is not None:
                        self.lgr.critical('orig uid %d  orig e_uid %d' % \
                           (cred_info.uid, cred_info.e_uid))
                    self.top.addLogEvent(cred_info.comm, cred_info.pid, cred_info.comm, forensicEvents.KERNEL_CRED,
                         'modification of user creds: %s at %x ' % (cred_info.area_type, memory.physical_address))
            else:
                self.lgr.critical('cred changed by %s:%d (%s) for %s:%d (%s) type: %s ; addr writtn to: %x at eip %x  break_num: %d' % \
                    (current_cell_name, pid, comm, self.cell_name, cred_info.pid, 
                     cred_info.comm, cred_info.area_type, memory.physical_address, eip, breakpoint))
                ''' content of a credential record changed '''
                cell = cred_info.cpu.physical_memory
                phys_block = cred_info.cpu.iface.processor_info.logical_to_physical(cred_info.addr, Sim_Access_Read)
                delta = memory.physical_address - phys_block.address 
                self.lgr.critical('address of credential was %x (physical: %x),  wrote to %x, that is offset %x' \
                    % (cred_info.addr, phys_block.address, memory.physical_address, delta)) 
                value_was = SIM_read_phys_memory(cred_info.cpu, memory.physical_address, self.os_p_utils.mem_utils.WORD_SIZE)
                self.lgr.info('the value to be written is %x, and it was %x' % (value, value_was))
                #SIM_break_simulation('wait til positive territory...')
                self.top.addLogEvent(cred_info.comm, cred_info.pid, cred_info.comm, forensicEvents.KERNEL_CRED,
                     'modification of user creds: %s at %x ' % (cred_info.area_type, memory.physical_address))
        else:
            self.lgr.debug('lingering watchLinuxCreds Hap for %s:%d (%s) type: %s addr %x break num %d' % \
              (self.cell_name, cred_info.pid, cred_info.comm, cred_info.area_type, 
               memory.physical_address, breakpoint))
            SIM_break_simulation('lingering hap in credChanged')

    class credInfo():
        def __init__(self, cell_name, cpu, pid, comm, area_type, value, uid, e_uid, addr):
            self.cell_name = cell_name
            self.cpu = cpu
            self.pid = pid
            self.comm = comm
            self.area_type = area_type
            self.value = value
            self.uid = uid
            self.e_uid = e_uid
            self.addr = addr

    def addPersonalityHap(self, pid, comm, addr, length, area_type, cpu):
        cell = cpu.physical_memory
        phys_block = cpu.iface.processor_info.logical_to_physical(addr, Sim_Access_Read)
        if phys_block.address == 0:
            self.lgr.debug('watchLinuxCreds, addPersonalityHap, add 0x%x has physical address of zero' % addr)
            return
        #cell = self.cell_info.cell_context[self.cell_name]
        #break_num = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Write, 
        #                addr, length, 0)
        break_num = SIM_breakpoint(cell, Sim_Break_Physical, Sim_Access_Write, 
                        phys_block.address, length, 0)
        self.break_num[pid].append(break_num)
        # TBD check this, why did it work with no value defined?
        value = None
        uid = None
        e_uid = None
        cred_info = self.credInfo(self.cell_name, cpu, pid, comm, area_type, value, uid, e_uid, addr)
        hap_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.personalityChanged, cred_info, break_num)
        self.lgr.debug('watchLinuxCreds addPersonalityHap for %s:%d (%s) break_num: %d hap_num: %d addr %x area_type: %s' \
           % (self.cell_name, pid, comm, break_num, hap_num, addr, area_type))
        self.cb_num[pid].append(hap_num)

    def addHap(self, pid, comm, addr, length, area_type, cpu):
        cell = cpu.physical_memory
        #cell = self.cell_info.cell_context[self.cell_name]
        phys_block = cpu.iface.processor_info.logical_to_physical(addr, Sim_Access_Read)
        if phys_block.address == 0:
            self.lgr.debug('watchLinuxCreds, addHap, add 0x%x has physical address of zero' % addr)
            return
        #break_num = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Write, 
        #                addr, length, 0)
        break_num = SIM_breakpoint(cell, Sim_Break_Physical, Sim_Access_Write, 
                        phys_block.address, length, 0)
        self.break_num[pid].append(break_num)
        value = None
        uid = None
        e_uid = None
        if area_type == CRED_ADDR or area_type == REAL_CRED_ADDR:
            value = addr
        if area_type == CRED_ADDR:
            cred_addr = self.os_p_utils.mem_utils.readPtr(cpu, addr)
            uid, e_uid = self.getIds(cred_addr, cpu)
        cred_info = self.credInfo(self.cell_name, cpu, pid, comm, area_type, value, uid, e_uid, addr)
        hap_num = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.credChanged, cred_info, break_num)
        self.lgr.debug('watchLinuxCreds addHap for %s:%d (%s) break_num: %d hap_num: %d addr %x area_type: %s' % (self.cell_name, pid, comm, 
           break_num, hap_num, addr, area_type))
        self.cb_num[pid].append(hap_num)
       
    ''' 
        Watch process credentials
    ''' 
    def addPid(self, pid, comm, cur_addr, cpu):
        self.lgr.debug('watchLinuxCred addPid %s %d (%s)' % (self.cell_name, pid, comm))
        # TBD put this offset in param!
        # or, for now, rely on creds preceeding comm
        real_cred_addr = cur_addr + (self.param.ts_comm - 2*self.os_p_utils.mem_utils.WORD_SIZE)
        cred_addr = cur_addr + (self.param.ts_comm - self.os_p_utils.mem_utils.WORD_SIZE)
        #real_cred_addr = cur_addr + 0x224
        #cred_addr = cur_addr + 0x228
 
        # hardwired value to get us past counters 
        real_cred_struct = self.os_p_utils.mem_utils.readPtr(cpu, real_cred_addr) + self.ID_OFFSET
        # note address of original cred struct so we know when it is switching back
        self.cred_struct[pid] = self.os_p_utils.mem_utils.readPtr(cpu, cred_addr) + self.ID_OFFSET
        self.break_num[pid] = [] 
        self.cb_num[pid] = [] 
        self.addHap(pid, comm, real_cred_addr, self.os_p_utils.mem_utils.WORD_SIZE, REAL_CRED_ADDR, cpu)
        self.addHap(pid, comm, cred_addr, self.os_p_utils.mem_utils.WORD_SIZE, CRED_ADDR, cpu)
        self.addHap(pid, comm, real_cred_struct, 8*self.os_p_utils.mem_utils.WORD_SIZE, REAL_CRED_STRUCT, cpu)
        self.addHap(pid, comm, self.cred_struct[pid], 8*self.os_p_utils.mem_utils.WORD_SIZE, CRED_STRUCT, cpu)
        if self.top.isCB(comm):
            pers_addr = cur_addr + self.param.ts_pid + PERSONALITY_OFFSET
            self.addPersonalityHap(pid, comm, pers_addr, self.os_p_utils.mem_utils.WORD_SIZE, PERSONALITY_FIELD)
 
    class cellPid():
        def __init__(self, cell_name, pid):
            self.cell_name = cell_name
            self.pid = pid

    def rmRecentHap(self, cell_name, pid):
        pass

    def cleanAlone(self, cell_pid):
        cell_name = cell_pid.cell_name
        pid = cell_pid.pid
        if pid in self.cb_num:
            for cb_num in self.cb_num[pid]:
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop", cb_num)
            for break_num in self.break_num[pid]:
                self.lgr.debug('watchLinuxCred cleanAlone for %s:%d break_num: %d' % (cell_name, pid, break_num))
                SIM_delete_breakpoint(break_num)
            del self.cb_num[pid]
            del self.break_num[pid]

    def cleanPid(self, pid):
        self.lgr.debug('cleanPid in watchLinuxCred do clean pid for %s:%d' % (self.cell_name, pid))
        if pid in self.cb_num:
            cell_pid = self.cellPid(self.cell_name, pid)
            SIM_run_alone(self.cleanAlone, cell_pid)
        #self.lgr.debug('watchUID created %d removed %d' % (self.haps_added, self.haps_removed)) 
