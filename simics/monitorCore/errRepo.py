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

STACK_SIZE=8192
TS_COMM=556
TS_PID=336
WORD_SIZE = 4
COMM_SIZE = 16
'''
reproduce simics problem in which reversing micro checkpoints get corrupted
'''
class errRepo():
    def __init__(self):
        print('errRepo begin')
        self.fault_cycle = None
        self.stop_hap = None 
        cpu = SIM_current_processor()
        self.sig_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, 0x102e9bd, 1, 0)
        self.sig_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop",
              self.sig_callback, cpu, self.sig_break)

        self.page_hap = SIM_hap_add_callback_obj_index("Core_Exception", cpu, 0,
                 self.page_fault_callback, cpu, 14)


    def rmHaps(self, dum):
        print('removing haps & breakpoint')
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.sig_hap)
        SIM_hap_delete_callback_id("Core_Exception", self.page_hap)
        SIM_delete_breakpoint(self.sig_break)

    def installStopHap(self, dum):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped",
                 self.stop_callback, None)

    def sig_callback(self, cpu, third, forth, fifth):
        '''
        Invoked when linux signal handling code is entered
        '''
        cpu, cur_addr, comm, pid = currentProcessInfo()
        if comm.startswith('CB'):
            print('in sig_callback for CB')
            SIM_run_alone(self.installStopHap, None)
            SIM_break_simulation('in sig_callback')
            SIM_run_alone(self.rmHaps, None)

    def page_fault_callback(self, cpu, one, exception_number):
        cpu, cur_addr, comm, pid = currentProcessInfo()
        if comm.startswith('CB'):
            self.fault_cycle = SIM_cycle_count(cpu)
            print('recorded fault cycle at %x' % self.fault_cycle)


    def go(self):
        SIM_run_command('enable-reverse-execution')
        SIM_run_command('disable-vmp')
        '''
        SIM_run_command('load-module state-assertion')
        SIM_run_command('state-assertion-create-file compression = gz file = /mnt/bigstuff/test.sa')
        SIM_run_command('sa0.add obj = viper.mb.cpu0.core[0][0] steps = 10000')

        SIM_run_command('sa0.start')
        '''
        SIM_run_command('set-bookmark mymark')
        SIM_run_command('continue')

    def runAlone(self, dum):
        '''
        skip to the instruction proceeding the previous fault
        '''
        previous = self.fault_cycle - 1
        print('in runAlone, do skip-to cycle=%d' % previous)
        SIM_run_command('skip-to cycle=%d' % previous)
        cpu = SIM_current_processor()
        reg_num = cpu.iface.int_register.get_number("esp")
        esp = cpu.iface.int_register.read(reg_num)
        phys_block = cpu.iface.processor_info.logical_to_physical(esp, Sim_Access_Read)
        print('A breakpoint has been set at esp %x   break -w p:0x%x' % (esp, phys_block.address))
        self.write_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, phys_block.address, 1, 0)
        print('Now, type "rev" to run back to the breakpoint, which will be a kernel address')
        print('Then return to where we were: "skip-to cycle=%d"' % previous)
        print('Then type "rev" and you will miss the memory write we saw previously, and end up at the bp push')
        print('The again do a "skip-to cycle=%d" and you will not go to the same instruction as the last skip to' % previous)


    def stop_callback(self, dum, one, two, three):
        print('in stop_hap')
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        SIM_run_alone(self.runAlone, None)
    

        
def currentProcessInfo():
    cur_processor = SIM_current_processor()
    cur_addr = getCurrentProcAddr(cur_processor)
    comm = readString(cur_processor, cur_addr + TS_COMM, COMM_SIZE)
    pid = readWord(cur_processor, cur_addr + TS_PID)
    return cur_processor, cur_addr, comm, pid

def readPhysBytes(cpu, paddr, len):
    return cpu.iface.processor_info_v2.get_physical_memory().iface.memory_space.read(cpu, paddr, len, 0)

def readString(cpu, vaddr, maxlen):
    s = ''
    phys_block = cpu.iface.processor_info.logical_to_physical(vaddr, Sim_Access_Read)
    if phys_block.address == 0:
        return None
    for v in readPhysBytes(cpu, phys_block.address, maxlen):
        if v == 0:
            return s
        s += chr(v)

    return None

def getCPL(cpu):
    reg_num = cpu.iface.int_register.get_number("cs")
    cs = cpu.iface.int_register.read(reg_num)
    mask = 3
    return cs & mask


'''
    Get address of the current task record
'''
def getCurrentProcAddr(cpu):
    cpl = getCPL(cpu)
    #if cpl == simics.Sim_CPU_Mode_User:
    if cpl != 0:
        tr_base = cpu.tr[7]
        esp = readPtr(cpu, tr_base + 4)
    else:
        reg_num = cpu.iface.int_register.get_number("esp")
        esp = cpu.iface.int_register.read(reg_num)
    ptr = esp - 1 & ~(STACK_SIZE - 1)


    ret_ptr = readPtr(cpu, ptr)
    return ret_ptr

def readPtr(cpu, vaddr):
    return SIM_read_phys_memory(cpu, v2p(cpu, vaddr), WORD_SIZE)
    
def readWord(cpu, vaddr):
    return SIM_read_phys_memory(cpu, v2p(cpu, vaddr), WORD_SIZE)

def v2p(cpu, v):
    phys_block = cpu.iface.processor_info.logical_to_physical(v, Sim_Access_Read)
    return phys_block.address

print('reverse error reproduction')
er = errRepo()
er.go()

