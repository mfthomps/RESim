from simics import *
import hapCleaner
import taskUtils
OPEN = 5
class SyscallInfo():
    def __init__(self, cpu, pid, callnum, calculated, trace):
        self.cpu = cpu
        self.pid = pid
        self.callnum = callnum
        self.calculated = calculated
        self.trace = trace

class Syscall():

    def __init__(self, top, cell, param, mem_utils, task_utils, context_manager, lgr, callnum=None, trace = False): 
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.context_manager = context_manager
        pid, dumb, cpu = context_manager.getDebugPid()
        self.cpu = cpu
        self.cell = cell
        self.pid = pid
        self.top = top
        self.param = param
        self.lgr = lgr
        self.stop_hap = None
        self.trace_fh = None
        break_list = []
        if trace:
            self.trace_fh = open('/tmp/syscall_trace.txt', 'w')
        ''' will stop within the kernel at the computed entry point '''
        entry = None
        if callnum is None:
            self.lgr.debug('runToSyscall no callnum, set break at 0x%x & 0x%x' % (param.sysenter, param.sys_entry))
            #proc_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, param.sysenter, 1, 0)
            #proc_break1 = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, param.sys_entry, 1, 0)
            proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, param.sysenter, 1, 0)
            proc_break1 = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, param.sys_entry, 1, 0)
            break_list.append(proc_break)
            break_list.append(proc_break1)
        else:
            entry = self.task_utils.getSyscallEntry(callnum)
            self.lgr.debug('runToSyscall callnum is %s entry 0x%x' % (callnum, entry))
            proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, entry, 1, 0)
            proc_break1 = proc_break
            break_list.append(proc_break)
        
        syscall_info = SyscallInfo(self.cpu, self.pid, callnum, entry, trace)
        #proc_hap = SIM_hap_add_callback_range("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break, proc_break1)
        proc_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.syscallHap, syscall_info, proc_break, proc_break1)
        if not trace:
            hap_clean = hapCleaner.HapCleaner(cpu)
            hap_clean.add("Core_Breakpoint_Memop", proc_hap)
            flist = [self.top.skipAndMail]
            stop_action = hapCleaner.StopAction(hap_clean, break_list, flist)
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, stop_action)
        if not trace:
            SIM_run_command('c')

    def frameFromStackSyscall(self):
        reg_num = self.cpu.iface.int_register.get_number(self.mem_utils.getESP())
        esp = self.cpu.iface.int_register.read(reg_num)
        regs_addr = esp + self.mem_utils.WORD_SIZE
        #self.lgr.debug('frameFromStackSyscall regs_addr is 0x%x  ' % (regs_addr))
        frame = self.task_utils.getFrame(regs_addr, self.cpu)
        return frame

    def parseOpen(self, frame):
        fname_addr = frame['ebx']
        flags = frame['ecx']
        mode = frame['edx']
        fname = self.mem_utils.readString(self.cpu, fname_addr, 256)
        ida_msg = 'Syscall: open flags: 0x%x  mode: 0x%x  filename: %s' % (flags, mode, fname)
        self.lgr.debug('parseOpen set ida message to %s' % ida_msg)
        if self.trace_fh is not None:
            self.trace_fh.write(ida_msg+'\n')
        else:
            self.context_manager.setIdaMessage(ida_msg)

    def syscallParse(self, frame):
        callnum = frame['eax']
        self.lgr.debug('syscallParse callnum got %d compare to %d' % (callnum, OPEN))
        if callnum == OPEN:        
            self.lgr.debug('will call parseOpen')
            self.parseOpen(frame)
        else:
            ida_msg = 'Syscall: %s' % taskUtils.stringFromFrame(frame)
            if self.trace_fh is not None:
                self.trace_fh.write(ida_msg+'\n')
            else:
                self.context_manager.setIdaMessage(ida_msg)


    def stopHap(self, stop_action, one, exception, error_string):
        self.lgr.debug('syscall stopHap cycle: 0x%x' % stop_action.hap_clean.cpu.cycles)
        for hc in stop_action.hap_clean.hlist:
            if hc.hap is not None:
                self.lgr.debug('will delete hap %s' % str(hc.hap))
                self.context_manager.genDeleteHap(hc.htype, hc.hap)
                hc.hap = None
        if self.stop_hap is not None:
            self.lgr.debug('will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            for bp in stop_action.breakpoints:
                self.context_manager.genDeleteBreakpoint(bp)
            ''' check functions in list '''
            if len(stop_action.flist) > 0:
                fun = stop_action.flist.pop(0)
                fun(stop_action.flist) 

    def syscallHap(self, syscall_info, third, forth, memory):
        cpu = SIM_current_processor()
        if syscall_info.cpu is not None and cpu != syscall_info.cpu:
            self.lgr.debug('syscallHap, wrong cpu %s %s' % (cpu.name, syscall_info.cpu.name))
            return
        cpu, comm, pid = self.task_utils.curProc() 
        break_eip = self.top.getEIP()
        stack_frame = None
        if break_eip == self.param.sysenter:
            ''' caller frame will be on stack '''
            stack_frame = self.frameFromStackSyscall()
        elif break_eip == self.param.sys_entry:
            stack_frame = self.task_utils.frameFromRegs(syscall_info.cpu)
        elif break_eip == syscall_info.calculated:
            stack_frame = self.task_utils.frameFromStackSyscall()
        else:
            self.lgr.error('syscallHap unexpected break_ip 0x%x' % break_eip)
            return

        eax = stack_frame['eax']
        #self.lgr.debug('syscallHap in proc %d (%s), eax: 0x%x  EIP: 0x%x' % (pid, comm, eax, break_eip))
        if syscall_info.pid is None or syscall_info.pid == pid: 
            frame_string = taskUtils.stringFromFrame(stack_frame)
            self.lgr.debug('syscallHap frame: %s' % frame_string)
            if syscall_info.callnum is not None:
                if eax == syscall_info.callnum:
                    self.lgr.debug('syscall 0x%d from %d (%s) at 0x%x cycles: 0x%x' % (eax, pid, comm, break_eip, cpu.cycles))
                    if self.trace_fh is None:
                        SIM_break_simulation('syscall frame was %s' % frame_string)
                    self.syscallParse(stack_frame)
            else:
                self.lgr.debug('syscall looking for any, got 0x%d from %d (%s) at 0x%x ' % (eax, pid, comm, break_eip))
                if self.trace_fh is None:
                    SIM_break_simulation('syscall')
                self.syscallParse(stack_frame)


