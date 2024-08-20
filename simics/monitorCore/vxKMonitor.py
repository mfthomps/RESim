'''
Experimental VxWorks DKM tracker.
'''
import os
import sys
from simics import *
import decodeArm as decode
import resimUtils
import memUtils
import taskUtils
import net
import vxKMemUtils
import vxNet

class VxKMonitor():
    def __init__(self, top, cpu, cell_name, mem_utils, task_utils, so_map, run_from_snap, comp_dict, lgr):
        
        self.lgr = lgr
        self.cpu = cpu
        self.top = top
        #cpu0_str="zynqmp.soc.rpu.cores[0]"
        #cpu1_str="zynqmp.soc.rpu.cores[1]"
        #self.cpu0 = SIM_get_object(cpu0_str)
        #self.cpu1 = SIM_get_object(cpu1_str)
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.so_map = so_map
        self.sym_hap = None
        self.cur_task_hap = None
        self.stop_hap = None

        self.local_sym = {}
        self.global_sym = task_utils.getGlobalSyms()
        self.global_sym_break = {}
        
        # values for myCMakeDKM.out
        #self.module_addr = 0x786bb5b8
        #self.module_size = 1094

        # values for pltdkm_custom.out
        #self.module_addr = 0x79666208
        #self.module_size = 855614
        self.module_bp = None
        self.module_hap = None
        self.trace_all = False

        # tbd tie this to some debug call
        self.debug_module = comp_dict['MODULE']
        self.task_list = []
        SIM_run_command('enable-reverse-execution')
        self.lgr.debug('set module break')
        self.setModuleBreak()

    def setModuleBreak(self, dumb=None):
        ''' set a break range to cover the module.  Intended to catch returns '''
        module_info = self.so_map.getModuleInfo(self.debug_module)
        self.module_bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, module_info.addr, module_info.size, 0)
        self.module_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.moduleHap, None, self.module_bp)
        self.lgr.debug('setModuleBreak set on 0x%x size 0x%x' % (module_info.addr, module_info.size))

    def moduleHap(self, user_param, conf_object, break_num, memory):
        # hit when module code entered, e.g., first time or return from vxworks call
        if self.module_hap is not None:
            addr = memory.logical_address
            r0 = self.mem_utils.getRegValue(self.cpu, 'r0')
            self.lgr.debug('moduleHap addr 0x%x r0: 0x%x ' % (addr, r0))
            hap = self.module_hap
            SIM_delete_breakpoint(self.module_bp)
            SIM_run_alone(self.rmHap, hap)
            self.module_hap = None
            pc = self.getPC(self.cpu)
            if len(self.global_sym_break) == 0:
                SIM_break_simulation('first entry, pc 0x%x' % pc)
                self.lgr.debug('moduleHap no global syms yet, set them')
                if self.trace_all:
                    SIM_run_alone(self.setGlobal, None)
            elif not self.trace_all:
                SIM_break_simulation('Return to application, pc 0x%x' % pc)
            else:
                #self.lgr.debug('moduleHap has global syms yet, enable them')
                SIM_run_alone(self.enableSyms, None)

    def rmHap(self, hap):
        if hap is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", hap)

    def symbolHap(self, user_param, conf_object, break_num, memory):
        # entered when a global symbol was hit.
        addr = memory.logical_address
        #ttbr = self.cpu.translation_table_base0
        #cpu = SIM_current_processor()
        reg_num = self.cpu.iface.int_register.get_number('sp')
        sp_value = self.cpu.iface.int_register.read(reg_num)
        cur_task = self.task_utils.getCurrentTask()
        if addr in self.local_sym:
            #print('hit local sym %s at 0x%x' % (self.local_sym[addr], addr))
            self.lgr.debug('hit local sym %s at 0x%x sp_value: 0x%x cur_task: 0x%x cpu: %s' % (self.local_sym[addr], addr, sp_value, cur_task, self.cpu.name))
        elif addr in self.global_sym:
            #print('hit global sym %s at 0x%x' % (self.global_sym[addr], addr))
            # Hack to use stack value to distinguish our thread from other threads
            #if sp_value > 0x78e00000 and sp_value < 0x78f00000:
            if sp_value > 0x79000000:
                self.lgr.debug('hit global sym %s at 0x%x sp_value: 0x%x cur_task: 0x%x self.cpu: %s cycles: 0x%x' % (self.global_sym[addr], addr, sp_value, cur_task, self.cpu.name, self.cpu.cycles))
                SIM_run_alone(self.disableSyms, None)
                SIM_run_alone(self.setModuleBreak, None)
                self.getCallParams(self.global_sym[addr])
                if self.global_sym[addr] == 'write':
                    SIM_break_simulation('write')
                if self.global_sym[addr] == 'bind':
                    SIM_break_simulation('bind')
                if not self.trace_all:
                    SIM_break_simulation('global')
            else:
                self.lgr.debug('hit global sym %s at 0x%x sp_value: 0x%x cur_task: 0x%x cpu: %s WRONG STACK?' % (self.global_sym[addr], addr, sp_value, cur_task, self.cpu.name))
                pass
            #if addr == self.fwprintf:
            #    SIM_break_simulation('fwprintf %s' % cpu.name)
        else:
            print('hit other at 0x%x' % (addr))
            self.lgr.debug('hit other at 0x%x conf: %s' % (addr, str(conf_object)))
            SIM_run_alone(self.setGlobal, None)
            SIM_break_simulation('other %s' % self.cpu.name)
        #SIM_break_simulation('hit break')

    def setLocal(self):
        for addr in self.local_sym:
            self.setBreak0(addr)

    def setGlobal(self, dumb=None):
        bp_start = None
        bp = None
        for addr in self.global_sym:
            bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
            if bp_start is None:
                bp_start = bp
            self.global_sym_break[addr] = bp
        self.sym_hap = SIM_hap_add_callback_range("Core_Breakpoint_Memop", self.symbolHap, None, bp_start, bp)

    def disableSyms(self, dumb=None):
        for addr in self.global_sym_break:
            bp = self.global_sym_break[addr]
            SIM_disable_breakpoint(bp)
        #self.lgr.debug('disableSysms done')

    def enableSyms(self, dumb=None):
        for addr in self.global_sym_break:
            bp = self.global_sym_break[addr]
            SIM_enable_breakpoint(bp)
        #self.lgr.debug('enableSyms done')
        
    def dbg(self):
        cmd = 'new-gdb-remote cpu=%s architecture=arm port=9123' % (self.cpu.name)
        SIM_run_command(cmd)

    def getPC(self, cpu):
        reg_num = cpu.iface.int_register.get_number('pc')
        reg_value = cpu.iface.int_register.read(reg_num)
        return reg_value

    def rmAll(self):
        self.disableSyms()
        if self.module_hap is not None:
            hap = self.module_hap
            SIM_delete_breakpoint(self.module_bp)
            self.rmHap(hap)
            self.module_hap = None
        if self.sym_hap is not None:
            hap = self.sym_hap
            self.rmHap(hap)
            self.sym_hap = None
        self.trace_all = False

    def runTo(self, fun):
        got_fun = None
        for addr in self.global_sym:
            if self.global_sym[addr] == fun:
                got_fun = addr
                break
        if got_fun is not None:
            bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, got_fun, 1, 0)
            self.global_sym_break[got_fun] = bp
            self.sym_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.symbolHap, None, bp)
            self.lgr.debug('runTo set hap for fun %s at addr 0x%x' % (fun, got_fun))
        else:
            self.lgr.error('runTo failed to find %s in global symbols' % fun)
 
    def so(self):
        pc = self.getPC(self.cpu)
        next_instruct = pc + 4
        bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, next_instruct, 1, 0)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap, bp)
        SIM_continue(0)

    def stopHap(self, bp, one, exception, error_string):
        if self.stop_hap is not None: 
            self.lgr.debug('stopHap bp %d' % bp)
            SIM_delete_breakpoint(bp)                        
            hap = self.stop_hap
            SIM_run_alone(self.rmStopHap, hap)
            self.stop_hap = None
            print('stopped')

    def rmStopHap(self, hap):
        if hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", hap)

    def disassemble(self, count=1):
        pc = self.getPC(self.cpu)
        for i in range(count):
            instruct = SIM_disassemble_address(self.cpu, pc, 1, 0)
            self.lgr.debug('disassemble pc 0x%x instruct %s' % (pc, instruct[1]))
            if instruct[1].startswith('bl'):
                parts = instruct[1].split()
                dest = None
                if len(parts) == 2:
                    try:
                        dest = int(parts[1], 16)
                    except:
                        pass
                if dest is not None:
                    self.lgr.debug('disassemble dest is 0x%x' % dest)
                    if dest in self.global_sym:
                        print('bl %s' % self.global_sym[dest])
                    else:
                        dest = None
                if dest is None:
                    print(instruct[1])
            else:
                print(instruct[1])
            pc = pc + 4

    def traceAll(self, record_fd=None):
        self.lgr.debug('traceAll')
        self.trace_all = True
        if self.inModule(self.debug_module):
            self.lgr.debug('traceAll in app, set globals')
            self.setGlobal()
        else:
            self.lgr.debug('traceAll not in app, set module break')
            self.setModuleBreak()

    def ida(self):
        pc = self.getPC(self.cpu)
        ida = pc - self.module_addr
        print('Orig address: 0x%x' % ida)

    def getCallParams(self, fun):
        frame = self.task_utils.frameFromRegs()
        if fun == 'socket':
            domain = frame['param1']
            sock_type = frame['param2']
            protocol = frame['param3']
            domain_name = net.domaintype[domain]
            type_name = net.socktype[sock_type] 
            self.lgr.debug('getCallParams %s domain: %s  type: %s' % (fun, domain_name, type_name))
        if fun == 'ioctl':
            fd = frame['param1']
            cmd = frame['param2']
            arg = frame['param3']
            arg_val = SIM_read_phys_memory(self.cpu, arg, 4)
            FIONBIO = 0x90040010
            if cmd == FIONBIO:
                self.lgr.debug('getCallParams %s fd: 0x%x FIONBIO (set blocking) arg 0x%x arg_val 0x%x' % (fun, fd, arg, arg_val))
            elif cmd == 0x10:
                FIONBIO = 0x90040010
                self.mem_utils.setRegValue(self.cpu, 'r1', FIONBIO)
                self.lgr.debug('getCallParams %s fd: 0x%x FORCED set of FIONBIO (set blocking) arg 0x%x arg_val 0x%x' % (fun, fd, arg, arg_val))
            else:
                self.lgr.debug('getCallParams %s fd: 0x%x cmd: 0x%x arg: 0x%x' % (fun, fd, cmd, arg))
        elif fun == 'bind':
            ss = vxNet.SockStruct(self.cpu, frame['param2'], self.mem_utils, fd=frame['param1'], length=frame['param3'], lgr=self.lgr)
            self.lgr.debug('getCallParams %s %s' % (fun, ss.getString()))
             
        else:
            frame_string = taskUtils.stringFromFrame(frame)
            self.lgr.debug('getCallParams %s %s' % (fun, frame_string))

    def toModule(self):
        if self.so_map.inModule(self.debug_module):
            print('Already in module %s' % self.debug_module)
        else:
            self.setModuleBreak()
            SIM_continue(0)

#track = Track()

