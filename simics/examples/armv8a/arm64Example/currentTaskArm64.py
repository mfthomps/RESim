''' ARM64 current task example.  Finds the location of the "current" value in the kernel
    that points to the current task record.  From the kernel source code: 
        arch/arm64/include/asm/current.h
              static __always_inline struct task_struct *get_current(void)
              {
                  unsigned long sp_el0;
                  asm ("mrs %0, sp_el0" : "=r" (sp_el0));
                  return (struct task_struct *)sp_el0;
              }
    This tells us that within the kernel, after kernel entry housekeeping,
    the sp_el0 register will contain the address of the current task record.
    Our goal is to observe the kernel entry housekeeping in order to determine
    where in memory the kernel finds this value to load into sp_el0.

    This example is derived from "modeTest.py" from the simics/workspace diretory.

    The meat of this example has been implented within getKernelParams

'''
import os
import sys
resim_dir = os.getenv('RESIM_DIR')
core = os.path.join(resim_dir, 'simics', 'monitorCore')
sys.path.append(core)
import decodeArm as decode
import resimUtils

class CurrentTaskArm64():
    def __init__(self):
        ''' Get the cpu name as a variable for future reference '''
        cmd = 'fvp.get-processor-list'
        proclist = SIM_run_command(cmd)
        self.cpu = SIM_get_object(proclist[0])
        self.mode_hap = None
        ''' Set the mode hap to catch kernel entry'''
        self.watchMode()
        ''' a memory access hap example '''
        self.bp = None
        self.break_hap = None
        self.stop_hap = None
        self.log_dir = './logs'
        ''' Standard RESim logger. '''
        self.lgr = resimUtils.getLogger('currentTaskArm', self.log_dir)

    def getPC(self):
        ''' example of getting register values, in this case pc is the
            instruction pointer on 64-bit arm '''
        reg_num = self.cpu.iface.int_register.get_number('pc')
        reg_value = self.cpu.iface.int_register.read(reg_num)
        return reg_value

    def modeChanged(self, want_pid, one, old, new):
        ''' callback invoked when mode changes '''

        reg_value = self.getPC()
        print('in mode changed old %s new %s  pc is 0x%x' % (old, new, reg_value))
        if new == Sim_CPU_Mode_Supervisor:
            print('is supervisor')
            ''' Set the stop hap and stop so we can single step to find sp_el0 reference '''
            SIM_run_alone(self.setStopHap, None)
        else:
            print('is user')

    def watchMode(self):
        ''' set the mode hap.  Will call modeChanged on every change in cpu mode'''
        self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChanged, None)

    def rmHap(self):
        ''' remove the mode hap (otherwise reversing gets messy) '''
        SIM_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)


    def setBreak(self, addr):
        ''' set a breakpoint and a hap on the break'''
        if self.bp is None:
            self.bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, addr, 1, 0)
            self.break_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.breakHap, None, self.bp)
        else:
            print('break already set')

    def breakHap(self, user_param, conf_object, break_num, memory):
        print('hit break hap at 0x%x' % memory.logical_address)

    def rmBreak(self):
        if self.break_hap is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.break_hap)
            SIM_delete_breakpoint(self.bp)
            self.bp = None
            self.break_hap = None

    def setStopHap(self, dumb):
        ''' Set the stop hap and stop the simulation, causing stopHap to be called. '''
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap, None)
        SIM_break_simulation('from setStopHap')

    def stopHap(self, dumb, one, exception, error_string):
        ''' Invoked when the simulation stops following kernel entry.  We want to stop so that we can single step,
            which is not available while the simulation is running.'''
        if self.stop_hap is not None:
            self.lgr.debug('stopHap')
            ''' Remove the stop hap so it is not invoked again.  Since we are in a hap at the moment, we need to
                "run alone" because you cannot add/remove haps from within haps.''' 
            ''' this sequence is important to avoid race conditions.  Since the removal happens in a separate thread, we
                need to ensure the value of stop_hap is null so we we enter stopHap again, we just fall out.'''
            hap = self.stop_hap
            SIM_run_alone(self.rmStopHap, hap)
            self.stop_hap = None
            ''' Find the instructions that load sp_el0.  We cannot issue "continue" or "skip" from within a hap, so we
                must run alone.'''
            SIM_run_alone(self.checkTask, None)

    def rmStopHap(self, hap):
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", hap)

    def checkTask(self, dumb):
        ''' Find the memory from which the value loaded into sp_el0 is read. '''
        done = False
        SIM_run_command('enable-reverse-execution')
        ''' error handling to keep from forever loops '''
        bailat = 1000
        i = 0
        our_reg = None
        while not done:
            i = i + 1
            if i > bailat:
                print('never found sp_el0 ref')
                return 
            ''' step forward 1 instruction '''
            SIM_continue(1)
            pc = self.getPC()
            instruct = SIM_disassemble_address(self.cpu, pc, 1, 0)
            if instruct[1].startswith('msr sp_el0'):
                done = True
                print('got instruct at 0x%x' % pc)
                op2, op1 = decode.getOperands(instruct[1])
                print('operand 1 %s  2 %s' % (op1, op2))
                our_reg = op2
        ''' at this point we assume our_reg contains the name of the register from which sp_el0's value was moved, e.g.,
               msr sp_el0, X28   '''
        done = False
        bailat = 1000
        i = 0
        our_exp = None
        while not done:
            i = i + 1
            if i > bailat:
                print('never found sp_el0 ref')
                return 
            ''' skip backwards one instruction '''
            prev = self.cpu.cycles - 1
            resimUtils.skipToTest(self.cpu, prev, self.lgr)
            pc = self.getPC()
            instruct = SIM_disassemble_address(self.cpu, pc, 1, 0)
            if isinstance(instruct, tuple):
                print(instruct[1]) 
                op2, op1 = decode.getOperands(instruct[1])
                if op1 == our_reg:
                    print('got our reg in %s' % instruct[1])
                    done = True
                    our_expr = op2   
            else:
                self.lgr.debug('instruct not a tuple?  value %s' % str(instrut))
                  
        addr = decode.getAddressFromOperand(self.cpu, our_expr, self.lgr)
        print('Found location of current task pointer:  0x%x' % addr) 


''' Create the CurrentTaskArm64 object.  Name it at simics command prompt using @ct.
    E.g., @ct.rmHap() '''

ct = CurrentTaskArm64()
