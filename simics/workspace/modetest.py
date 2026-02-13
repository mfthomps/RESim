''' Execution mode testing '''
class ModeTest():
    def __init__(self):
        ''' Get the cpu name as a variable for future reference '''
        cmd = 'board0.get-processor-list'
        proclist = SIM_run_command(cmd)
        self.cpu = SIM_get_object(proclist[0])
        self.mode_hap = None
        ''' Set the mode hap '''
        self.watchMode()
        ''' a memory access hap example '''
        self.bp = None
        self.break_hap = None

    def modeChanged(self, want_pid, one, old, new):
        ''' callback hit when mode changes '''

        ''' example of getting register values, in this case rip is the
            instruction pointer on 64-bit x86 '''
        reg_num = self.cpu.iface.int_register.get_number('rip')
        reg_value = self.cpu.iface.int_register.read(reg_num)
        print('in mode changed old %s new %s  rip is 0x%x' % (old, new, reg_value))
        if new == Sim_CPU_Mode_Supervisor:
            print('is supervisor')
        else:
            print('is user')
        SIM_break_simulation('breakit')

    def watchMode(self):
        ''' set the mode hap'''
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


''' Create the ModeTest object.  Name it at simics command prompt using @mt.
    E.g., @mt.rmHap() '''

mt = ModeTest()
