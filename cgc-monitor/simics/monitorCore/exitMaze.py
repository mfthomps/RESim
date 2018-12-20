from simics import *

def getCPL(cpu):
    reg_num = cpu.iface.int_register.get_number("cs")
    cs = cpu.iface.int_register.read(reg_num)
    mask = 3
    return cs & mask

def getEIP(cpu):
    reg_num = cpu.iface.int_register.get_number('eip')
    reg_value = cpu.iface.int_register.read(reg_num)
    return reg_value

class ExitMaze():
    def __init__(self, top, cpu, cell, pid, syscall, context_manager, lgr):
        self.cpu = cpu
        self.cell = cell
        self.pid = pid
        self.lgr = lgr
        self.syscall = syscall
        self.context_manager = context_manager
        self.instructs = {}
        self.the_breaks = []
        self.breakout_hap = None
        self.top = top
        self.stop_hap = None

    def run(self):
        round_count = 0
        call_level = 0
        self.lgr.debug('exitMaze, Begin')
        cmd = 'si -q'
        timeofday_count_start = self.syscall.getTimeofdayCount()
        cpl = getCPL(self.cpu)
        for i in range(2000):
            eip = getEIP(self.cpu)
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            result = SIM_run_command(cmd)
            if getCPL(self.cpu) > 0:
                if cpl == 0:
                    ''' returned, check timeofday count'''
                    tod = self.syscall.getTimeofdayCount()
                    if (tod - timeofday_count_start) > 1:
                        self.lgr.debug('been around')
                        break
                    cpl = 3
                self.lgr.debug('exitMaze eip: 0x%x instruct: %s' % (eip, instruct[1]))
                parts = instruct[1].split()
                mn = parts[0]
                if mn == 'call':
                    call_level += 1
                    self.lgr.debug('call, level now %d' % call_level)
                elif mn == 'ret':
                    if call_level == 0:
                        self.lgr.debug('new higher level, flush instructions')
                        self.instructs.clear()
                    else:
                        call_level -= 1
                        self.lgr.debug('ret, level now %d' % call_level)
                elif call_level == 0:
                    self.instructs[eip] = instruct
                    self.lgr.debug('adding to list %x %s' % (eip, instruct[1]))
            else:
                cpl = 0


    def showInstructs(self):
        for eip in self.instructs:
            print('0x%x %s' % (eip, self.instructs[eip][1]))
               
    def plantBreaksXX(self):
        #bl = [0x807b30e, 0x807b2a1, 0x807b232, 0x807b2f6]
        bl = [0x807b2a1, 0x807b232, 0x807b2f6, 0x807b30e]
        for b in bl:
            proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, b, 1, 0)
            self.the_breaks.append(proc_break)
        self.breakout_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.breakoutHap, None, self.the_breaks[0], self.the_breaks[-1])
        self.lgr.debug('plantBreaks set hap %d' % self.breakout_hap)
        self.syscall.stopTrace()
        self.top.stopThreadTrack()
        self.top.removeDebugBreaks()


    def plantBreaks(self):
        did_eip = []
        for eip in self.instructs:
            if self.instructs[eip][1].strip().startswith('j'):
                self.lgr.debug('is jump')
                parts = self.instructs[eip][1].split()
                dest = None
                if len(parts) > 1:
                    op0 = parts[1]  
                    try:
                        dest = int(op0, 16)
                    except:
                        self.lgr.debug('plantBreaks could not get dest from %s from %s' % (op0, self.instructs[eip]))
                if dest is not None:
                    if dest not in self.instructs:
                        if dest not in did_eip:
                            self.lgr.debug('WOULD PLANT jump flag at 0x%x' % dest) 
                            proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, dest, 1, 0)
                            self.the_breaks.append(proc_break)
                            did_eip.append(dest)
                    else:
                        in_len = self.instructs[eip][0]
                        self.lgr.debug('len is %d' % in_len)
                        next_in = eip + in_len
                        if next_in not in self.instructs:
                            if next_in not in did_eip:
                                self.lgr.debug('WOULD PLANT next instruction flag at 0x%x' % next_in) 
                                proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, next_in, 1, 0)
                                self.the_breaks.append(proc_break)
                                did_eip.append(next_in)
        if len(self.the_breaks) > 0:
            self.breakout_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.breakoutHap, None, self.the_breaks[0], self.the_breaks[-1])
            self.lgr.debug('plantBreaks set hap %d' % self.breakout_hap)
        self.top.removeDebugBreaks()
        self.syscall.stopTrace()
        self.top.stopThreadTrack()
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, None)
        SIM_run_command('c')

    def stopHap(self, stop_action, one, exception, error_string):
        if self.stop_hap is not None:
            SIM_run_alone(self.top.restoreDebugBreaks, None)
            SIM_run_alone(self.syscall.doBreaks, None)
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)

    def breakoutHap(self, syscall_info, third, forth, memory):
        print('Broke out')
        self.context_manager.genDeleteHap(self.breakout_hap)
        SIM_break_simulation('broke out')
        
