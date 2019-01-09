from simics import *
import decode
from collections import OrderedDict
'''
Scheme to manage syscall tracing in cases where the application spins around waiting for
a time delay, e.g., read from network for 30 seconds -- which can generate millions of
system calls and effectively halt the analysis.

Limitations are evident in the hueristic description below.
The strategy assumes a single clock read per loop cycle.  We use the clock read to identify
when we've completed a cycle.  During the cycle, we track call/returns, saving only those
instructions that are not within called functions.  

Once a loops worth of instructions are recorded, we look at each conditional jump that goes to
an address.  If either of the two branches has not been followed (as reflected in our instruction
trace), we set a breakpoint on that branch.

We then disable all tracing and debug breakpoints  and run until we hit one of the new breakpoints.
Crude, yes, but sometimes you need to fight crude with crude.

NOTE: Tracing may miss data ingest, e.g., network traffic that arrives within the delay.  TBD,
extend to scheme catch actual arrival of data though a breakpoint in the kernel?

'''
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
    def __init__(self, top, cpu, cell, pid, syscall, context_manager, task_utils, mem_utils, debugging, lgr):
        self.cpu = cpu
        self.cell = cell
        self.pid = pid
        self.task_utils = task_utils
        self.lgr = lgr
        self.syscall = syscall
        self.context_manager = context_manager
        self.mem_utils = mem_utils
        ''' recorded instructions, not within functions '''
        self.instructs = OrderedDict()
        ''' look for changes in compare values '''
        self.compares = {}
        ''' addresses upon which we'll break  TBD how to know where we came from? '''
        self.break_addrs = []
        
        self.break_map = {}
        self.breakout_hap = None
        self.top = top
        self.stop_hap = None
        self.debugging = debugging
        self.live_cmp = []

    def run(self):
        if self.debugging:
            SIM_run_command('disable-reverse-execution')
        round_count = 0
        call_level = 0
        cmd = 'si -q'
        timeofday_count_start = self.syscall.getTimeofdayCount()
        self.lgr.debug('exitMaze, Begin.  timeofday_count_start is %d' % timeofday_count_start)
        cpl = getCPL(self.cpu)
        self.cycle_start = self.cpu.cycles
        self.cycle_len = 0
        max_loops = 2
        for i in range(200000):
            eip = getEIP(self.cpu)
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            result = SIM_run_command(cmd)
            if getCPL(self.cpu) > 0:
                if cpl == 0:
                    ''' returned, check timeofday count'''
                    tod = self.syscall.getTimeofdayCount()
                    if (tod - timeofday_count_start) > max_loops:
                        self.lgr.debug('been around')
                        if len(self.break_addrs) == 0:
                            ''' first time around '''
                            self.cycle_len = self.cpu.cycles - self.cycle_start         
                            self.getBreaks()    
                            self.removeDebugBreaks()
                            if len(self.break_addrs) > 4:
                                print('more than 4 breakpoints, looking for likely exit')
                                self.plantCmpBreaks()
                                return
                            else:
                                self.lgr.debug('ExitMaze Found %d breaks' % len(self.break_addrs))
                                return
                        else:
                            self.lgr.error('ExitMaze confused')
                            return
                    cpl = 3
                #self.lgr.debug('exitMaze eip: 0x%x instruct: %s' % (eip, instruct[1]))
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
                    if len(self.break_addrs) == 0:
                        self.instructs[eip] = instruct
                        self.lgr.debug('adding to list %x %s' % (eip, instruct[1]))
                    
            else:
                cpl = 0


    def showInstructs(self):
        for eip in self.instructs:
            print('0x%x %s' % (eip, self.instructs[eip][1]))
               

    def getBreaks(self):
        did_eip = []
        self.lgr.debug('ExitMaze getBreaks')
        ''' track the cmp TBD, other operators affecting jumps '''
        prev = None
        for eip in self.instructs:
            if self.instructs[eip][1].strip().startswith('j') and prev is not None:
                self.lgr.debug('is jump')
                parts = self.instructs[eip][1].split()
                dest = None
                if len(parts) > 1:
                    op0 = parts[1]  
                    try:
                        dest = int(op0, 16)
                    except:
                        self.lgr.debug('getBreaks could not get dest from %s from %s' % (op0, self.instructs[eip]))
                if dest is not None:
                    if dest not in self.instructs:
                        if dest not in did_eip:
                            self.lgr.debug('WOULD PLANT jump to 0x%x instruct %s  cmp was at 0x%x' % (dest, self.instructs[eip][1], prev))
                            self.break_addrs.append((dest, prev))
                            #did_eip.append(dest)
                    else:
                        in_len = self.instructs[eip][0]
                        self.lgr.debug('len is %d' % in_len)
                        next_in = eip + in_len
                        if next_in not in self.instructs:
                            if next_in not in did_eip:
                                self.lgr.debug('WOULD PLANT next instruction flag at 0x%x' % next_in) 
                                self.break_addrs.append((next_in, prev))
                                #did_eip.append(next_in)
            if self.instructs[eip][1].strip().startswith('cmp'):
                self.lgr.debug('getBreaks found cmp')
                prev = eip


    def pruneBreaks(self):
        ''' prune to 4 '''
        num_to_cut = len(self.break_addrs) - 4
        list_copy = list(self.break_addrs)
        print('to exit maze, will prune %d breakpoints' % num_to_cut)
        for item in list_copy:
            jmp_to_eip, cmp_eip = item
            if cmp_eip not in self.live_cmp:
                self.break_addrs.remove(item)
                self.lgr.debug('pruneBreaks cut %x %x' % (jmp_to_eip, cmp_eip))
                print('pruneBreaks cut %x %x' % (jmp_to_eip, cmp_eip))
                num_to_cut = num_to_cut -1
                if num_to_cut == 0:
                    break
            else:
                print('retaining jmp_to 0x%x from cmp at 0x%x because it is moving' % (jmp_to_eip, cmp_eip))


    def removeDebugBreaks(self):
        self.top.removeDebugBreaks()
        self.syscall.stopTrace()
        self.top.stopThreadTrack()

    def plantCmpBreaks(self):
        first_break = None
        for jmp_to_eip, cmp_eip in self.break_addrs:
            proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, cmp_eip, 1, 0)
            if first_break is None:
                first_break = proc_break
            last_break = proc_break
            self.lgr.debug('plantCmp break 0x%x ' % (cmp_eip))
        if len(self.break_addrs) > 0:
            self.compare_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.compareHap, None, first_break, last_break, 'watchCompare')
            self.lgr.debug('plantCmp set hap %d' % self.compare_hap)

    def compareHap(self, from_eip, third, breakpoint, memory):
            eip = getEIP(self.cpu)
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            parts = instruct[1].split()
            mn = parts[0]
            if mn == 'cmp':
                op1, op0 = decode.getOperands(instruct[1])
                self.lgr.debug('operands 1:<%s> 0:<%s>' % (op1, op0))
                if '[' in op1:
                    address = decode.getAddressFromOperand(self.cpu, op1, self.lgr)
                    #self.lgr.debug('[ in op1, got address 0x%x' % address)
                    val1 = self.mem_utils.readWord32(self.cpu, address)
                else:
                    val1 = decode.getValue(op1, self.cpu, self.lgr)

                if '[' in op0:
                    address = decode.getAddressFromOperand(self.cpu, op0, self.lgr)
                    #self.lgr.debug('[ in op0, got address 0x%x' % address)
                    val0 = self.mem_utils.readWord32(self.cpu, address)
                else:
                    val0 = decode.getValue(op0, self.cpu, self.lgr)
                #self.lgr.debug('0x%08x  cmp 0 is 0x%x, 1 0x%x' % (eip, val0, val1))
                if eip in self.compares:
                   old0, old1 = self.compares[eip]
                   if old1 != val1 or old0 != val0:
                       self.lgr.debug('CHANGED:  o0: 0x%x o1: 0x%x' % (old0, old1))
                       self.lgr.debug('TO     :  v0: 0x%x v1: 0x%x' % (val0, val1))
                       current_len = self.cpu.cycles - self.cycle_start         
                       if current_len > self.cycle_len * 1000:
                           self.lgr.debug('did 1000 loops?')
                           self.live_cmp.append(eip)
                           self.context_manager.genDeleteHap(self.compare_hap)
                           SIM_run_alone(self.plantBreaks, None)
                self.compares[eip] = (val0, val1)

    def plantBreaks(self, dumb=None):
        self.lgr.debug('ExitMaze plantBreaks, len of break_addrs is %d' % len(self.break_addrs))
        if len(self.break_addrs) > 4:
            self.pruneBreaks()
        first_break = None
        for jmp_to_eip, cmp_eip in self.break_addrs:
            proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, jmp_to_eip, 1, 0)
            if first_break is None:
                first_break = proc_break
            last_break = proc_break
            self.break_map[proc_break] = cmp_eip
            self.lgr.debug('plantBreaks break_map set %d to 0x%x jmp_to was 0x%x' % (proc_break, cmp_eip, jmp_to_eip))
        if len(self.break_addrs) > 0:
            self.breakout_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.breakoutHap, None, first_break, last_break, 'exitMaze')
            self.lgr.debug('plantBreaks set hap %d' % self.breakout_hap)
        self.lgr.debug('plantBreaks, remove other breaks')
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, None)
        SIM_run_command('list-breakpoints')
        self.top.showHaps()
        SIM_run_command('system-perfmeter')
        #SIM_run_command('c')

    def stopHap(self, stop_action, one, exception, error_string):
        if self.stop_hap is not None:
            self.lgr.debug('ExitMaze in stopHap')
            self.context_manager.watchTasks()
            self.syscall.doBreaks()
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            if self.debugging:
                if self.debugging:
                    SIM_run_command('enable-reverse-execution')
                self.top.skipAndMail()
            else:        
                SIM_run_alone(SIM_run_command, 'c')
            

    def breakoutHap(self, from_eip, third, breakpoint, memory):
        cpu, comm, pid = self.task_utils.curProc() 
        bp = int(str(breakpoint))
        self.lgr.debug('breakout breakpoint %d  bp %d' % (breakpoint, bp))
        self.top.showHaps()
        break_handle = self.context_manager.getBreakHandle(bp)
        cmp_eip = self.break_map[break_handle]
        if self.pid == pid:
            print('broke out, cmp was at 0x%x' % cmp_eip)
            self.context_manager.genDeleteHap(self.breakout_hap)
            self.lgr.debug('ExitMaze breakoutHap, am out cmp was at 0x%x' % cmp_eip)
            SIM_break_simulation('broke out')
        else:
            self.lgr.debug('ExitMaze breakoutHap for wrong pid %d' % pid)
        
