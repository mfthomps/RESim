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
import decode
import decodeArm
import memUtils
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
def getEIP(cpu):
    reg_num = cpu.iface.int_register.get_number('eip')
    reg_value = cpu.iface.int_register.read(reg_num)
    return reg_value

class ExitMaze():
    def __init__(self, top, cpu, tid, syscall, context_manager, task_utils, mem_utils, debugging, one_proc, lgr):
        self.cpu = cpu
        self.tid = tid
        self.task_utils = task_utils
        self.lgr = lgr
        self.syscall = syscall
        self.context_manager = context_manager
        self.mem_utils = mem_utils
        self.one_proc = one_proc
        self.call_level = 0
        self.timeofday_count_start = 0
        ''' recorded instructions, not within functions '''
        self.instructs = OrderedDict()
        ''' look for changes in compare values '''
        self.compares = {}
        ''' addresses upon which we'll break  TBD how to know where we came from? '''
        self.break_addrs = []
        ''' unexplored destinations that only lead to where we've been '''
        self.bumps = []
        
        self.break_map = {}
        self.breakout_hap = None
        self.top = top
        self.stop_hap = None
        self.stop_hap_mode = None
        self.debugging = debugging
        self.live_cmp = []
        self.breakout_addr = None
        self.function_ret = None
        self.just_return = False
        self.compare_hap = None
        #self.stack_frames = []
        self.broke_out_count = 0
        self.planted_break_sets = 0
        if cpu.architecture == 'arm':
            self.decode = decodeArm
            self.lgr.debug('findKernelWrite using arm decoder')
        else:
            self.decode = decode

    def mazeReturn(self, was_running=False):
        if self.function_ret is None:
            print('no function return set.')
            self.lgr.error('exitMaze mazeReturn no function return has been set.  was_running %r' % was_running)
            if not was_running:
                self.lgr.error('exitMaze mazeReturn was not running, try to continue anyway (better than a dead stop)')
                SIM_continue(0)
            return
        self.just_return = True
        self.break_addrs = []
        self.break_addrs.append((self.function_ret, 0))
        self.lgr.debug('mazeReturn tid:%s , plant breaks' % self.tid)
        #self.removeDebugBreaks()
        if was_running:
            ''' was already running, do not unpause '''
            SIM_run_alone(self.plantBreaks, False)
        else:
            SIM_run_alone(self.plantBreaks, True)

    def checkJustReturn(self):
        if not self.just_return:
            return False
        st = self.top.getStackTraceQuiet()
        current_frames = st.getFrames(4)
        for i in range(len(self.stack_frames)):
            if current_frames[i].ip != self.stack_frames[i].ip:
                self.lgr.debug('exitMaze tid:%s checkStack not equal %d 0x%x 0x%x' % (self.tid, i, current_frames[i].ip, self.stack_frames[i].ip))
                return False
        else:
            return True

    def recordStack(self):
        st = self.top.getStackTraceQuiet()
        if st is None:
            self.lgr.error('exitMaze no stack frames')
            return
        count = st.countFrames()
        if count == 0:
            self.lgr.error('exitMaze no stack frames')
            return
        if count < 4:
            self.stack_frames = st.getFrames(count-1)
            self.lgr.debug('exitMaze, only %d stack frames' % count)
        else:
            self.stack_frames = st.getFrames(4)

    def retHap(self, count, third, forth, memory):
        if self.ret_hap is None:
            return
        cpu, comm, tid = self.task_utils.curThread() 
        if tid == self.tid:
            self.context_manager.genDeleteHap(self.ret_hap)
            self.ret_hap = None
            self.lgr.debug('exitMaze ret from call tid:%s count %d' % (self.tid, count))
            SIM_run_alone(self.addStopModeAlone, count)

    def traceCircuit(self, count):
        self.lgr.debug('traceCircuit tid:%s count %d' % (self.tid, count))
        max_loops = 2
        cmd = 'si -q'
        for i in range(count, 200000):
            eip = getEIP(self.cpu)
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            result = SIM_run_command(cmd)
            if memUtils.getCPL(self.cpu) > 0:
                ''' see if we are returning from kernel or call from outer scope''' 
                if i > 0 and i == count:
                    ''' returned, check timeofday count'''
                    tod = self.syscall.getTimeofdayCount(self.tid)
                    self.lgr.debug('exitMaze tid:%s tod is %d, start %d' % (self.tid, tod, self.timeofday_count_start))
                    ''' have we called tod enough to establish a circuit? '''
                    if (tod - self.timeofday_count_start) > max_loops:
                        self.lgr.debug('exitMaze tid:%s been around, collected instructions' % self.tid)
                        for instruct_eip in self.instructs: 
                            self.lgr.debug('\t0x%x  %s' % (instruct_eip, self.instructs[instruct_eip][1]))
                        if len(self.break_addrs) == 0:
                            ''' we've run the circuit, look at the collected instructions and 
                                select breakpoints based on branches not followed '''
                            ''' first make sure we are in outer scope and offer a break on return '''
                            #while True:
                            #    eip = getEIP(self.cpu)
                            #    if eip in self.instructs:
                            #        break
                            #    result = SIM_run_command(cmd)
                            ''' in outer scope, make note of return instruction based on EBP '''
                            reg_num = self.cpu.iface.int_register.get_number('ebp')
                            ebp = self.cpu.iface.int_register.read(reg_num)
                            self.function_ret = self.mem_utils.readPtr(self.cpu, ebp + self.mem_utils.WORD_SIZE)

                            self.cycle_len = self.cpu.cycles - self.cycle_start         
                            self.getBreaks()    
                            #self.removeDebugBreaks()
                            print('Would add these breaks:')
                            self.lgr.debug('exitMaze traceCircuit Would add these breaks:')
                            for dest, prev in self.break_addrs:
                                if prev != 0:
                                    self.lgr.debug('\tdest 0x%x prev 0x%x' % (dest, prev))
                                    print('dest 0x%x prev 0x%x' % (dest, prev))
                                else:
                                    print('function return: 0x%x' % dest)
                                    self.lgr.debug('\tfunction return: 0x%x' % dest)
                            if self.top.getAutoMaze():
                                SIM_run_alone(self.mazeReturn, None)
                            elif len(self.break_addrs) > 4:
                                self.lgr.debug('exitMaze traceCircuit more than 4 breaks Found %d breaks' % len(self.break_addrs))
                                print('more than 4 breakpoints.  \nUse @cgc.plantCmpBreaks() to prune and run')
                                print('Or use @cgc.doMazeReturn() to exit via a function return, and continue doing so')
                                print('when this maze is again encountered.')
                            else:
                                self.lgr.debug('exitMaze Found %d breaks' % len(self.break_addrs))
                                print('Use @cgc.plantBreaks() to set the above breaks to exit the maze')
                                print('Or use @cgc.doMazeReturn() to exit via a function return, and continue doing so')
                                print('when this maze is again encountered.')
                            return
                        else:
                            self.lgr.error('exitMaze confused')
                            return
                #self.lgr.debug('exitMaze eip: 0x%x instruct: %s' % (eip, instruct[1]))
                parts = instruct[1].split()
                mn = parts[0]
                if mn == 'call':
                    self.instructs[eip] = instruct
                    self.lgr.debug('exitMaze adding to list %x %s' % (eip, instruct[1]))
                    ret_addr = eip + instruct[0]
                    ret_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, ret_addr, 1, 0)
                    self.ret_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.retHap, i, ret_break, 'retMaze')
                    self.lgr.debug('exitMaze call from tid:%s eip 0x%x, %s set break/hap on return 0x%x now run' % (self.tid, eip, instruct[1], ret_addr))
                    SIM_run_command('c')
                    return
                elif mn == 'ret':
                    self.lgr.debug('new higher level from eip 0x%x, flush instructions' % eip)
                    self.instructs.clear()
                else:
                    if len(self.break_addrs) == 0 and eip not in self.instructs:
                        self.instructs[eip] = instruct
                        self.lgr.debug('exitMaze not call or ret adding to list %x %s' % (eip, instruct[1]))

            else:
                ''' in kernel run til out '''
                self.lgr.debug('exitMaze in kernel, add mode hap count %d' % i)
                self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChanged, i)
                SIM_run_command('c')
                return

    def stopHapMode(self, count, one, exception, error_string):
        if self.stop_hap_mode is None:
            return
        
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap_mode)
        self.stop_hap_mode = None
        SIM_run_alone(self.traceCircuit, count)

    def addStopModeAlone(self, count):
        self.stop_hap_mode = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHapMode, count)
        SIM_break_simulation('back in user space')         

    def modeChanged(self, count, one, old, new):
        if self.mode_hap is None:
            return
        if old == Sim_CPU_Mode_Supervisor:
            cpu, comm, tid = self.task_utils.curThread() 
            if tid == self.tid:
                SIM_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
                self.mode_hap = None
                self.lgr.debug('exitMaze modeChanged count %d' % count)
                SIM_run_alone(self.addStopModeAlone, count)

    def run(self):
        if self.debugging:
            self.lgr.debug('exitMaze Disabling reverse execution')
            SIM_run_command('disable-reverse-execution')
        #self.recordStack()
        self.call_level = 0
        self.syscall.resetTimeofdayCount(self.tid)
        self.timeofday_count_start = 0
        self.lgr.debug('exitMaze, Begin.  timeofday_count_start is %d' % self.timeofday_count_start)
        cpl = memUtils.getCPL(self.cpu)
        self.cycle_start = self.cpu.cycles
        self.cycle_len = 0
        self.traceCircuit(0)


    def showInstructs(self):
        for eip in self.instructs:
            print('0x%x %s' % (eip, self.instructs[eip][1]))

    def getMaze(self):
        retval = {}
        retval['instructions'] = []
        for eip in self.instructs:
            retval['instructions'].append(eip)
        retval['breaks'] = []
        for jmp_to_eip, cmp_eip in self.break_addrs:
            if cmp_eip != 0:
                retval['breaks'].append(jmp_to_eip)
        retval['bumps'] = self.bumps
        return retval
               

    def getBreaks(self):
        self.lgr.debug('exitMaze getBreaks tid:%s' % self.tid)
        if self.function_ret is not None:
            self.break_addrs.append((self.function_ret, 0))
            self.lgr.debug('exitMaze getBreaks tid:%s set function return break at 0x%x' % (self.tid, self.function_ret))
        did_eip = []
        ''' track the cmp TBD, other operators affecting , collected instructions '''
        prev = None
        exit_eips = self.top.getMazeExits()
        for x in exit_eips:
            print('exit eip 0x%x' % x)
        for eip in self.instructs:
            ins = self.instructs[eip][1]
            if self.decode.isJump(self.cpu, ins, ignore_flags=True) and prev is not None:
                self.lgr.debug('is jump: 0x%x %s' % (eip, ins))
                try:
                    parts = str(ins).split(' ', 1)
                except:
                    self.lgr.error('exitMaze getBreaks failed to parse %s' % ins)
                    continue
                dest = None
                if len(parts) > 1:
                    op0 = parts[1]  

                    dest = decode.addressFromExpression(self.cpu, op0, self.lgr)
                    if dest is None:
                        self.lgr.debug('getBreaks could not get dest from %s from %s' % (op0, self.instructs[eip]))
                        return
                if dest is not None:
                    if dest not in self.instructs:
                        if dest not in did_eip and dest not in exit_eips and not self.isBump(dest):
                            self.lgr.debug('WOULD PLANT tid:%s jump to 0x%x instruct %s  cmp was at 0x%x' % (self.tid, dest, self.instructs[eip][1], prev))
                            self.break_addrs.append((dest, prev))
                            #did_eip.append(dest)
                    else:
                        in_len = self.instructs[eip][0]
                        next_in = eip + in_len
                        self.lgr.debug('dest of jmp already in instructs, check next instruct at 0x%x' % next_in)
                        if next_in not in self.instructs:
                            if next_in not in did_eip and next_in not in exit_eips and not self.isBump(next_in):
                                self.lgr.debug('WOULD PLANT tid:%s  next instruction flag at 0x%x' % (self.tid, next_in)) 
                                self.break_addrs.append((next_in, prev))
                                #did_eip.append(next_in)
                            else:
                                self.lgr.debug('next instruct 0x%x not in instructs, but in did_eip or exit_eips or maybe bump' % next_in)
                else:
                    self.lgr.debug('dest of %s is None?' % ins)
            if ins.startswith('cmp') or ins.startswith('test'):
                self.lgr.debug('getBreaks conditional found 0x%x %s' % (eip, ins))
                prev = eip

    def isBump(self, dest):
        ''' iterate through instructions until jump or ret found and determine
            if we've already been to jmp destinations. '''
        retval = False
        done = False
        ip = dest
        self.lgr.debug('exitMaze isBump is 0x%x a bump?' % dest)
        count = 0
        while not done and not retval:
            instruct = SIM_disassemble_address(self.cpu, ip, 1, 0)
            if instruct[1].startswith('jmp'):
                op = instruct[1].split()[1]
                self.lgr.debug('exitMaze isBump ip 0x%x is jmp op is %s' % (ip, op))
                try:
                    next_dest = int(op, 16)
                except:
                    self.lgr.debug('isBump jump not explicit %s' % instruct[1])
                    return False
                self.lgr.debug('exitMaze isBump is 0x%x in instructs?' % next_dest)
                if next_dest in self.instructs:
                    retval = True
                    self.bumps.append(ip)
                    self.lgr.debug('exitMaze isBump 0x%x leads 0x%x which is nowhere new' % (next_dest, dest))
            elif instruct[1].startswith('j'):
                op = instruct[1].split()[1]
                self.lgr.debug('exitMaze isBump ip 0x%x is jxx op is %s' % (ip, op))
                try:
                    next_dest = int(op, 16)
                except:
                    self.lgr.debug('isBump jxx not explicit %s' % instruct[1])
                    return False
                next_ip = ip+in_len 
                if next_dest in self.instructs and next_ip in self.instructs:
                    retval = True
                    self.bumps.append(ip)
                    self.lgr.debug('exitMaze isBump both branches out of 0x%x lead to nowhere new' % (dest))
                else:
                    self.lgr.debug('exitMaze isBump either newdest 0x%x or nextip 0x%x not in instructs' % (next_dest, next_ip))
                
                done = True
            elif instruct[1]=='ret':
                done = True
            in_len = instruct[0]
            ip = ip + in_len
            count = count + 1
            if count > 1000:
                done = True
        return retval


    def pruneBreaks(self):
        ''' prune to 4 '''
        num_to_cut = len(self.break_addrs) - 4
        list_copy = list(self.break_addrs)
        print('to exit maze, will prune %d breakpoints' % num_to_cut)
        self.lgr.debug('exitMaze pruneBreaks to exit maze, will prune %d breakpoints' % num_to_cut)
        for item in list_copy:
            jmp_to_eip, cmp_eip = item
            if cmp_eip not in self.live_cmp and cmp_eip != 0:
                self.break_addrs.remove(item)
                self.lgr.debug('exitMaze pruneBreaks cut %x %x' % (jmp_to_eip, cmp_eip))
                print('pruneBreaks cut %x %x' % (jmp_to_eip, cmp_eip))
                num_to_cut = num_to_cut -1
                if num_to_cut == 0:
                    break
            else:
                print('retaining jmp_to 0x%x from cmp at 0x%x because it is moving' % (jmp_to_eip, cmp_eip))


    def removeDebugBreaks(self):
        self.lgr.debug('exitMaze removeDebugBreaks')
        self.top.removeDebugBreaks()
        self.syscall.stopTrace()
        self.top.stopThreadTrack()
        self.top.stopTrace()

    def plantCmpBreaks(self):
        first_break = None
        for jmp_to_eip, cmp_eip in self.break_addrs:
            if cmp_eip == 0:
                continue
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, cmp_eip, 1, 0)
            if first_break is None:
                first_break = proc_break
            last_break = proc_break
            self.lgr.debug('extiMaze plantCmp break 0x%x ' % (cmp_eip))
        if len(self.break_addrs) > 0:
            self.compare_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.compareHap, None, first_break, last_break, 'watchCompare')
            self.lgr.debug('extiMaze plantCmp set hap %d' % self.compare_hap)

    def compareHap(self, from_eip, third, breakpoint, memory):
            eip = getEIP(self.cpu)
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            parts = instruct[1].split()
            mn = parts[0]
            if mn == 'cmp':
                op1, op0 = decode.getOperands(instruct[1])
                self.lgr.debug('extiMaze compareHap operands 1:<%s> 0:<%s>' % (op1, op0))
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
                       self.lgr.debug('exitMaze CHANGED:  o0: 0x%x o1: 0x%x' % (old0, old1))
                       self.lgr.debug('exitMaze TO     :  v0: 0x%x v1: 0x%x' % (val0, val1))
                       current_len = self.cpu.cycles - self.cycle_start         
                       if current_len > self.cycle_len * 1000:
                           self.lgr.debug('did 1000 loops?')
                           self.live_cmp.append(eip)
                           self.lgr.debug('exitMaze cmpareHap remove compare hap')
                           self.context_manager.genDeleteHap(self.compare_hap)
                           SIM_run_alone(self.plantBreaks, False)
                self.compares[eip] = (val0, val1)

    def plantBreaks(self, then_run=True):
        self.lgr.debug('exitMaze plantBreaks tid:%s, len of break_addrs is %d' % (self.tid, len(self.break_addrs)))
        if len(self.break_addrs) > 4:
            self.pruneBreaks()
        first_break = None
        #self.context_manager.addNoWatch()
        self.context_manager.setTaskHap()
        self.context_manager.addSuspendWatch()
        for jmp_to_eip, cmp_eip in self.break_addrs:
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, jmp_to_eip, 1, 0)
            if first_break is None:
                first_break = proc_break
            last_break = proc_break
            self.break_map[proc_break] = cmp_eip
            self.lgr.debug('plantBreaks break_map set proc_break %d to 0x%x cmp_eip was 0x%x' % (proc_break, jmp_to_eip, cmp_eip))
        if len(self.break_addrs) > 0:
            self.breakout_hap = self.context_manager.genHapRange("Core_Breakpoint_Memop", self.breakoutHap, None, first_break, last_break, 'exitMaze')
            self.lgr.debug('plantBreaks set hap %d' % self.breakout_hap)
            self.lgr.debug('plantBreaks,  set stop hap')
        #SIM_run_command('list-breakpoints')
        #self.top.showHaps()
        #SIM_run_command('system-perfmeter')
        self.planted_break_sets = self.planted_break_sets+1
        if then_run:
            self.lgr.debug('exitMaze tid:%s Try to breakout, will continue' % self.tid)
            SIM_run_command('c')

    def rmAllBreaks(self):
        self.lgr.debug('exitMaze rmAllBreaks')
        if self.stop_hap is not None:
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
        if self.breakout_hap is not None:
            self.context_manager.genDeleteHap(self.breakout_hap) 
            self.breakout_hap = None
        if self.compare_hap is not None:
            self.context_manager.genDeleteHap(self.compare_hap)
            self.compare_hap = None
        if self.ret_hap is not None:
            self.context_manager.genDeleteHap(self.ret_hap)
            self.ret_hap = None

    def stopHap(self, stop_action, one, exception, error_string):
        if self.stop_hap is not None:
            cpu, comm, tid = self.task_utils.curThread() 
            if tid != self.tid:
                self.lgr.debug('exitMaze stopHap wrong tid, wanted %s got %s' % (self.tid, tid))
                return
            self.lgr.debug('exitMaze in stopHap tid:%s' % tid)
            #if self.one_proc:
            #    self.context_manager.watchTasks()
            #    self.syscall.doBreaks()
            #else:
            #    self.top.traceProcesses(new_log=False)
            self.lgr.debug('exitMaze stopHap remove the nowatch')
            self.context_manager.rmSuspendWatch()
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            if self.debugging:
                if self.debugging:
                    self.lgr.debug('exitMaze enabling reverse execution')
                    SIM_run_command('enable-reverse-execution')
                self.top.skipAndMail()
            else:        
                SIM_run_alone(SIM_run_command, 'c')
                print('out of stop hap')
            
    def getBreakout(self):
        return self.breakout_addr

    def addStopAlone(self, dumb):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap, None)
        SIM_break_simulation('broke out')

    def breakoutHap(self, from_eip, third, breakpoint, memory):
        ''' TBD can we manage breakpoints/haps with runAlone vice stopping execution? '''
        if self.breakout_hap is None:
            return
        cpu, comm, tid = self.task_utils.curThread() 
        bp = int(str(breakpoint))
        self.lgr.debug('exitMaze breakout tid:%s breakpoint %d  bp %d' % (self.tid, breakpoint, bp))
        #self.top.showHaps()
        break_handle = self.context_manager.getBreakHandle(bp)
        cmp_eip = self.break_map[break_handle]
        if self.tid == tid:
            eip = getEIP(self.cpu)
            if cmp_eip == 0:
                print('exitMaze breakoutHap hit return from function at 0x%x' % eip)
            else:
                print('exitMaze breakoutHap broke out to 0x%x, cmp was at 0x%x' % (eip, cmp_eip))
            self.broke_out_count = self.broke_out_count + 1
            self.context_manager.genDeleteHap(self.breakout_hap)
            self.breakout_hap = None
            self.lgr.debug('exitMaze breakoutHap, am out at 0x%x cmp was at 0x%x' % (eip, cmp_eip))
            ''' record for retrieval by top if this breakout seems nested '''
            self.breakout_addr = eip
            SIM_run_alone(self.addStopAlone, None)
        else:
            self.lgr.debug('exitMaze breakoutHap for wrong tid:%s, expeced %s' % (tid, self.tid))
       
    def getStatus(self):
        return self.tid, self.planted_break_sets, self.broke_out_count 
