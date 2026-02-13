''' Execution mode testing '''
import cli
import os
import sys
import json
import pickle
from simics import *
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'monitorCore'))
import resimUtils
import memUtils
import decode
class WinxpParams():
    def __init__(self, param, target):
        ''' Get the cpu name as a variable for future reference '''
        self.lgr = resimUtils.getLogger('WinxpParams', '/tmp/WinxpParams.log')
        self.kernel_start = 0x80000000
        cmd = 'board.get-processor-list'
        proclist = SIM_run_command(cmd)
        self.cpu = SIM_get_object(proclist[0])
        self.target = target
        self.mode_hap = None
        ''' a memory access hap example '''
        self.bp = None
        self.break_hap = None
        self.call_list = []
        resim_dir = os.getenv('RESIM_DIR')
        print('resim_dir is %s' % resim_dir)
        map_file = os.path.join(resim_dir,'windows', 'winxp.json')
        self.call_map = None
        with open(map_file) as fh:
            self.call_map = json.load(fh)
        ''' Set the mode hap '''
        self.pending_stop_hap = None
        self.stop_hap = None
        self.call_entry_addr = None
        self.call_exit_addr = None
        self.fault_addr = None
        self.bp = None
        self.break_hap = None
        #self.ptr_to_current_thread = 0xffdff01c
        self.ptr_to_current_thread = None
        self.current_thread_ptr_offset =  None
        self.cur_thread_addr = None
        self.enter_bp = None
        self.enter_hap = None
        self.did_threads = []
        self.did_procs = []
        self.prec_offset = None
        self.comm_offset = None
        self.pid_map = {}
        self.pid_attempts = 0
        self.bad_pid_offsets = []
        self.testing_prec_offset = None
        self.bad_prec_offsets = []
        self.next_prec = None
        self.prev_prec = None
        # offset of pid within EPROCESS
        self.pid_offset = None
        # offset of tid within ETHREAD
        self.tid_offset = None
        self.param = param
        self.thread_next = None
        self.thread_prev = None
        self.count_offset = None
        self.watchMode()


    def RES_delete_stop_hap(self, hap, your_stop=False):
        self.lgr.debug('RES_delete_stop_hap hap %s your_stop %r' % (str(hap), your_stop))
        self.pending_stop_hap = None
        if hap is None and your_stop:
            self.lgr.debug('RES_delete_stop_hap haps was none, set to our stop_hap %s' % str(self.stop_hap))
            hap = self.stop_hap
        if hap is not None:
            SIM_hap_delete_callback_id('Core_Simulation_Stopped', hap)
            if your_stop:
                self.stop_hap = None


    def RES_add_stop_callback(self, callback, param, your_stop=False):
        retval = None
        if self.pending_stop_hap is not None:
            self.lgr.error('RES_add_stop_callback called for %s, but already pending stop with callback %s!' % (str(callback), str(self.pending_stop_hap)))
            self.quit()
        else:
            retval = SIM_hap_add_callback('Core_Simulation_Stopped', callback, param)
            self.pending_stop_hap = callback
            self.lgr.debug('RES_add_stop_callback for %s your_stop %r' % (str(callback), your_stop))
            if your_stop:
                self.stop_hap = retval
                self.lgr.debug('RES_add_stop_callback your stop set hap to %s' % str(retval))
        return retval

    def getRegValue(self, reg):
        reg_num = self.cpu.iface.int_register.get_number(reg)
        value = self.cpu.iface.int_register.read(reg_num)
        return value 

    def modeChanged(self, want_pid, one, old, new):
        ''' callback hit when mode changes '''
        if self.mode_hap is None:
            return
        eax = self.getRegValue('eax')
        if new == Sim_CPU_Mode_Supervisor:
            if eax not in self.call_list:
                self.call_list.append(eax)
                eax_str = str(eax)
                if eax_str in self.call_map:
                    call_name = self.call_map[eax_str]
                else:
                    call_name = 'unknown'
                #print('in mode changed old %s new %s  eax is %d (0x%x) call_name: %s' % (old, new, eax, eax, call_name))
                #if call_name == 'NtReadFile':
                if self.call_entry_addr is not None and self.fault_addr is not None and self.call_exit_addr is not None:
                    SIM_run_alone(self.stopAndCall, self.findCurrent) 
                else:
                    if self.call_entry_addr is None or self.fault_addr is None:
                        SIM_run_alone(self.stopAndCall, self.inKernelEntry) 
                #SIM_break_simulation('breakit')
                #print('is read file')
                #SIM_break_simulation('breakit')
        else:
            if self.call_exit_addr is None:
                print('is user')
                eip = self.getRegValue('eip')
                self.call_exit_addr = eip
                print('modeChanged recorded exit address as 0x%x' % eip)

    def inKernelEntry(self, dumb=None):
        #print('inKernelEntry')
        enter_eip = self.getRegValue('eip')
        cli.quiet_run_command('rev 1')
        eip = self.getRegValue('eip')
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        if instruct[1] == 'sysenter':
            if self.call_entry_addr is None:
                self.call_entry_addr = enter_eip
                print('call entry addr 0x%x' % enter_eip)
            elif self.call_entry_addr != enter_eip:
                print('call entry addr 0x%x DOES NOT MATCH previous 0x%x' % (enter_eip, self.call_entry_addr))
        else:
            print('not a syscall assume page fault enter addr 0x%x' % enter_eip)
            self.fault_addr = enter_eip
        SIM_continue(0)

    def findCurrent(self, dumb=None):
        print('findCurrent, now begin to find the current task pointer')
        self.rmModeHap()
        self.setEnterBreak()

    def watchMode(self):
        ''' set the mode hap'''
        SIM_run_command('enable-reverse-execution')
        self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.modeChanged, None)

    def rmModeHap(self):
        ''' remove the mode hap (otherwise reversing gets messy) '''
        SIM_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)
        self.mode_hap = None

    def setEnterBreak(self, dumb=None):
        print('setEnterBreak on previously found syscall entry')
        self.enter_bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Execute, self.call_entry_addr, 1, 0)
        self.enter_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.enterHap, None, self.enter_bp)
        SIM_continue(0)

    def rmBreak(self):
        if self.break_hap is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.break_hap)
            SIM_delete_breakpoint(self.bp)
            self.bp = None
            self.break_hap = None

    def rmEnterBreak(self):
        if self.enter_hap is not None:
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.enter_hap)
            SIM_delete_breakpoint(self.enter_bp)
            self.enter_bp = None
            self.enter_hap = None

    def quitAlone(self, dumb):
        sys.stderr.write('user requested quit')
        self.lgr.debug('quitAlone')
        SIM_run_command('q')

    def quit(self, cycles=None):
        SIM_run_alone(self.quitAlone, cycles)

    def stopAndCall(self, callback):
        self.lgr.debug('stopAndCall')
        self.stop_hap = self.RES_add_stop_callback(self.stopAndCallHap, callback)
        SIM_break_simulation('stopping simulation...')

    def stopAndCallHap(self, callback, one, exception, error_string):
        if self.stop_hap is not None:
            self.lgr.debug('stopAndCallHap callback is %s' % str(callback))
            hap = self.stop_hap
            self.RES_delete_stop_hap_run_alone(hap)
            self.stop_hap = None
            SIM_run_alone(callback, None)

    def RES_delete_stop_hap_run_alone(self, hap, your_stop=False):
        # race condition of 2 stop haps existing?
        self.pending_stop_hap = None
        self.lgr.debug('RES_delete_stop_hap_run_alone hap: %s your_stop: %r' % (str(hap), your_stop))
        if hap is None and your_stop:
            hap = self.stop_hap
            self.lgr.debug('RES_delete_stop_hap_run_alone hap was none and your_stop, set hap to %s' % str(hap))
        SIM_run_alone(self.RES_delete_stop_hap, hap)
        if your_stop:
            self.stop_hap = None

    def testCurrent(self):
        cli.quiet_run_command('si')
        print('testCurent ptr_to_current_thread 0x%x' % (self.ptr_to_current_thread))
        self.cur_thread_addr = self.readWord(self.ptr_to_current_thread)
        print('testCurent cur_thread_addr is 0x%x' % (self.cur_thread_addr)) 
        self.bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Write, self.cur_thread_addr, 1, 0)
        self.break_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.breakHap, None, self.bp)
        print('added break at cur_thread_addr 0x%x' % self.cur_thread_addr)
        #SIM_continue(0)

    def enterHap(self, user_param, conf_object, break_num, memory):
        if self.enter_hap is None:
            return
        #print('enterHap at 0x%x' % memory.logical_address)
        if self.ptr_to_current_thread is None:
            SIM_run_alone(self.stopAndCall, self.findCurrentLoad)
        elif self.pid_offset is None:
            something = self.readWord(self.ptr_to_current_thread)
            the_offset = self.current_thread_ptr_offset 
            cur_thread = something + the_offset
            #print('proc_addr 0x%x' % proc_addr)
            self.cur_thread_addr = self.readWord(cur_thread)
            if self.cur_thread_addr not in self.did_threads:
                self.did_threads.append(self.cur_thread_addr)
                #print('cur_thread_addr 0x%x from cur_thread 0x%x' % (self.cur_thread_addr, cur_thread))
                SIM_run_alone(self.stopAndCall, self.atSyscallEnter)
        elif self.thread_next is None:
            SIM_run_alone(self.stopAndCall, self.findThreadOffsets)
        else:
            SIM_run_alone(self.stopAndCall, self.findCompute)

    def getCurThread(self):
        something = self.readWord(self.ptr_to_current_thread)
        the_offset = self.current_thread_ptr_offset 
        cur_thread = something + the_offset
        cur_thread_addr = self.readWord(cur_thread)
        return cur_thread_addr

    def findThreadOffsets(self, dumb=None):
        ''' find thread_next and thread_prev in the ETHREAD records.  we know the proc offset 
            in each record, so we see if the guess leads to a thread record having a resonable proc offset.
        '''
        cur_thread = self.getCurThread()
        guess_next = 0x1f0
        for i in range(0xa0):
            next_thread = cur_thread
            guess_prev = guess_next - 4
            prev_thread = 0
            comm_count = 0
            for j in range(30):
                maybe_next = next_thread + guess_next
                next_head = self.readWord(maybe_next)
                if next_head is not None:
                    next_thread = next_head - guess_prev
                    #print('guess_next: 0x%x next_thread 0x%x prev_thread: 0x%x' % (guess_next, next_thread, prev_thread))
                    if prev_thread is not None and next_thread == prev_thread:
                        break
                    cur_proc_addr = next_thread + self.prec_offset
                    prec = self.readWord(cur_proc_addr)
                    if prec is not None:
                        comm = self.getComm(prec)
                        if comm == 'System' or comm.endswith('exe'):
                            #print('\tguess_next of 0x%x for thread: 0x%x comm %s' % (guess_next, next_thread, comm)) 
                            comm_count += 1
                    prev_thread = next_thread
                else:
                    break
            if comm_count > 20:
                print('findThreadOffsets we think the offset is 0x%x' % guess_next)        
                self.thread_next = guess_next
                self.thread_prev = guess_next - 4
                #break
            guess_next = guess_next + 4
            
        # We have the next/prev, find the threadID
        self.findThreadID()
        self.findThreadOffsetInPrec()
        self.findThreadCount()

    def isclose(self, head, thread_list, guess):
        for t in thread_list:
              if head >= t and head < (t+0x300): 
                  delta = head - t
                  print('head 0x%x close to thhead 0x%x guess was 0x%x delta 0x%x thread_prev 0x%x' % (head, t, guess, delta, self.thread_prev))

    def getThreadPrec(self, thread):
        pa = thread + self.prec_offset
        retval = self.readWord(pa)
        return retval 

    def findThreadOffsetInPrec(self):
        ''' find the offset into the prec that points to the thread list header
        '''
        cur_thread = self.getCurThread()
        cur_proc_addr = cur_thread + self.prec_offset
        cur_proc = self.readWord(cur_proc_addr)
        # get list of threads for this prec so we can see if any offsets point to them
        thread_list = self.getThreadList()
        for t in thread_list:
            pa = t + self.prec_offset
            cp = self.readWord(pa)
            print('proc of thread 0x%x is 0x%x' % (t, cp))
        
        pid = self.getPID(cur_proc)
        comm = self.getComm(cur_proc)
        print('findThreadOffsetInPrec got %d threads in thread_list for proc rec 0x%x pid:%d (%s)' % (len(thread_list), cur_proc, pid, comm))
        thread_guess = 0xc0
        for i in range(400):
            thread_addr = cur_proc+ thread_guess
            thread_head = self.readWord(thread_addr)
            if thread_head is not None:
                thread = thread_head - self.thread_prev
                if thread in thread_list:
                    print('findThreadOffsetInPrec offset 0x%x is thread 0x%x, which is in list' % (thread_guess, thread))
                    self.thread_offset_in_prec = thread_guess
                    break
            thread_guess = thread_guess + 4

    def findThreadCount(self):
        ''' find the offset into the prec that provides the thread count
        '''
        cur_thread = self.getCurThread()
        cur_proc_addr = cur_thread + self.prec_offset
        cur_proc = self.readWord(cur_proc_addr)
        # get list of threads for this prec so we can see if any offsets point to them
        thread_list = self.getThreadList()
        thread_count = len(thread_list) 
        count_guess = 0xc0
        for i in range(400):
            count_addr = cur_proc + count_guess
            count = self.readWord(count_addr)
            if count == thread_count:
                print('findThreadCount found match of count %d at offset 0x%x' % (thread_count, count_guess))
                self.count_offset = count_guess
                break
            count_guess = count_guess + 4
   
    def findThreadID(self): 
        ''' find the thread ID.  we know the pid of the current process.  brute force until we see a 
            client id struct that contains the pid.
        '''
        print('threadId')
        cur_thread = self.getCurThread()
        cur_proc_addr = cur_thread + self.prec_offset
        prec = self.readWord(cur_proc_addr)
        pid_ptr = prec + self.pid_offset
        pid = self.readWord(pid_ptr)
        client_guess = 0xc0
        got_it = False
        for i in range(100):
            client_ptr = cur_thread + client_guess
            pid_maybe = self.readWord(client_ptr)
            if pid_maybe is not None:
                if pid_maybe == pid:
                    print('findThreadID, thread 0x%x offset 0x%x matches pid %d' % (cur_thread, client_guess, pid))
                    got_it = True
                    break
            client_guess = client_guess + 4
        if got_it:
            #self.testClientID(client_guess)
            self.tid_offset = client_guess + 4
           
    def testClientID(self, client_offset): 
        cur_thread = self.getCurThread()
        next_thread = cur_thread
        did_threads = []
        for j in range(80):
            if next_thread in did_threads:
                print('thread 0x%x already in did_thread' % next_thread)
                break
            did_threads.append(next_thread) 
            cur_proc_addr = next_thread + self.prec_offset
            prec = self.readWord(cur_proc_addr)
            pid_ptr = prec + self.pid_offset
            proc_pid = self.readWord(pid_ptr)
            thread_pid_ptr = next_thread + client_offset
            thread_pid = self.readWord(thread_pid_ptr)
            thread_tid = self.readWord(thread_pid_ptr+4)
            print('testClientID thread: 0x%x thread_pid %d thread_tid: %d  proc_pid %d' % (next_thread, thread_pid, thread_tid, proc_pid))
            next_ptr = next_thread + self.thread_next
            next_head = self.readWord(next_ptr)
            if next_head is not None:
                next_thread = next_head - self.thread_prev
            else:
                print('failed to get next_thread from next_ptr 0x%x' % next_ptr)

    def findCompute(self, dumb=None):
        '''
        We do not record any compute parameters.  Code from testCompute must be moved to winTaskUtils
        '''
        print('findCompute')
        orig_eax = self.getRegValue('eax')
        self.testCompute(orig_eax)
        for i in range(100):
            cli.quiet_run_command('si')
            eip = self.getRegValue('eip')
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            #print('instruct is %s' % instruct[1])
            if "eax*4" in instruct[1]:
                print('got eax*4')
                base = self.getRegValue('edi')
                self.testCompute(orig_eax)
                break
            prev_instruct = instruct[1]
        self.rmEnterBreak()
        self.rmBreak()
        self.saveParam()
   
    def testCompute(self, orig_eax): 
        call_num = orig_eax
        print('testCompute call_num 0x%x' % call_num)
        esi_value = self.cur_thread_addr
        esi_adjusted = esi_value + 0xe0
        print('testCompute esi_adjusted 0x%x' % esi_adjusted)
        edi_adjust = self.readWord(esi_adjusted)
        print('testCompute edi_adjust 0x%x' % edi_adjust)
        print('call_num 0x%x' % call_num)
        shifted = call_num >> 8 
        print('shifted 0x%x' % shifted)
        anded = shifted & 0x30
        print('anded 0x%x' % anded)
        edi_start = ((call_num >> 8) & 0x30) 
        print('testCompute edi_start 0x%x' % edi_start)
        edi = edi_start + edi_adjust
        print('testCompute edi now 0x%x' % edi)
        val_in_edi = self.readWord(edi)
        print('testCompute val_in_edi 0x%x' % val_in_edi)
        eax_now = call_num & 0xfff
        call_to_addr = val_in_edi + 4*eax_now
        call_to = self.readWord(call_to_addr)
        print('testCompute call_to 0x%x' % call_to)

    def findCurrentLoad(self, dumb=None):
        print('findCurrentLoad, step until we see what looks like a loading of the current task pointer')
        hard_count = 0
        our_reg = None
        hardcode = None
        for i in range(100):
            cli.quiet_run_command('si')
            eip = self.getRegValue('eip')
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            print('instruct is %s' % instruct[1])
            hardcode = decode.getDirectHardMove(instruct[1])
            if hardcode is not None:
                print('findCurrentLoad is hardcode move %s' % instruct[1])
                hard_count += 1
                if hard_count == 2:
                    op2, op1 = decode.getOperands(instruct[1])
                    our_reg = op1
                    break
        if hard_count == 2:
            for i in range(10):
                cli.quiet_run_command('si')
                eip = self.getRegValue('eip')
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                reg_relative = decode.getRegRelative(instruct[1], our_reg)
                if reg_relative is not None:
                    self.ptr_to_current_thread = hardcode
                    self.current_thread_ptr_offset =  reg_relative
                    print('findCurrent got hardcode address 0x%x and offset 0x%x' % (self.ptr_to_current_thread, self.current_thread_ptr_offset))
                    SIM_continue(0)
                    break

    def findComm(self):
        ''' Brute force find comm field, and thereby also the offset of the EPROCESS pointer
        '''
        # we'll start at offset 0x200 and look for addresses from there
        cur_guess = 0x200 + self.cur_thread_addr
        cheat = 0x220 + self.cur_thread_addr
        got_it = False
        for i in range (100):
            prec = self.readWord(cur_guess)
            test_offset = cur_guess - self.cur_thread_addr
            if prec is not None and prec > self.kernel_start and test_offset not in self.bad_prec_offsets:
                #print('prec to try is 0x%x' % prec)
                comm_guess = prec + 0x50
                for j in range (100):
                    #if cur_guess == cheat:
                    #    print('comm_guess to try is 0x%x' % comm_guess)
                    some_string = self.readString(comm_guess, 20)
                    #if cur_guess == cheat:
                    #    print('some_string 0x%x  %s' % (comm_guess, some_string))
                    if some_string is not None and some_string in ['svchost.exe','services.exe']:
                        print('KACHING')
                        got_it = True
                        self.prec_offset = cur_guess - self.cur_thread_addr
                        print('prec_offset is 0x%x' % self.prec_offset)
                        self.comm_offset = comm_guess - prec
                        print('comm_offset is 0x%x' % self.comm_offset)
                        cur_proc_addr = self.cur_thread_addr + self.prec_offset
                        prec = self.readWord(cur_proc_addr)
                        some_string = self.getComm(prec)
                        #print('TESTING comm for prec 0x%x is %s' % (prec, some_string))
                        SIM_continue(0)
                        break
                    comm_guess = comm_guess + 4
            if got_it:
                break
            cur_guess = cur_guess + 4
        if not got_it:
            print('failed to find known service, try next thread')
            SIM_continue(0)
        else:
            self.testing_prec_offset = 0

    def getComm(self, prec):
        comm_addr = prec + self.comm_offset
        retval = self.readString(comm_addr, 20)
        return retval

    def getPID(self, prec):
        pid_addr = prec + self.pid_offset
        retval = self.readWord(pid_addr)
        return retval

    def getPrec(self):
        cur_proc_addr = self.cur_thread_addr + self.prec_offset
        prec = self.readWord(cur_proc_addr)
        return prec

    def atSyscallEnter(self, dumb=None):
        #print('atSyscallEnter')
        if self.testing_prec_offset is not None:
            cur_proc_addr = self.cur_thread_addr + self.prec_offset
            prec = self.readWord(cur_proc_addr)
            comm_addr = prec + self.comm_offset
            some_string = self.readString(comm_addr, 20)
            #print('comm for prec 0x%x is %s' % (prec, some_string))
            if not some_string.endswith('.exe') and len(some_string) < 8:
                self.testing_prec_offset = None
                self.bad_prec_offsets.append(self.prec_offset)
                self.prec_offset = None
                SIM_continue(0)
            else:
                self.testing_prec_offset += 1
                if self.testing_prec_offset > 10:
                    print('we got it')
                    self.testing_prec_offset = None
                    self.did_threads = []
                    SIM_continue(0)
                else:
                    SIM_continue(0)
        elif self.prec_offset is None:
            self.findComm()
        elif self.next_prec is None:
            print('we have prec and comm, look for list pointer')
            prec = self.getPrec()
            #offset_guess = 0x70
            offset_guess = 0x10
            for i in range(300):
                comm_list = self.findNextPtr(prec, offset_guess)
                if len(comm_list) > 4:
                    print('good walk!')
                    self.next_prec = offset_guess
                    self.prev_prec = offset_guess - 4
                    break
                if self.next_prec is None:
                    comm_list = self.findNextPtr(prec, offset_guess, backwards=True)
                    if len(comm_list) > 4:
                        print('good walk!')
                        self.next_prec = offset_guess
                        self.prev_prec = offset_guess - 4
                        break

                offset_guess = offset_guess + 4
            if self.next_prec is not None:
                print('NOW DO pidSearch *********************')
                self.pidSearch()
        else:
            print('we have linked list pointers, now what?')
        
    def pidSearch(self):    
        prec_list = self.getPrecList()
        system_prec = None
        for prec in prec_list:
            comm = self.getComm(prec)
            print('prec 0x%x comm: %s' % (prec, comm))
            if comm == 'System':
                system_prec = prec
        print('pidSearch prec_list has %d items' % len(prec_list))
        pid_guess = 0x70
        maybe_offsets = []
        for i in range(300):
            addr = system_prec + pid_guess
            maybe_system_pid = self.readWord(addr)
            if maybe_system_pid == 4:
                for prec in prec_list:
                    if prec not in self.pid_map: 
                        self.pid_map[prec] = {}
                    comm = self.getComm(prec)
                    addr = prec + pid_guess
                    maybe = self.readWord(addr)
                    if pid_guess < 0xfffff and self.checkMaybe(maybe, pid_guess, prec, comm):
                        self.pid_map[prec][pid_guess] = maybe
                        if pid_guess not in maybe_offsets:
                            maybe_offsets.append(pid_guess)
            pid_guess = pid_guess + 4
        # eleminate offsets that do not appear for each prec
        maybe_offsets_copy = list(maybe_offsets)
        for offset in maybe_offsets_copy:
            for prec in self.pid_map:
                if offset not in self.pid_map[prec]:
                    self.lgr.debug('pidSearch culling offset 0x%x' % offset)
                    if offset in maybe_offsets:
                        maybe_offsets.remove(offset)
        if len(maybe_offsets) == 1:
            self.pid_offset = maybe_offsets[0]
            print('pidSearch found pid_offset 0x%x' % self.pid_offset)
        elif len(maybe_offsets) == 0:
            print('pidSearch found no pid offsets')
        else:
            print('pidSearch found more than 1 offset:')
            for offset in maybe_offsets:
                print('\tremaining offset: 0x%x' % offset)
            
        #for prec in self.pid_map:
        #    comm = self.getComm(prec)
        #    print('prec 0x%x comm: %s' % (prec, comm))
        #    for i in self.pid_map[prec]:
        #        print('\toffset 0x%x pid %d' % (i, self.pid_map[prec][i]))

    def checkMaybe(self, maybe, i, check_prec, check_comm):
        retval = True
        for prec in self.pid_map:
            if prec == check_prec:
                continue
            comm = self.getComm(prec)
            if i in self.pid_map[prec] and maybe == self.pid_map[prec][i]:
                retval = False
                self.bad_pid_offsets.append(i)
                print('checkMaybe check_prec 0x%x check_comm: %s reject %d for offset 0x%x, already in another proc prec: 0x%x comm %s' % (check_prec, check_comm, maybe, i, prec, comm))
                break
        return retval

    def breakHap(self, user_param, conf_object, break_num, memory):
        print('hit break hap at 0x%x' % memory.logical_address)
        SIM_run_alone(self.stopAndCall, self.currentChange)

    def currentChange(self, dumb):
        print('currentChange')
        prec_offset = 0x124
        proc_addr = self.cur_thread_addr + prec_offset
        print('proc_addr 0x%x' % proc_addr)
        cur_proc = self.readWord(proc_addr)
        print('cur_proc 0x%x from proc_addr 0x%x' % (cur_proc, proc_addr))

    def getUnsigned(self, value):
        retval = value & 0xFFFFFFFF
        return retval

    def readWord(self, addr):                 
        try:
            phys_block = self.cpu.iface.processor_info.logical_to_physical(addr, Sim_Access_Read)
        except:
            return None
        phys = phys_block.address
        retval = self.getUnsigned(SIM_read_phys_memory(self.cpu, phys, 4))
        return retval

    def readString(self, addr, maxlen):
        phys_block = self.cpu.iface.processor_info.logical_to_physical(addr, Sim_Access_Read)
        phys = phys_block.address
        return self.readStringPhys(phys, maxlen)
 
    def readStringPhys(self, paddr, maxlen):
        s = ''
        try:
            read_data = memUtils.readPhysBytes(self.cpu, paddr, maxlen, lgr=self.lgr)
        except ValueError:
            self.lgr.debug('readStringPhys, error reading paddr 0x%x maxlen 0x%x' % (paddr, maxlen))
            return None
        for v in read_data:
            if v == 0:
                del read_data
                return s
            s += chr(v)
        if len(s) > 0:
            return s
        else:
            return None

    def findNextPtr(self, paddr, offset, backwards=False):
        ''' try walking EPROCESS list with given paddr and offset of next.  Test using known comm offset '''
        comm = self.getComm(paddr)
        #print('walk, starting paddr: 0x%x offset 0x%x comm: %s' % (paddr, offset, comm))
        cur_paddr = paddr
        guess_previous = offset - 4
        comm_list = []
        for i in range(30):
            if backwards:
                next_addr_ptr = cur_paddr + guess_previous
            else:
                next_addr_ptr = cur_paddr + offset
            next_head = self.readWord(next_addr_ptr)
            if cur_paddr == (next_head - guess_previous):
                #print('next for offset 0x%x get same as previous paddr 0x%x, bail**************' % (offset, paddr))
                return comm_list
 
            cur_paddr = next_head - guess_previous
            if cur_paddr == paddr:
                #print('next for offset 0x%x get same paddr 0x%x, bail**************' % (offset, paddr))
                return comm_list
            if cur_paddr is None or cur_paddr < self.kernel_start:
                return comm_list
            #print('\ttry new cur_paddr of 0x%x' % cur_paddr)
            comm = self.getComm(cur_paddr)
            #print('\toffset 0x%x cur_paddr 0x%x next_head: 0x%x comm %s backward: %r' % (offset, cur_paddr, next_head, comm, backwards))
            if (comm is None or len(comm) == 0) and len(comm_list) > 1:
                print('ignoring lack of comm...')
            elif comm is None:
                return comm_list
            elif not comm.endswith('.exe') and len(comm) < 6 and comm != 'System':
                return comm_list
            comm_list.append(comm)
            #print('\toffset 0x%x sees a comm %s' % (offset, comm))
        return comm_list

    def getPrecList(self):
        retval = []
        first_prec = self.getPrec()
        prec = first_prec
        retval.append(prec)          
        for i in range(300):
            prec_ptr = prec + self.next_prec
            next_head = self.readWord(prec_ptr)
            if next_head is None:
                print('getPrecList got null for next_head 0x%x' % prec_ptr)
                break
            prec = next_head - self.prev_prec
            if prec in retval:
                print('getPrecList prec 0x%x already in list' % prec)
                break
            retval.append(prec)          
        for i in range(300):
            prec_ptr = prec + self.prev_prec
            next_head = self.readWord(prec_ptr)
            if next_head is None:
                print('getPrecList got null for next_head 0x%x' % prec_ptr)
                break
            prec = next_head - self.prev_prec
            if prec in retval:
                print('getPrecList prec 0x%x already in list' % prec)
                break
            retval.append(prec)          

        return retval

    def getThreadList(self):
        retval = []
        first_thread = self.getCurThread()
        thread = first_thread
        retval.append(thread)          
        for i in range(300):
            thread_ptr = thread + self.thread_next
            next_head = self.readWord(thread_ptr)
            if next_head is None:
                print('getThreadList got null for next_head 0x%x' % thread_ptr)
                break
            thread = next_head - self.thread_prev
            if thread in retval:
                print('getThreadList thread 0x%x already in list' % thread)
                break
            prec = self.getThreadPrec(thread)
            if prec != 0:
                retval.append(thread)          
        for i in range(300):
            thread_ptr = thread + self.thread_prev
            next_head = self.readWord(thread_ptr)
            if next_head is None:
                print('getThreadList got null for next_head 0x%x' % thread_ptr)
                break
            thread = next_head - self.thread_prev
            if thread in retval:
                print('getThreadList thread 0x%x already in list' % thread)
                break
            prec = self.getThreadPrec(thread)
            if prec != 0:
                retval.append(thread)          

        return retval

    def saveParam(self):
        self.param.sysenter = self.call_entry_addr
        self.param.sysexit = self.call_exit_addr
        self.param.page_fault = self.fault_addr
        self.param.current_task = self.ptr_to_current_thread
        self.param.current_thread_offset = self.current_thread_ptr_offset 
        self.param.proc_ptr = self.prec_offset
        self.param.ts_next = self.next_prec
        self.param.ts_prev = self.prev_prec
        self.param.ts_pid = self.pid_offset
        self.param.ts_comm = self.comm_offset
        self.param.thread_id_offset = self.tid_offset
        self.param.thread_next = self.thread_next
        self.param.thread_prev = self.thread_next
        self.param.thread_offset_in_prec = self.thread_offset_in_prec
        self.param.count_offset = self.count_offset
        self.lgr.debug(self.param.getParamString())
        self.lgr.debug('saveParam')
        fname = '%s.param' % self.target
        pickle.dump( self.param, open( fname, "wb" ) )
        self.param.printParams()


''' Create the ModeTest object.  Name it at simics command prompt using @mt.
    E.g., @mt.rmHap() '''

#mt = XPTest()
