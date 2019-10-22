from simics import *
import pageUtils
import stopFunction
import hapCleaner
import decode
import elfText
import memUtils
class DataWatch():
    ''' Watch a range of memory and stop when it is read.  Intended for use in tracking
        reads to buffers into which data has been read, e.g., via RECV. '''
    def __init__(self, top, cpu, page_size, context_manager, mem_utils, param, lgr):
        self.start = []
        self.length = []
        self.read_hap = []
        self.top = top
        self.cpu = cpu
        self.context_manager = context_manager
        self.mem_utils = mem_utils
        self.lgr = lgr
        self.page_size = page_size
        self.show_cmp = False
        self.break_simulation = True
        self.param = param
        self.return_break = None
        self.return_hap = None
        self.prev_cycle = None
        self.watch_marks = []

    class WatchMark():
        def __init__(self, cycle, ip, msg):
            self.cycle = cycle
            self.ip = ip
            self.msg = msg
        def getJson(self):
            retval = {}
            retval['cycle'] = self.cycle
            retval['ip'] = self.ip
            retval['msg'] = self.msg
            return retval

    def setRange(self, start, length, msg):
        self.lgr.debug('DataWatch set range start 0x%x length 0x%x' % (start, length))
        end = start+length
        overlap = False
        for index in range(len(self.start)):
            if self.start[index] != 0:
                this_end = self.start[index] + self.length[index]
                if self.start[index] <= start and this_end >= end:
                    overlap = True
                    self.lgr.debug('DataWatch setRange found overlap, skip it')
                    break
        if not overlap:
            self.start.append(start)
            self.length.append(length)
        eip = self.top.getEIP(self.cpu)
        fixed = unicode(msg, errors='replace')
        self.watch_marks.append(self.WatchMark(self.cpu.cycles, eip, fixed))

    def close(self, fd):
        ''' called when FD is closed and we might be doing a trackIO '''
        eip = self.top.getEIP(self.cpu)
        msg = 'closed FD: %d' % fd
        self.watch_marks.append(self.WatchMark(self.cpu.cycles, eip, msg))
        

    def watch(self, show_cmp=False, break_simulation=None):
        self.lgr.debug('DataWatch watch show_cmp: %r' % show_cmp)
        self.show_cmp = show_cmp         
        if break_simulation is not None:
            self.break_simulation = break_simulation         
        if len(self.start) > 0:
            self.setBreakRange()
            return True
        return False

    def showCmp(self, addr): 
        eip = self.top.getEIP(self.cpu)
        instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
        self.lgr.debug('showCmp eip 0x%x %s' % (eip, instruct[1]))
        mval = self.mem_utils.readWord32(self.cpu, addr)
        if instruct[1].startswith('cmp'):
            op2, op1 = decode.getOperands(instruct[1])
            val = None
            if decode.isReg(op2):
                val = self.mem_utils.getRegValue(self.cpu, op2)
            elif decode.isReg(op1):
                val = self.mem_utils.getRegValue(self.cpu, op1)
            if val is not None:
                print('%s  reg: 0x%x  addr:0x%x mval: 0x%08x' % (instruct[1], val, addr, mval))
          
    def getCmp(self):
        retval = '' 
        eip = self.top.getEIP(self.cpu)
        for i in range(10):
            instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            if instruct[1].startswith('cmp'):
                retval = instruct[1]
                break
            else:
                eip = eip + instruct[0]
        return retval
            
               
    def stopWatch(self, break_simulation=None): 
        self.lgr.debug('dataWatch stopWatch')
        for index in range(len(self.start)):
            if self.start[index] == 0:
                continue
            if index < len(self.read_hap):
                if self.read_hap[index] is not None:
                    self.context_manager.genDeleteHap(self.read_hap[index])
            else:
                self.lgr.debug('dataWatch stopWatch index %d not in read_hap len is %d ' % (index, len(self.read_hap)))
        self.read_hap = []
        if break_simulation is not None: 
            self.break_simulation = break_simulation
    
    def kernelReturnHap(self, pass_this, third, forth, memory):
        self.context_manager.genDeleteHap(self.return_hap)
        eax = self.mem_utils.getRegValue(self.cpu, 'syscall_ret')
        self.lgr.debug('kernelReturnHap, retval 0x%x' % eax)
        self.watch()

    def kernelReturn(self, dumb):
        if self.cpu.architecture == 'arm':
            cell = self.top.getCell()
            proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, self.param.arm_ret, 1, 0)
            self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.kernelReturnHap, None, proc_break, 'memcpy_return_hap')
        else:
            self.lgr.debug('Only ARM kernel return handled for now') 
            self.watch()
        
      
    def returnHap(self, pass_this, third, forth, memory):
        src, dest, ret_ip = pass_this
        new_src = self.mem_utils.getRegValue(self.cpu, 'r1')
        self.context_manager.genDeleteHap(self.return_hap)
        ''' TBD assumes arm memcpy starts with a LDM     R1!, {R3-R8,R12,LR} '''
        length = (new_src - src) + 0x20
        msg = 'copy %d bytes from 0x%x to 0x%x' % (length, src, dest)
        self.setRange(dest, length, msg) 
        self.lgr.debug('dataWatch returnHap, return from memcpy src: 0x%x dest: 0x%x new_src: 0x%x length %d ' % (src, dest, new_src, length))
        #SIM_break_simulation('return hap')
        #return
        self.watch()
         
    def handleMemcpy(self, ret_ip):
        if self.cpu.architecture == 'arm':
            dest = self.mem_utils.getRegValue(self.cpu, 'r0')
            src = self.mem_utils.getRegValue(self.cpu, 'r1')
            cell = self.top.getCell()
            pass_this = [src, dest, ret_ip]
            proc_break = self.context_manager.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Execute, ret_ip, 1, 0)
            self.return_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.returnHap, pass_this, proc_break, 'memcpy_return_hap')
            self.lgr.debug('handleMemcpy set hap on ret_ip at 0x%x' % ret_ip)
            #SIM_break_simulation('wtf is the lr?')
            

        else:
            self.lgr.debug('Only ARM memcpy handled for now') 
            self.watch()

    def readHap(self, index, third, forth, memory):
        #value = SIM_get_mem_op_value_le(memory)
        if self.cpu.cycles == self.prev_cycle:
            return
        self.prev_cycle = self.cpu.cycles

        if index >= len(self.read_hap):
            self.lgr.error('dataWatch readHap invalid index %d, only %d read haps' % (index, len(self.read_hap)))
            return
        if self.read_hap[index] is None:
            return
        op_type = SIM_get_mem_op_type(memory)
        addr = memory.logical_address
        eip = self.top.getEIP(self.cpu)
        #self.lgr.debug('dataWatch readHap index %d addr 0x%x eip 0x%x' % (index, addr, eip))
        if self.show_cmp:
            self.showCmp(addr)

        if self.break_simulation:
            self.lgr.debug('readHap will break_simulation, set the stop hap')
            self.stopWatch()
            SIM_run_alone(self.setStopHap, None)
        offset = addr - self.start[index]
        cpl = memUtils.getCPL(self.cpu)
        start, end = self.context_manager.getText()
        call_sp = None
        if eip > end and cpl != 0:
            ''' from so library, check for cpy functions '''
            if not self.break_simulation:
                ''' prevent stack trace from triggering haps '''
                self.stopWatch()
            st = self.top.getStackTraceQuiet()
            self.lgr.debug('%s' % st.getJson()) 
            ''' look for memcpy'ish... TBD generalize '''
            ret_ip = st.memcpy()
            if ret_ip is not None:
                self.lgr.debug('DataWatch readHap ret_ip 0x%x' % (ret_ip))
                SIM_run_alone(self.handleMemcpy, ret_ip)
            else:
                self.lgr.debug('DataWatch readHap not memcpy, reset the watch')
                self.watch()
        if op_type == Sim_Trans_Load:

            self.lgr.debug('Data read from 0x%x within input buffer (offset of %d into buffer of %d bytes starting at 0x%x) eip: 0x%x cycle:0x%x' % (addr, 
                    offset, self.length[index], self.start[index], eip, self.cpu.cycles))
            msg = ('Data read from 0x%x within input buffer (offset of %d into %d bytes starting at 0x%x) eip: 0x%x' % (addr, 
                        offset, self.length[index], self.start[index], eip))
            self.context_manager.setIdaMessage(msg)
            mark_msg = 'Read from 0x%08x offset %4d into 0x%8x (buf size %4d) %s' % (addr, offset, self.start[index], self.length[index], self.getCmp())
            self.watch_marks.append(self.WatchMark(self.cpu.cycles, eip, mark_msg))
            if self.break_simulation:
                SIM_break_simulation('DataWatch read data')

            if cpl == 0:
                if not self.break_simulation:
                    self.stopWatch()
                SIM_run_alone(self.kernelReturn, None)
            elif call_sp is None:
                ''' not kernel and not library copy. look for compare '''
                for i in range(3):
                    instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                    self.lgr.debug('\t\t0x%x  %s' % (eip, instruct[1]))
                    eip = eip + instruct[0]

        elif cpl > 0:
            self.lgr.debug('Data written to 0x%x within input buffer (offset of %d into buffer of %d bytes starting at 0x%x) eip: 0x%x' % (addr, offset, self.length[index], self.start[index], eip))
            self.context_manager.setIdaMessage('Data written to 0x%x within input buffer (offset of %d into %d bytes starting at 0x%x) eip: 0x%x' % (addr, offset, self.length[index], self.start[index], eip))
            if self.break_simulation:
                ''' TBD when to treat buffer as unused?  does it matter?'''
                self.start[index] = 0
                SIM_break_simulation('DataWatch written data')
       
    def showWatch(self):
        for index in range(len(self.start)):
            if self.start[index] != 0:
                print('%d start: 0x%x  length: 0x%x' % (index, self.start[index], self.length[index]))
 
    def setBreakRange(self):
        context = self.context_manager.getRESimContext()
        for index in range(len(self.start)):
            if self.start[index] == 0:
                self.lgr.debug('DataWatch setBreakRange index %d is 0' % index)
                self.read_hap.append(None)
                continue
            break_num = self.context_manager.genBreakpoint(context, Sim_Break_Linear, Sim_Access_Read | Sim_Access_Write, self.start[index], self.length[index], 0)
            end = self.start[index] + self.length[index] 
            eip = self.top.getEIP(self.cpu)
            self.lgr.debug('DataWatch setBreakRange eip: 0x%x Adding breakpoint %d for %x-%x length %x index now %d' % (eip, break_num, self.start[index], end, self.length[index], index))
            self.read_hap.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.readHap, index, break_num, 'dataWatch'))

    def stopHap(self, stop_action, one, exception, error_string):
        if stop_action is None or stop_action.hap_clean is None:
            self.lgr.error('dataWatch stopHap error, stop_action None?')
            return
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('dataWatch stopHap eip 0x%x cycle: 0x%x' % (eip, stop_action.hap_clean.cpu.cycles))

        if self.stop_hap is not None:
            self.lgr.debug('dataWatch stopHap will delete hap %s' % str(self.stop_hap))
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None
            ''' check functions in list '''
            self.lgr.debug('stopHap now run actions %s' % str(stop_action.flist))
            stop_action.run()
         
    def setStopHap(self, dumb):
        f1 = stopFunction.StopFunction(self.top.skipAndMail, [], nest=False)
        flist = [f1]
        hap_clean = hapCleaner.HapCleaner(self.cpu)
        stop_action = hapCleaner.StopAction(hap_clean, None, flist)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        self.lgr.debug('setStopHap set actions %s' % str(stop_action.flist))

    def setShow(self):
        self.show_cmp = ~ self.show_cmp
        return self.show_cmp

    def findRange(self, addr):
        for index in range(len(self.start)):
            if self.start[index] != 0:
                end = self.start[index] + self.length[index]
                if addr >= self.start[index] and addr <= end:
                    return self.start[index]
        return None

    def getWatchMarks(self):
        retval = []
        for mark in self.watch_marks:
            retval.append(mark.getJson())
        return retval        

    def goToMark(self, index):
        mark = self.watch_marks[index]
        SIM_run_command('pselect %s' % self.cpu.name)
        SIM_run_command('skip-to cycle=%d' % mark.cycle)
 
