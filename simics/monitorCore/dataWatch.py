from simics import *
import pageUtils
import stopFunction
import hapCleaner
import decode
class DataWatch():
    ''' Watch a range of memory and stop when it is read.  Intended for use in tracking
        reads to buffers into which data has been read, e.g., via RECV. '''
    def __init__(self, top, cpu, page_size, context_manager, mem_utils, lgr):
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

    def setRange(self, start, length):
        self.lgr.debug('DataWatch set range start 0x%x length 0x%x' % (start, length))
        self.start.append(start)
        self.length.append(length)

    def watch(self, show_cmp):
        self.lgr.debug('DataWatch watch show_cmp: %r' % show_cmp)
        self.show_cmp = show_cmp         
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
           
                
             
    def readHap(self, index, third, forth, memory):
        #value = SIM_get_mem_op_value_le(memory)
        if index >= len(self.read_hap):
            self.lgr.error('dataWatch readHap invalid index %d, only %d read haps' % (index, len(self.read_hap)))
            return
        if self.read_hap[index] is None:
            return
        op_type = SIM_get_mem_op_type(memory)
        addr = memory.logical_address
        self.lgr.debug('dataWatch readHap index %d addr 0x%x' % (index, addr))
        eip = self.top.getEIP(self.cpu)
        if self.show_cmp:
            self.showCmp(addr)

        for index in range(len(self.start)):
            if self.start[index] == 0:
                continue
            self.context_manager.genDeleteHap(self.read_hap[index])
        self.read_hap = []

        SIM_run_alone(self.setStopHap, None)
        if op_type == Sim_Trans_Load:
            self.lgr.debug('Data read from 0x%x within input buffer (%d bytes starting at 0x%x) eip: 0x%x' % (addr, self.length[index], self.start[index], eip))
            self.context_manager.setIdaMessage('Data read from 0x%x within input buffer (%d bytes starting at 0x%x) eip: 0x%x' % (addr, self.length[index], self.start[index], eip))
            SIM_break_simulation('DataWatch read data')
        else:
            self.lgr.debug('Data written to 0x%x within input buffer (%d bytes starting at 0x%x) eip: 0x%x' % (addr, self.length[index], self.start[index], eip))
            self.context_manager.setIdaMessage('Data written to 0x%x within input buffer (%d bytes starting at 0x%x) eip: 0x%x' % (addr, self.length[index], self.start[index], eip))
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
        f1 = stopFunction.StopFunction(self.top.skipAndMail, [], False)
        flist = [f1]
        hap_clean = hapCleaner.HapCleaner(self.cpu)
        stop_action = hapCleaner.StopAction(hap_clean, None, flist)
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
        	     self.stopHap, stop_action)
        self.lgr.debug('setStopHap set actions %s' % str(stop_action.flist))

    def setShow(self):
        self.show_cmp = ~ self.show_cmp
        return self.show_cmp
