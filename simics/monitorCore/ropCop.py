from simics import *
import decode
import decodeArm
class RopCop():
    def __init__(self, top, cpu, cell, context_manager, mem_utils, text, size, lgr):
        self.context_manager = context_manager
        self.top = top
        self.cpu = cpu
        self.cell = cell
        self.mem_utils = mem_utils
        self.text = text
        self.size = size
        self.lgr = lgr
        self.rop_hap = None
        self.stop_hap = None
        self.watching = False
        self.lgr.debug('RopCop text 0x%x size %d' % (text, size))
        if self.cpu.architecture == 'arm':
            self.decode = decodeArm
        else:
            self.decode = decode

    def watchROP(self):
        self.watching = True

    def setHap(self):
        if not self.watching:
            return
        if self.cpu.architecture == 'arm':
            prefix = 'ldm'
            self.callmn = 'bl'
            proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.text, self.size, 0, prefix)
            self.rop_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.ropHapArm, None, proc_break, 'rop_hap')
        else:
            prefix = 'ret'
            self.callmn = 'call'
            proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, self.text, self.size, 0, prefix)
            self.rop_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.ropHap, None, proc_break, 'rop_hap')

    def isArmCall(self, instruct):
        retval = False
        if instruct.startswith(self.callmn):
            retval = True
        elif instruct.startswith('ldr'):
            parts = instruct.split()
            if parts[1].strip().lower() == 'pc,':
               retval = True
        return retval

    def ropHap(self, dumb, third, forth, memory):
        ''' callback when ret or pop executed'''
        #addr = memory.logical_address
        #instruct = SIM_disassemble_address(self.cpu, addr, 1, 0)
        #current_eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        
        esp = self.mem_utils.getRegValue(self.cpu, 'esp')
        return_to = self.mem_utils.readWord32(self.cpu, esp)
        eip = return_to - 8
        done = False
        #self.lgr.debug("rop_cop_ret_callback current_eip: %x return_to %x" % (current_eip, return_to))
        while not done and eip < return_to:
            # TBD use instruction length to confirm it is a true call
            try:
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            except:
                self.lgr.debug('ropCop  failed to disassble instruct %x ' % (eip))
                return
            if instruct[1].startswith('call'):
                done = True
            else:
                eip = eip+1
        if not done:
            self.lgr.debug('********************* not call prior to 0x%x' % (return_to))
            SIM_run_alone(self.stopAlone, None)
  

    def ropHapArm(self, dumb, third, forth, memory):
        ''' callback when ret or pop executed'''
        addr = memory.logical_address
        instruct = SIM_disassemble_address(self.cpu, addr, 1, 0)
        if 'pc' in instruct[1]:
            stack_val = self.decode.armLDM(self.cpu, instruct[1], 'pc', self.lgr)
            ret_addr = self.mem_utils.readPtr(self.cpu, stack_val)
            #self.lgr.debug('ropHap at 0x%x  %s  stack: 0x%x ret_addr: 0x%x' % (addr, instruct[1], stack_val, ret_addr))
            pc = ret_addr - 4
            prev_instruct = SIM_disassemble_address(self.cpu, pc, 1, 0)
            #self.lgr.debug('followCall instruct is %s' % instruct[1])
            if not self.isArmCall(prev_instruct[1]):
                self.lgr.debug('********************* not call %s  at 0x%x' % (prev_instruct[1], pc))
                SIM_run_alone(self.stopAlone, None)

    def stopAlone(self, dumb):
        self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", self.stopHap, None)
        print('Possible ROP')
        SIM_break_simulation('ROP ?')

    def stopHap(self, my_args, one, exception, error_string):
        if self.stop_hap is None:  
            return
        SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.lgr.debug('ropCop stopHap, call skipAndMail')
        self.top.skipAndMail()

    def clearHap(self):
        if self.rop_hap is not None:
            self.context_manager.genDeleteHap(self.rop_hap, immediate=True)
            self.lgr.debug('ropCop cleared hap %d' % self.rop_hap)
            self.rop_hap = None
