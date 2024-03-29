from simics import *
import decode
import decodeArm
from resimHaps import *
class RopCop():
    def __init__(self, top, cpu, cell_name, context_manager, mem_utils, text, size, bookmarks, task_utils, lgr):
        self.context_manager = context_manager
        self.top = top
        self.cpu = cpu
        self.cell_name = cell_name
        self.mem_utils = mem_utils
        self.text = text
        self.size = size
        self.lgr = lgr
        self.task_utils = task_utils
        self.bookmarks = bookmarks
        self.rop_hap = None
        self.stop_hap = None
        self.watching = False
        ''' hack to keep hap from invoking twice '''
        self.in_process = False
        self.lgr.debug('RopCop text 0x%x size %d' % (text, size))
        if self.cpu.architecture == 'arm':
            self.decode = decodeArm
        else:
            self.decode = decode

    def watchROP(self, watching=True):
        self.watching = watching
        self.lgr.debug('watchROP %r' % watching)
        if watching:
            self.setHap()
        else:
            self.clearHap()

    def setHap(self):
        if not self.watching:
            return
        self.in_process = False
        if self.cpu.architecture == 'arm':
            prefix = 'ldm'
            self.callmn = 'bl'
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.text, self.size, 0, prefix)
            self.rop_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.ropHapArm, None, proc_break, 'rop_hap')
        else:
            prefix = 'ret'
            self.callmn = 'call'
            proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, self.text, self.size, 0, prefix)
            self.rop_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.ropHap, None, proc_break, 'rop_hap')
        #self.lgr.debug('ropCop setHap done on 0x%x size 0x%x' % (self.text, self.size))

    def ropHap(self, dumb, third, forth, memory):
        ''' callback when ret or pop executed'''
        if self.rop_hap is None:  
            return
        if self.in_process:
            self.lgr.debug('ropHap, in progress, return')
            return
        #addr = memory.logical_address
        #instruct = SIM_disassemble_address(self.cpu, addr, 1, 0)
        #current_eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        
        esp = self.mem_utils.getRegValue(self.cpu, 'esp')
        word_size = self.mem_utils.wordSize(self.cpu)
        if word_size == 4:
            return_to = self.mem_utils.readWord32(self.cpu, esp)
        else:
            return_to = self.mem_utils.readWord(self.cpu, esp)
        #eip = return_to - 8
        eip = return_to - 2*word_size
        done = False
        #self.lgr.debug("rop_cop_ret_callback current_eip: %x return_to %x" % (eip, return_to))
        while not done and eip < return_to:
            # TBD use instruction length to confirm it is a true call
            try:
                instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
            except:
                self.lgr.error('ropCop  failed to disassemble instruct %x ' % (eip))
                return
            
            #if instruct[1].startswith('call'):
            #if self.decode.isCall(self.cpu, instruct[1], ignore_flags=True):
            if instruct[1].startswith(self.callmn):
                done = True
            else:
                eip = eip+1
        if not done and self.cpu.architecture != 'arm':
            ''' is the return to a signal handler? '''
            ''' hacky look for int 80 or sysenter '''
            for eip in range(return_to, return_to+40):
                try:
                    instruct = SIM_disassemble_address(self.cpu, eip, 1, 0)
                except:
                    self.lgr.error('ropCop looking for sighandler failed to disassble instruct %x ' % (eip))
                    return
                if instruct[1].startswith('int') or instruct[1].startswith('sysenter'):
                    dumb, comm, cur_tid  = self.task_utils.curThread()
                    self.lgr.debug('ropCop found signal in tid %s' % cur_tid)
                    done = True
                    break
          
        if not done:
            self.lgr.debug('********************* not call prior to 0x%x' % (return_to))
            self.in_process = True
            SIM_run_alone(self.stopAlone, return_to)
  

    def ropHapArm(self, dumb, third, forth, memory):
        ''' callback when ret or pop executed'''
        if self.rop_hap is None:  
            return
        if self.in_process:
            self.lgr.debug('ropHap, in progress, return')
            return
        addr = memory.logical_address
        instruct = SIM_disassemble_address(self.cpu, addr, 1, 0)
        if 'pc' in instruct[1]:
            stack_val = self.decode.armLDM(self.cpu, instruct[1], 'pc', self.lgr)
            ret_addr = self.mem_utils.readPtr(self.cpu, stack_val)
            #self.lgr.debug('ropHap at 0x%x  %s  stack: 0x%x ret_addr: 0x%x' % (addr, instruct[1], stack_val, ret_addr))
            pc = ret_addr - 4
            prev_instruct = SIM_disassemble_address(self.cpu, pc, 1, 0)
            #self.lgr.debug('followCall instruct is %s' % instruct[1])
            #if not self.decode.isCall(self.cpu, prev_instruct[1]):
            if not prev_instruct[1].startswith(self.callmn):
                prev_pc = pc - 4
                prev_prev_instruct = SIM_disassemble_address(self.cpu, prev_pc, 1, 0)
                op2, op1 = self.decode.getOperands(prev_prev_instruct[1])
                if not (prev_prev_instruct[1].startswith('mov') and op2 == 'pc' and op1 == 'lr'):
                    self.in_process = True
                    self.lgr.debug('********************* not call %s  at 0x%x' % (prev_instruct[1], pc))
                    self.lgr.debug('********************* or not mov lr, pc: %s' % prev_prev_instruct[1])
                    SIM_run_alone(self.stopAlone, ret_addr)

    def stopAlone(self, ret_addr):
        self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", self.stopHap, ret_addr)
        print('Possible ROP')
        SIM_break_simulation('ROP ?')

    def stopHap(self, ret_addr, one, exception, error_string):
        if self.stop_hap is None:  
            return
        RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
        self.clearHap()
        self.watchROP(watching=False)
        self.lgr.debug('ropCop stopHap, call skipAndMail, disabled ROP watch')
        eip = self.mem_utils.getRegValue(self.cpu, 'eip')
        esp = self.mem_utils.getRegValue(self.cpu, 'esp')
        bm = "ROP eip:0x%x esp:0x%x would return to 0x%x" % (eip, esp, ret_addr)
        dumb, comm, cur_tid  = self.task_utils.curThread()
        self.lgr.debug('ropCop stopHap %s tid:%s' % (bm, cur_tid))
        self.top.removeDebugBreaks()
        self.top.stopDataWatch()
        self.bookmarks.setDebugBookmark(bm)
        self.top.skipAndMail()

    def clearHap(self):
        if self.rop_hap is not None:
            #self.context_manager.genDeleteHap(self.rop_hap, immediate=False)
            #self.lgr.debug('ropCop clear hap %d' % self.rop_hap)
            self.context_manager.genDeleteHap(self.rop_hap, immediate=True)
            #self.lgr.debug('ropCop cleared hap %d' % self.rop_hap)
            self.rop_hap = None
        self.did_these = []
