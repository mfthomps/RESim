import os
import memUtils
from simics import *
class VxKTaskUtils():
    def __init__(self, cpu, cell_name, mem_utils, comp_dict, run_from_snap, lgr):
        self.lgr = lgr
        self.cpu = cpu 
        self.cell_name = cell_name 
        self.mem_utils = mem_utils 
        self.comp_dict = comp_dict 
        self.global_sym = {}
        self.local_sym = {}
        self.task_id_current = None
        self.prog_name = None
        if 'VXIMAGE_PATH' in comp_dict:
            self.loadSyms(comp_dict['VXIMAGE_PATH'])
        else:
            self.lgr.error('No VXIMAGE_PATH defined in ini file')
            return

    def getMemUtils(self):
        return self.mem_utils

    def getPhysCurrentTask(self):
        return None

    def getTidList(self):
        return []

    def loadSyms(self, vximage_path):
        #sfile = 'vxworks-sym.txt'
        sfile = os.path.join(vximage_path, 'rpu_global.symbols')
        if not os.path.isfile(sfile):
            self.lgr.error('vxKMonitor loadSyms rpu_global.symbols not found at %s' % sfile)
            return
        with open(sfile) as fh:
            for line in fh:
                try:
                    addr, kind, sym = line.split()
                except:
                    print('trouble reading %s' % line)
                    continue
                addr = int(addr, 16)
                #addr = addr - self.symbol_offset
                if kind == 't':
                    self.local_sym[addr] = sym
                elif kind == 'T':
                    self.global_sym[addr] = sym
                else:
                    print('loadSys confused by %s' % line)
        print('loaded %d symbols' % len(self.global_sym))
        dfile = os.path.join(vximage_path, 'rpu_data.symbols')
        if not os.path.isfile(dfile):
            self.lgr.error('vxKMonitor loadSyms rpu_data.symbols not found at %s' % dfile)
            return
        with open(dfile) as fh:
            for line in fh:
                if 'taskIdCurrent' in line:
                    parts = line.split()
                    self.task_id_current = int(parts[0], 16)
                    self.lgr.debug('vxKMonitor loadSyms got task_id_current of 0x%x' % self.task_id_current)
                    break

    def getGlobalSymDict(self):
        return self.global_sym

    def setCurTaskBreak(self, addr):
        ''' set a write breakpoint and a hap on the task_id_current'''
        bp = SIM_breakpoint(self.cpu.current_context, Sim_Break_Linear, Sim_Access_Write, addr, 1, 0)
        self.cur_task_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.curTaskHap, None, bp)
        self.lgr.debug('setCurTaskBreak set on 0x%x' % addr)

    def curTaskHap(self, user_param, conf_object, break_num, memory):
        new_val = memUtils.memoryValue(self.cpu, memory)
        addr = memory.logical_address
        old_val = SIM_read_phys_memory(self.cpu, addr, 4)
        if new_val not in self.task_list:
            self.lgr.debug('curTaskHap addr 0x%x old value 0x%x new 0x%x' % (addr, old_val, new_val))
            self.task_list.append(new_val)
            SIM_break_simulation('curTask')

    def getCurrentTask(self):
        retval = SIM_read_phys_memory(self.cpu, self.task_id_current, 4)
        return retval

    def pickleit(self, name):
        return

    def curTID(self):
        tid = '0x%x' % self.getCurrentTask()
        return tid

    def getGroupLeaderTid(self, tid):
        return self.curTID

    def getGroupTids(self, tid):
        return [self.curTID()]

    def getProgName(self, tid):
        return self.prog_name, None

    def clearExitTid(self):
        return

    def curThread(self):
        comm = self.prog_name
        tid = self.curTID()
        return self.cpu, comm, tid

    def setProgName(self, prog_name):
        self.prog_name = prog_name

    def frameFromRegs(self, compat32=None):
        frame = {}
        for p in memUtils.param_map['arm']:
            frame[p] = self.mem_utils.getRegValue(self.cpu, memUtils.param_map['arm'][p])
            frame['sp'] = self.mem_utils.getRegValue(self.cpu, 'sp')
            frame['pc'] = self.mem_utils.getRegValue(self.cpu, 'pc')
            frame['lr'] = self.mem_utils.getRegValue(self.cpu, 'lr')
        return frame

    def getGlobalSym(self, addr):
        retval = None
        if addr in self.global_sym:
            #print('VxWorks global symbol at 0x%x is %s' % (addr, self.global_sym[addr]))
            retval = self.global_sym[addr]
        return retval

    def syscallName(self, call_num, compat32):
        return 'eh?' 

    def getCurThreadRec(self):    
        return self.getCurrentTask()

    def recentExitTid(self):
        return None
