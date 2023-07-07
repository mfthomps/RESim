from simics import *
class TraceMalloc():
    def __init__(self, fun_mgr, context_manager, mem_utils, task_utils, cpu, cell, dataWatch, lgr):
        self.fun_mgr = fun_mgr
        self.cell = cell
        self.cpu = cpu
        self.context_manager = context_manager
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.dataWatch = dataWatch
        self.lgr = lgr
        self.malloc_hap = None
        self.malloc_hap_ret = None
        self.free_hap = None
        self.malloc_list = []
        self.setBreaks()

    class MallocRec():
        def __init__(self, pid, size, cycle):
            self.pid = pid
            self.size = size
            self.addr = None
            self.cycle = cycle

    def stopTrace(self):
        if self.malloc_hap is not None:
            self.context_manager.genDeleteHap(self.malloc_hap)
            self.malloc_hap = None
            self.context_manager.genDeleteHap(self.free_hap)
            self.free_hap = None
        if self.malloc_hap_ret is not None:
            self.context_manager.genDeleteHap(self.malloc_hap_ret)
            self.malloc_hap_ret = None

    def setBreaks(self):
        if self.fun_mgr is not None:
            malloc_fun_addr, end = self.fun_mgr.getAddr('malloc')
            if malloc_fun_addr is not None:
                malloc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, malloc_fun_addr, 1, 0)
                self.malloc_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.mallocHap, None, malloc_break, 'malloc')
                free_fun_addr, end = self.fun_mgr.getAddr('free')
                free_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, free_fun_addr, 1, 0)
                self.free_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.freeHap, None, free_break, 'free')

            else:
                self.lgr.error('TraceMalloc, address of malloc not found in idaFuns')

    def mallocHap(self, dumb, context, break_num, memory):
        if self.malloc_hap is not None:
            cpu, comm, pid = self.task_utils.curProc() 
            #self.lgr.debug('TraceMalloc mallocHap pid:%d' % pid)
            if cpu.architecture == 'arm':
                size = self.mem_utils.getRegValue(self.cpu, 'r0') 
                #self.lgr.debug('malloc size %d' % size)
                ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr') 
            else:
                sp = self.mem_utils.getRegValue(self.cpu, 'sp')
                ret_addr = self.mem_utils.readPtr(self.cpu, sp)
                size = self.mem_utils.readWord32(self.cpu, sp+self.mem_utils.WORD_SIZE)
                #self.lgr.debug('malloc size %d' % size)
            malloc_rec = self.MallocRec(pid, size, cpu.cycles)
            malloc_ret_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, ret_addr, 1, 0)
            self.malloc_hap_ret = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.mallocEndHap, malloc_rec, malloc_ret_break, 'malloc_end')

    def freeHap(self, dumb, context, break_num, memory):
        if self.free_hap is not None:
            cpu, comm, pid = self.task_utils.curProc() 
            #self.lgr.debug('TraceMalloc freeHap pid:%d' % pid)
            if cpu.architecture == 'arm':
                addr = self.mem_utils.getRegValue(self.cpu, 'r0') 
                #self.lgr.debug('free addr 0x%x' % addr)
            else:
                sp = self.mem_utils.getRegValue(self.cpu, 'sp')
                addr = self.mem_utils.readPtr(self.cpu, sp+self.mem_utils.WORD_SIZE)
                #self.lgr.debug('free addr 0x%x' % addr)
            self.dataWatch.recordFree(addr)

    def mallocEndHap(self, malloc_rec, context, break_num, memory):
        if self.malloc_hap_ret is not None:
            cpu, comm, pid = self.task_utils.curProc() 
            #self.lgr.debug('TraceMalloc mallocEndHap pid:%d' % pid)
            if cpu.architecture == 'arm':
                addr = self.mem_utils.getRegValue(self.cpu, 'r0') 
                #self.lgr.debug('malloc addr 0x%x' % addr)
            else:
                addr = self.mem_utils.getRegValue(self.cpu, 'eax') 
                #self.lgr.debug('malloc addr 0x%x, size: %d' % (addr, malloc_rec.size))
            malloc_rec.addr = addr
            self.malloc_list.append(malloc_rec)
            self.context_manager.genDeleteHap(self.malloc_hap_ret)
            self.malloc_hap_ret = None
            self.dataWatch.recordMalloc(addr, malloc_rec.size)

    def showList(self):
        for rec in self.malloc_list:
            print('%4d \t0x%x\t%d' % (rec.pid, rec.addr, rec.size))
