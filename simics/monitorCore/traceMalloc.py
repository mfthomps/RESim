from simics import *
import json
class TraceMalloc():
    def __init__(self, top, fun_mgr, context_manager, mem_utils, task_utils, cpu, cell, dataWatch, lgr, comm=None, trace_mgr=None, callback=None):
        self.fun_mgr = fun_mgr
        self.cell = cell
        self.cpu = cpu
        self.top = top
        self.context_manager = context_manager
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.dataWatch = dataWatch
        self.lgr = lgr
        self.malloc_hap = None
        self.calloc_hap = None
        self.realloc_hap = None
        self.malloc_hap_ret = None
        self.free_hap = None
        self.malloc_list = []
        self.current_malloc = {}
        self.comm = comm
        self.trace_mgr = trace_mgr
        self.callback = callback
        self.setBreaks()

    class MallocRec():
        def __init__(self, fun, tid, size, cycle, realloc_ptr=None):
            self.fun = fun
            self.tid = tid
            self.size = size
            self.addr = None
            self.cycle = cycle
            self.realloc_ptr = realloc_ptr

    def stopTrace(self):
        self.lgr.debug('traceMalloc stopTrace')
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
            malloc_fun_addr = self.fun_mgr.getFunEntry('malloc')
            if malloc_fun_addr is not None:
                malloc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, malloc_fun_addr, 1, 0)
                self.malloc_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.mallocHap, 'malloc', malloc_break, 'malloc')

                calloc_fun_addr = self.fun_mgr.getFunEntry('calloc')
                calloc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, calloc_fun_addr, 1, 0)
                self.calloc_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.callocHap, 'calloc', calloc_break, 'calloc')

                realloc_fun_addr = self.fun_mgr.getFunEntry('realloc')
                realloc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, realloc_fun_addr, 1, 0)
                self.calloc_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.reallocHap, 'realloc', realloc_break, 'realloc')

                free_fun_addr = self.fun_mgr.getFunEntry('free')
                free_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, free_fun_addr, 1, 0)
                self.free_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.freeHap, None, free_break, 'free')
                self.lgr.debug('TraceMalloc setBreaks on malloc 0x%x and free 0x%x' % (malloc_fun_addr, free_fun_addr))

            else:
                self.lgr.error('TraceMalloc, address of malloc not found in idaFuns')
        else:
            self.lgr.warning('TraceMalloc no fun_mgr')
            print('TraceMalloc requested, no fun_mgr')

    def mallocHap(self, dumb, context, break_num, memory):
        if self.malloc_hap is not None:
            cpu, comm, tid = self.task_utils.curThread() 
            self.lgr.debug('TraceMalloc mallocHap tid:%s' % tid)
            if self.comm is not None and self.comm != comm:
                return
            if cpu.architecture == 'arm':
                size = self.mem_utils.getRegValue(self.cpu, 'r0') 
                #self.lgr.debug('malloc size %d' % size)
                ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr') 
            elif cpu.architecture == 'arm64':
                size = self.mem_utils.getRegValue(self.cpu, 'x0') 
                #self.lgr.debug('malloc size %d' % size)
                ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr') 
            elif cpu.architecture == 'ppc32':
                size = self.mem_utils.getRegValue(self.cpu, 'r3') 
                self.lgr.debug('malloc size %d' % size)
                ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr') 
            else:
                sp = self.mem_utils.getRegValue(self.cpu, 'sp')
                ret_addr = self.mem_utils.readPtr(self.cpu, sp)
                size = self.mem_utils.readWord32(self.cpu, sp+self.mem_utils.WORD_SIZE)
                #self.lgr.debug('TraceMalloc mallocHap malloc size %d ret_addr 0x%x cycle 0x%x' % (size, ret_addr, self.cpu.cycles))
            if not self.top.isLibc(ret_addr, target_cpu=self.cpu) and self.top.getSO(ret_addr, target_cpu=self.cpu) is not None:
                malloc_rec = self.MallocRec('malloc', tid, size, cpu.cycles)
                malloc_ret_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, ret_addr, 1, 0)
                self.malloc_hap_ret = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.mallocEndHap, malloc_rec, malloc_ret_break, 'malloc_end')
            else:
                fun = self.fun_mgr.getFun(ret_addr)
                self.lgr.debug('TraceMalloc mallocHap ret_addr 0x%x is CLIB, skip it cycle 0x%x fun: %s' % (ret_addr, self.cpu.cycles, fun))
    def callocHap(self, dumb, context, break_num, memory):
        if self.calloc_hap is not None:
            cpu, comm, tid = self.task_utils.curThread() 
            self.lgr.debug('TraceMalloc callocHap tid:%s' % tid)
            if self.comm is not None and self.comm != comm:
                return
            if cpu.architecture == 'arm':
                nmemb = self.mem_utils.getRegValue(self.cpu, 'r0') 
                size = self.mem_utils.getRegValue(self.cpu, 'r1') * nmemb
                #self.lgr.debug('malloc size %d' % size)
                ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr') 
            elif cpu.architecture == 'arm64':
                nmemb = self.mem_utils.getRegValue(self.cpu, 'x0') 
                size = self.mem_utils.getRegValue(self.cpu, 'x1') * nmemb
                #self.lgr.debug('malloc size %d' % size)
                ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr') 
            elif cpu.architecture == 'ppc32':
                nmemb = self.mem_utils.getRegValue(self.cpu, 'r3') 
                size = self.mem_utils.getRegValue(self.cpu, 'r4') * nmemb
                self.lgr.debug('malloc size %d' % size)
                ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr') 
            else:
                sp = self.mem_utils.getRegValue(self.cpu, 'sp')
                ret_addr = self.mem_utils.readPtr(self.cpu, sp)
                nmemb = self.mem_utils.readWord32(self.cpu, sp+self.mem_utils.WORD_SIZE)
                size = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.WORD_SIZE) * nmemb
                #self.lgr.debug('TraceMalloc mallocHap malloc size %d ret_addr 0x%x cycle 0x%x' % (size, ret_addr, self.cpu.cycles))
            if not self.top.isLibc(ret_addr, target_cpu=self.cpu) and self.top.getSO(ret_addr, target_cpu=self.cpu) is not None:
                malloc_rec = self.MallocRec('calloc', tid, size, cpu.cycles)
                malloc_ret_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, ret_addr, 1, 0)
                self.malloc_hap_ret = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.mallocEndHap, malloc_rec, malloc_ret_break, 'malloc_end')
            else:
                self.lgr.debug('TraceMalloc callocHap ret_addr 0x%x is CLIB, skip it cycle 0x%x' % (ret_addr, self.cpu.cycles))

    def reallocHap(self, dumb, context, break_num, memory):
        if self.realloc_hap is not None:
            cpu, comm, tid = self.task_utils.curThread() 
            self.lgr.debug('TraceMalloc reallocHap tid:%s' % tid)
            ptr = None
            if self.comm is not None and self.comm != comm:
                return
            if cpu.architecture == 'arm':
                ptr = self.mem_utils.getRegValue(self.cpu, 'r0') 
                size = self.mem_utils.getRegValue(self.cpu, 'r1') 
                #self.lgr.debug('malloc size %d' % size)
                ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr') 
            elif cpu.architecture == 'arm64':
                ptr = self.mem_utils.getRegValue(self.cpu, 'x0') 
                size = self.mem_utils.getRegValue(self.cpu, 'x1') 
                #self.lgr.debug('malloc size %d' % size)
                ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr') 
            elif cpu.architecture == 'ppc32':
                ptr = self.mem_utils.getRegValue(self.cpu, 'r3') 
                size = self.mem_utils.getRegValue(self.cpu, 'r4') 
                self.lgr.debug('malloc size %d' % size)
                ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr') 
            else:
                sp = self.mem_utils.getRegValue(self.cpu, 'sp')
                ret_addr = self.mem_utils.readPtr(self.cpu, sp)
                ptr = self.mem_utils.readWord32(self.cpu, sp+self.mem_utils.WORD_SIZE)
                size = self.mem_utils.readWord32(self.cpu, sp+2*self.mem_utils.WORD_SIZE)
                #self.lgr.debug('TraceMalloc mallocHap malloc size %d ret_addr 0x%x cycle 0x%x' % (size, ret_addr, self.cpu.cycles))
            if not self.top.isLibc(ret_addr, target_cpu=self.cpu) and self.top.getSO(ret_addr, target_cpu=self.cpu) is not None:
                malloc_rec = self.MallocRec('realloc', tid, size, cpu.cycles, realloc_ptr=ptr)
                malloc_ret_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, ret_addr, 1, 0)
                self.malloc_hap_ret = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.mallocEndHap, malloc_rec, malloc_ret_break, 'malloc_end')
                if ptr in self.current_malloc:
                    del self.current_malloc[ptr] 
            else:
                self.lgr.debug('TraceMalloc mallocHap ret_addr 0x%x is CLIB, skip it cycle 0x%x' % (ret_addr, self.cpu.cycles))

    def freeHap(self, dumb, context, break_num, memory):
        if self.free_hap is not None:
            cpu, comm, tid = self.task_utils.curThread() 
            #self.lgr.debug('TraceMalloc freeHap tid:%s cycle 0x%x' % (tid, self.cpu.cycles))
            if cpu.architecture == 'arm':
                addr = self.mem_utils.getRegValue(self.cpu, 'r0') 
                ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr') 
                #self.lgr.debug('free addr 0x%x' % addr)
            elif cpu.architecture == 'arm64':
                addr = self.mem_utils.getRegValue(self.cpu, 'x0') 
                ret_addr = self.mem_utils.getRegValue(self.cpu, 'lr') 
            else:
                sp = self.mem_utils.getRegValue(self.cpu, 'sp')
                addr = self.mem_utils.readPtr(self.cpu, sp+self.mem_utils.WORD_SIZE)
                ret_addr = self.mem_utils.readPtr(self.cpu, sp)
                #self.lgr.debug('free addr 0x%x' % addr)
            if not self.top.isLibc(ret_addr, target_cpu=self.cpu) and self.top.getSO(ret_addr, target_cpu=self.cpu) is not None:
                self.dataWatch.recordFree(addr)
                if self.trace_mgr is not None:
                    msg = 'free 0x%x tid:%s (%s)' % (addr, tid, comm)
                    self.trace_mgr.write(msg)
                if self.callback is not None:
                    self.callback('free', addr)
            if addr in self.current_malloc:
                del self.current_malloc[addr] 
                self.lgr.debug('TraceMalloc freeHap ********* freed 0x%x' % addr)
            else:
                self.lgr.debug('TraceMalloc freeHap add 0x%x not in current_malloc' % addr)
            #else:
            #    self.lgr.debug('TraceMalloc freeHap ret_addr 0x%x is CLIB, skip it cycle 0x%x' % (ret_addr, self.cpu.cycles))

    def mallocEndHap(self, malloc_rec, context, break_num, memory):
        if self.malloc_hap_ret is not None:
            cpu, comm, tid = self.task_utils.curThread() 
            self.lgr.debug('TraceMalloc mallocEndHap tid:%s cycle 0x%x' % (tid, self.cpu.cycles))
            if cpu.architecture == 'arm':
                addr = self.mem_utils.getRegValue(self.cpu, 'r0') 
                #self.lgr.debug('malloc addr 0x%x' % addr)
            elif cpu.architecture == 'arm64':
                addr = self.mem_utils.getRegValue(self.cpu, 'x0') 
                #self.lgr.debug('malloc addr 0x%x' % addr)
            elif cpu.architecture == 'ppc32':
                addr = self.mem_utils.getRegValue(self.cpu, 'r3') 
                self.lgr.debug('TraceMalloc mallocEndHap addr 0x%x' % addr)
            else:
                addr = self.mem_utils.getRegValue(self.cpu, 'eax') 
                #self.lgr.debug('TraceMalloc mallocEndHap addr 0x%x, size: %d' % (addr, malloc_rec.size))
            malloc_rec.addr = addr
            self.malloc_list.append(malloc_rec)
            self.current_malloc[addr] = malloc_rec
            self.context_manager.genDeleteHap(self.malloc_hap_ret)
            self.malloc_hap_ret = None
            self.dataWatch.recordMalloc(addr, malloc_rec.size)
            if self.trace_mgr is not None:
                if malloc_rec.realloc_ptr is not None:
                    msg = '%s 0x%x size 0x%x freed: 0x%x tid:%s (%s)' % (malloc_rec.fun, addr, malloc_rec.size, malloc_rec.realloc_ptr, tid, comm)
                else:
                    msg = '%s 0x%x size 0x%x tid:%s (%s)' % (malloc_rec.fun, addr, malloc_rec.size, tid, comm)
                self.trace_mgr.write(msg)
            if self.callback is not None:
                if malloc_rec.realloc_ptr is not None:
                    self.callback('realloc', addr, size=malloc_rec.size)
                else:
                    self.callback('malloc', addr, size=malloc_rec.size)

    def showList(self):
        for rec in self.malloc_list:
            print('%4s \t0x%x\t%d' % (rec.tid, rec.addr, rec.size))
        print('Current Malloc:')
        for addr in self.current_malloc:
            rec = self.current_malloc[addr] 
            print('Current: %4s \t0x%x\t%d' % (rec.tid, rec.addr, rec.size))

    def saveJson(self):
        jlist = []
        for addr in self.current_malloc:
            rec = self.current_malloc[addr] 
            jrec = {}
            jrec['tid'] = rec.tid
            jrec['addr'] = rec.addr
            jrec['size'] = rec.size
            jlist.append(jrec)
        with open('/tmp/alloc.json', 'w') as fh:
            fh.write(json.dumps(jlist))
