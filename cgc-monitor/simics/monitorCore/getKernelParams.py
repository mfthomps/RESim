from simics import *
#import linux4_4_32
import linuxParams
import memUtils
import taskUtils
import utils
target = 'VDR'
class cellConfig():
    '''
    Manage the Simics simulation cells (boxes), CPU's (processor cores).
    TBD -- clean up once multi-box strategy evolves, e.g., could there be
    multiple CPUs per cell?  
    '''
    cells = {}
    cell_cpu = {}
    cell_cpu_list = {}
    cell_context = {}
    def __init__(self):
        self.loadCellObjects()

    def loadCellObjects(self):
        first_box = target 
        self.cells[first_box] = 'vdr host'
        for cell_name in self.cells:
            obj = SIM_get_object(cell_name)
            self.cell_context[cell_name] = obj.cell_context

        for cell_name in self.cells:
            cmd = '%s.get-processor-list' % cell_name
            proclist = SIM_run_command(cmd)
            self.cell_cpu[cell_name] = SIM_get_object(proclist[0])
            self.cell_cpu_list[cell_name] = []
            for proc in proclist:
                self.cell_cpu_list[cell_name].append(SIM_get_object(proc))
    def cpuFromCell(self, cell_name):
        ''' simplification for single-core sims '''
        return self.cell_cpu[cell_name]

class TaskStruct(object):
    """The interesting information contained in a task_struct."""
    __slots__ = ['addr',
     'state',
     'tasks',
     'binfmt',
     'pid',
     'tgid',
     'comm',
     'real_parent',
     'parent',
     'children',
     'sibling',
     'group_leader',
     'thread_group',
     'active_mm',
     'mm',
     'good',
     'in_main_list',
     'in_sibling_list']

    def __init__(self, **kw):
        self.in_main_list = False
        self.in_sibling_list = None
        for k, v in kw.items():
            setattr(self, k, v)

    def __str__(self):
        return 'TaskStruct(%s)' % (', '.join(('%s = %s' % (slot, getattr(self, slot, None)) for slot in self.__slots__)),)

    def __repr__(self):
        return self.__str__()

    @property
    def next(self):
        return self.tasks.next

    @property
    def prev(self):
        return self.tasks.prev

class Kparams():
    def __init__(self):
        ''' assumptions '''
        #self.kernel_base = 3221225472
        self.kernel_base = 0xc0000000
        self.ram_base = 0
        self.stack_size = 8192
        self.ts_next_relative = True
        self.ts_state = None
        self.ts_active_mm = None
        self.ts_mm = None
        self.ts_binfmt = None
        self.ts_group_leader = None

        self.ts_next = None
        self.ts_prev = None
        self.ts_pid = None
        self.ts_comm = None
        self.ts_real_parent = None
        self.ts_parent = None
        self.ts_children_list_head = None
        self.ts_sibling_list_head = None
        self.ts_thread_group_list_head = None
        self.current_task = 0xc2001454


class GetKernelParams():
    def __init__(self):
        self.cell_config = cellConfig()
        self.log_dir = '/tmp'
        self.lgr = utils.getLogger('noname', os.path.join(self.log_dir, 'getKernelParams.txt'))
        #self.param = linux4_4_32.linuxParams()
        self.param = Kparams()
        self.real_param = linuxParams.linuxParams()
        self.mem_utils = memUtils.memUtils(4, self.real_param)
        #self.cpu = SIM_current_processor()
        self.cpu = self.cell_config.cpuFromCell(target)
        print('current processor %s' % self.cpu.name)
        #self.taskUtils = taskUtils.TaskUtils(self.cpu, self.param, self.mem_utils, self.param.current_task, self.lgr)
        self.hits = []
        self.trecs = []
        self.idle = None
        self.dumb_count = 0

    def searchCurrentTaskAddr(self, cpu, cur_task, fs=True):
        ''' Look for the Linux data addresses corresponding to the current_task symbol 
            starting at 0xc1000000.  Record each address that contains a match,
            and that list will be reduced later. 
        '''
        #self.run2Kernel(cpu)
        self.lgr.debug('searchCurrentTaskAddr task for task 0x%x fs: %r' % (cur_task, fs))
        start = 0xc1000000
        SIM_run_command('pselect cpu-name = %s' % cpu.name)
        if fs:
            cmd = 'logical-to-physical fs:0x%x' % start
        else:
            cmd = 'logical-to-physical 0x%x' % start
        #print('cmd is %s' % cmd)
        cpl = memUtils.getCPL(cpu)
        #print('cpl is %d' % cpl)
        addr = SIM_run_command(cmd)
        print('starting at 0x%x' % addr)
        got_count = 0
        offset = 0
        for i in range(14000000):
            val = None
            try:
                val = SIM_read_phys_memory(cpu, addr, 4)
            except:
                pass
            #val = self.mem_utils.readPtr(cpu, addr)
            if val is None:
                self.lgr.error('got None at 0x%x' % addr)
                return 
            if val == cur_task:
                vaddr = start+offset
                self.lgr.debug('got match at addr: 0x%x vaddr: 0x%x' % (addr, vaddr))
                self.hits.append(vaddr)
                got_count += 1
                #break
            if got_count == 9999:
                self.lgr.error('exceeded count')
                break
            #print('got 0x%x from 0x%x' % (val, addr))
            addr += 4
            offset += 4
        self.lgr.debug('final addr is 0x%x num hits %d' % ((start+offset), len(self.hits)))

    def checkHits(self, cur_task):
        ''' look at previously generated list of candidate current_task addresses and remove any
            that do not contain the given cur_task '''
        copy_hits = list(self.hits)
        for hit in copy_hits:
            cmd = 'logical-to-physical fs:0x%x' % hit
            addr = SIM_run_command(cmd)
            val = SIM_read_phys_memory(self.cpu, addr, 4)
            if val != cur_task:
                print('bad hit at 0x%x, removing' % hit)
                self.hits.remove(hit)
            

    def getCurrentTask(self, param, cpu):
        cpl = memUtils.getCPL(cpu)
        if cpl == 0:
            tr_base = cpu.tr[7]
            esp = self.mem_utils.readPtr(cpu, tr_base + 4)
            if esp is None:
                return None
            #print('kernel mode, esp is 0x%x' % esp)
        else:
            esp = self.mem_utils.getRegValue(cpu, 'esp')
            #print('user mode, esp is 0x%x' % esp)
        ptr = esp - 1 & ~(param.stack_size - 1)
        ret_ptr = self.mem_utils.readPtr(cpu, ptr)
        #print('ret_ptr is 0x%x' % ret_ptr)

        return ret_ptr

    
    def getCurrentTaskPtr(self):
        self.idle = None
        print('getCurrentTaskPtr')
        for i in range(900000):
            cpl = memUtils.getCPL(self.cpu)
            if cpl != 0:
                #print('no in pl0')
                continue
            ta = self.getCurrentTask(self.param, self.cpu)
            if ta in self.trecs:
                #print('already in trec')
                continue
            self.trecs.append(ta)
            self.lgr.debug('getCurrentTaskPtr adding trec 0x%x' % ta)
            if len(self.hits) == 0:
                print('find current')
                self.searchCurrentTaskAddr(self.cpu, ta)
                if len(self.hits)<3:
                    ''' maybe older kernel, we assumed those with fs relative will have many hits '''
                    self.hits = []
                    self.searchCurrentTaskAddr(self.cpu, ta, fs=False)
                 
            else:
                self.checkHits(ta)

            if len(self.hits) < 3:
                print('remaining hits')
                for hit in self.hits:
                    print('0x%x' % hit)
                self.param.current_task = self.hits[0]
                break
            SIM_run_command('c 500000')
        if len(self.hits) > 2:
            ''' maybe in tight application loop, assume second to last entry based on observations '''
            self.param.current_task = self.hits[-2]
            self.lgr.debug('assuming 2nd to last for current_task')

    def isThisSwapper(self, task):
        real_parent_offset = 0
        for i in range(800):
            test_task = self.mem_utils.readPtr(self.cpu, task + real_parent_offset)
            test_task1 = self.mem_utils.readPtr(self.cpu, task + real_parent_offset+4)
            if test_task == task and test_task1 == task:
                return real_parent_offset
            else:
                real_parent_offset += 4
        return None

    def isSwapper(self, task): 
        ''' look for what might be a real_parent and subsequent parent pointer fields that point to the
            given task.  if found, assume this is swaper and record those offsets.'''
        real_parent_offset = self.isThisSwapper(task)
        if real_parent_offset is not None:
            self.idle = task
            self.param.ts_real_parent = real_parent_offset
            self.param.ts__parent = real_parent_offset + 4
            self.param.ts_children_list_head = real_parent_offset + 8
            self.param.ts_sibling_list_head = real_parent_offset + 16
            self.param.ts_thread_group_list_head = real_parent_offset + 32
        return real_parent_offset
       
    def changedThread(self, cpu, third, forth, memory):
        ''' does the current thread look like swapper? would have consecutive pointers to itself '''
        if self.task_break is None:
            return
        cur_task = self.mem_utils.readPtr(self.cpu, self.param.current_task)
        if cur_task not in self.trecs:
            self.trecs.append(cur_task)
            if self.isSwapper(cur_task) is not None:
                print('is swapper 0x%x  real_parent %d' % (self.idle, self.param.ts_real_parent))
                SIM_break_simulation('found swapper')
                SIM_delete_breakpoint(self.task_break)
                self.task_break = None 
                return 
              
    
    def runUntilSwapper(self):
        ''' run until it appears that the swapper is running.  Will set self.idle, real_parent, siblings '''
        if self.param.current_task is None:
            self.getCurrentTaskPtr()
        #idle = self.taskUtils.findSwapper(self.current_task, self.cpu)
        #print('real swapper is 0x%x' % idle)
        self.trecs = []
        cell = self.cell_config.cell_context[target]
        self.task_break = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Write, self.param.current_task, self.mem_utils.WORD_SIZE, 0)
        self.task_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.changedThread, self.cpu, self.task_break)
        SIM_run_command('c')
     

    def getInit(self):
        ''' Assuming we have swapper in init.idle, find init and use it to locate
            next, prev, pid and comm '''
        #print('real_parent is %d  children %d' % (self.param.ts_real_parent, self.param.ts_children_list_head))
        swapper_child = self.mem_utils.readPtr(self.cpu, self.idle+self.param.ts_children_list_head) 
        #print('swapper_child_next is 0x%x  sib %d' % (swapper_child, self.param.ts_sibling_list_head))
        init = swapper_child - self.param.ts_sibling_list_head
        print('init is 0x%x' % init)
        next_offset = 20
        print('real next is %d' % self.real_param.ts_next)
        for i in range(800):
            swap_next = self.mem_utils.readPtr(self.cpu, self.idle + next_offset) - next_offset
            if swap_next == init:
                print('think next is %d' % next_offset)
                self.param.ts_next = next_offset
                self.param.ts_prev = next_offset + 4
                break
            else:
                next_offset += 4

        print('real pid is %d' % self.real_param.ts_pid)
        if self.param.ts_next is not None:
            init_next_ptr = self.mem_utils.readPtr(self.cpu, init + self.param.ts_next) 
            init_next = init_next_ptr - self.param.ts_next
            print('ts_next %d  ptr 0x%x init_next is 0x%x' % (self.param.ts_next, init_next_ptr, init_next))
            pid_offset = 0
            init_pid = 0
            next_pid = 0
            for i in range(800):
                init_pid = self.mem_utils.readWord32(self.cpu, init+pid_offset)
                next_pid = self.mem_utils.readWord32(self.cpu, init_next+pid_offset)
                init_pid_g = self.mem_utils.readWord32(self.cpu, init+pid_offset+4)
                next_pid_g = self.mem_utils.readWord32(self.cpu, init_next+pid_offset+4)
                if init_pid == 1 and next_pid == 2 and init_pid_g ==1 and next_pid_g == 2:
                    print('got 1 at offset %d' % pid_offset)
                    self.param.ts_pid = pid_offset
                    self.param.ts_tgid = pid_offset+4
                    break
                pid_offset += 4

        if self.param.ts_pid is not None:
            comm_offset = self.param.ts_pid+8
            print('real comm at %d' % (self.real_param.ts_comm))
            for i in range(800):
                
                comm = self.mem_utils.readString(self.cpu, init+comm_offset, 16)
                if comm == 'init':
                    print('found comm at %d' % comm_offset)
                    self.ts_comm = comm_offset
                    break
                comm_offset += 4
            
        return init

    def checkTasks(self):        
        self.taskUtils = taskUtils.TaskUtils(self.cpu, self.param, self.mem_utils, self.param.current_task, self.lgr)
        swapper_child = self.mem_utils.readPtr(self.cpu, self.idle+self.param.ts_children_list_head) 
        #print('swapper_child_next is 0x%x  sib %d' % (swapper_child, self.param.ts_sibling_list_head))
        init = swapper_child - self.param.ts_sibling_list_head
        ts = self.taskUtils.readTaskStruct(init, self.cpu)
        print('pid is %d' % ts.pid)
     

if __name__ == '__main__':
    gkp = GetKernelParams()
    #SIM_run_command('enable-real-time-mode')
    #gkp.getCurrentTaskPtr()
    gkp.runUntilSwapper()
    #gkp.mft()
    gkp.getInit()
    gkp.checkTasks()
    #gkp.findNext()
    #gkp.testNext()
