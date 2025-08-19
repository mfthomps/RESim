from simics import *
import memUtils
class TaskSwitches():
    def __init__(self, cpu, mem_utils, task_utils, param, lgr):
        self.mem_utils = mem_utils
        self.cpu = cpu
        self.param = param
        self.task_utils = task_utils
        self.lgr = lgr
        self.switch_hap = None
        phys_current_task = self.task_utils.getPhysCurrentTask()
        proc_break = SIM_breakpoint(cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             phys_current_task, self.mem_utils.WORD_SIZE, 0)
        self.lgr.debug('taskSwitches set break at 0x%x' % (phys_current_task))
        self.switch_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.switchHap, None, proc_break)

    def switchHap(self, dumb, third, forth, memory):
        ''' callback when current_task is updated.  new value is in memory parameter '''
        if self.switch_hap is None:
            return
        cur_task_rec = memUtils.memoryValue(self.cpu, memory)
        pid = self.mem_utils.readWord32(self.cpu, cur_task_rec + self.param.ts_pid)
        if pid != 0:
            comm = self.mem_utils.readString(self.cpu, cur_task_rec + self.param.ts_comm, 16)
            self.lgr.debug('got proc %s pid is %d' % (comm, pid))
