import ntpath
import os
import subprocess
import shlex
from resimHaps import *
from simics import *

def getTextSection(cpu, mem_utils, eproc, lgr):
        retval = None
        ''' TBD put in params! '''
        peb_addr = eproc+0x338
        lgr.debug('winProg getTextSection eproc 0x%x pep_addr 0x%x' % (eproc, peb_addr))
        peb = mem_utils.readPtr(cpu, peb_addr)
        if peb is not None:
            image_load_addr_addr = peb + 0x10
            lgr.debug('winProg getTextSection pep 0x%x addr_addr 0x%x' % (peb, image_load_addr_addr))
            retval = mem_utils.readWord(cpu, image_load_addr_addr)
        else:
            lgr.error('winProg getTextSection pep read as None')
        return retval

def getTextSize(full_path, lgr):
    size = None
    if full_path is None:
        return None
    if os.path.isfile(full_path):
        cmd = 'readpe -H %s' % full_path
        grep = 'grep "Size of .text section"'
        proc1 = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc2 = subprocess.Popen(shlex.split(grep),stdin=proc1.stdout,
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE)

        proc1.stdout.close() # Allow proc1 to receive a SIGPIPE if proc2 exits.
        out,err=proc2.communicate()
        #print(out)
        addr = None
        size = 0
        for line in out.splitlines():
            lgr.debug('winProg readpe got %s' % line)
            parts = line.split()
            size_s = parts[4]
            try:
                size = int(size_s, 16)
                break
            except:
                pass
    else:
        lgr.error('winProg getTextSize, no file at %s' % full_path)
    return size

class WinProg():
    def __init__(self, top, cpu, mem_utils, task_utils, context_manager, so_map, stop_action, param, lgr):
        self.top = top
        self.cpu = cpu
        self.mem_utils = mem_utils
        self.lgr = lgr
        self.task_utils = task_utils
        self.so_map = so_map
        self.context_manager = context_manager
        self.param = param
        self.stop_action = stop_action
        self.prog_string = None
        self.text_hap = None

    def toNewProc(self, prog_string):
        self.prog_string = prog_string
        self.lgr.debug('toNewProc %s' % prog_string)
        phys_current_task = self.task_utils.getPhysCurrentTask()
        self.cur_task_break = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             phys_current_task, self.mem_utils.WORD_SIZE, 0)
        self.cur_task_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.toNewProcHap, prog_string, self.cur_task_break)
        self.current_tasks = self.task_utils.getTaskList()
        #SIM_run_alone(SIM_continue, 0)

    def toNewProcHap(self, prog_string, third, forth, memory):
        ''' We should be in the new process '''
        if self.cur_task_hap is None:
            return
        #self.lgr.debug('winProg toNewProcHap for proc %s' % proc)
        cur_thread = SIM_get_mem_op_value_le(memory)
        cur_proc = self.task_utils.getCurTaskRec(cur_thread_in=cur_thread)
        pid_ptr = cur_proc + self.param.ts_pid
        pid = self.mem_utils.readWord(self.cpu, pid_ptr)
        self.context_manager.newProg(prog_string, pid)
        if cur_proc not in self.current_tasks:
            comm = self.mem_utils.readString(self.cpu, cur_proc+self.param.ts_comm, 16)
            proc = ntpath.basename(prog_string)
            self.lgr.debug('winProg does %s start with %s?' % (proc, comm))
            if proc.startswith(comm):
                self.lgr.debug('winProg toNewProcHap got new %s pid:%d' % (comm, pid))
                SIM_run_alone(self.rmNewProcHap, self.cur_task_hap)
                self.cur_task_hap = None
                self.task_utils.addProgram(pid, prog_string)
                self.context_manager.addTask(pid)

                self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.findText, pid)

                '''
                find_text = stopFunction.StopFunction(self.findText, [], nest=False)
                new_fun = stopFunction.StopFunction(self.context_manager.watchTasks, [True], nest=False)
                if self.stop_action is not None:
                    flist = self.stop_action.getFlist()
                    flist.append(find_text)
                    flist.append(new_fun)
                else:
                    flist = [find_text]
                    flist = [new_fun]

                load_addr = self.findText(cur_proc)
                #SIM_run_alone(self.top.toUser, flist)
                SIM_run_alone(self.stopTrace, False)
                SIM_break_simulation('got new proc %s' % proc)
                '''

    def rmNewProcHap(self, newproc_hap):
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", newproc_hap)
        if self.cur_task_break is not None:
            SIM_delete_breakpoint(self.cur_task_break)
            self.cur_task_break = None

    def rmFindTextHap(self, dumb):
        RES_hap_delete_callback_id("Core_Mode_Change", self.mode_hap)

    def findText(self, want_pid, one, old, new):
        if self.mode_hap is None:
            return
        cpu, comm, this_pid = self.task_utils.curProc() 
        if want_pid != this_pid:
            self.lgr.debug('findText, mode changed but wrong pid, wanted %d got %d' % (want_pid, this_pid))
            return
        self.lgr.debug('winProg findText')
        SIM_run_alone(self.rmFindTextHap, None)
        eproc = self.task_utils.getCurTaskRec()
        load_addr = getTextSection(self.cpu, self.mem_utils, eproc, self.lgr)
        self.lgr.debug('winProg findText load_addr 0x%x' % load_addr)
        print('Program %s image base is 0x%x' % (self.prog_string, load_addr))
        self.top.debugExitHap()
        full_path = self.top.getFullPath(fname=self.prog_string)
        self.lgr.debug('winProg got full_path %s from prog %s' % (full_path, self.prog_string))
        self.top.setFullPath(full_path)
        size = getTextSize(full_path, self.lgr)
        if size is None:
            self.lgr.error('winProg findText unable t get size.  Is path to executable defined in the ini file RESIM_root_prefix?')
            self.top.quit()
            return 
        self.lgr.debug('winProg findText got size 0x%x' % size)
        self.so_map.addText(self.prog_string, want_pid, load_addr, size)
        proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, load_addr, size, 0)
        self.text_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.textHap, None, proc_break, 'text_hap')

    def textHap(self, dumb, third, forth, memory):
        self.context_manager.genDeleteHap(self.text_hap)
        SIM_run_alone(self.top.stopAndAction, self.stop_action)
