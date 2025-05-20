import ntpath
import os
import subprocess
import shlex
try:
    from resimHaps import *
    from simics import *
except:
    # if loaded from script like findBNT.py
    pass

PEB_ADDR = 0x338
class WinProgInfo():
    def __init__(self, load_addr, text_offset, text_size, machine, image_base):
        self.load_addr = load_addr
        self.text_offset = text_offset
        self.text_size = text_size
        self.machine = machine
        self.image_base = image_base

# match linux structure for use by utils like findBNT
class Text():
    def __init__(self, address, offset, size):
        self.address = address
        self.offset = offset
        self.size = size
        self.locate = None
        self.text_start = None
        self.text_size = None
        self.text_offset = None

    def setText(self, address, size, offset):
        self.text_start = address
        self.text_size = size
        self.text_offset = offset

def getWinProgInfo(cpu, mem_utils, eproc, full_path, lgr):
    load_address = None
    if eproc is not None:
        load_address = getLoadAddress(cpu, mem_utils, eproc, full_path, lgr)
    text_size, machine, image_base, text_offset = getSizeAndMachine(full_path, lgr)
    return WinProgInfo(load_address, text_offset, text_size, machine, image_base)

def getLoadAddress(cpu, mem_utils, eproc, prog, lgr):
        retval = None
        ''' TBD put in params! '''
        peb_addr = eproc+PEB_ADDR
        lgr.debug('winProg getLoadAddress eproc 0x%x pep_addr 0x%x prog %s' % (eproc, peb_addr, prog))
        peb = mem_utils.readPtr(cpu, peb_addr)
        if peb is not None:
            image_load_addr_addr = peb + 0x10
            lgr.debug('winProg getLoadAddress pep 0x%x addr_addr 0x%x' % (peb, image_load_addr_addr))
            retval = mem_utils.readWord(cpu, image_load_addr_addr)
            if retval is None:
                lgr.debug('winProg getLoadAddress got None reading 0x%x' % image_load_addr_addr)
            else:
                lgr.debug('winProg getLoadAddress got load addr 0x%x reading 0x%x' % (retval, image_load_addr_addr))
        else:
            lgr.error('winProg getLoadAddress pep read as None')
        return retval

def getSizeAndMachine(full_path, lgr):
    size = None
    machine = None
    image_base = None
    addr_of_text = None
    lgr.debug('winProg getSizeAndMachine for %s' % full_path)
    if full_path is None:
        lgr.warning('winProg getSizeAndMachine called with full_path of None')
        return None, None, None, None
    if os.path.isfile(full_path):
        lgr.debug('is it a real path that exists')
        cmd = 'readpe -H "%s"' % full_path
        with subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as ps:
            output = ps.communicate()
            for line in output[0].decode("utf-8").splitlines():
                if 'ImageBase:' in line: 
                    parts = line.split()
                    image_base_s = parts[1]
                    try:
                        image_base = int(image_base_s, 16)
                        break
                    except:
                        lgr.error('winProg getSizeAndMachine failed to get image base from %s' % line)
                if 'Address of .text section' in line: 
                    #lgr.debug('winProg readpe got %s' % line)
                    parts = line.split()
                    addr_s = parts[4]
                    try:
                        addr_of_text = int(addr_s, 16)
                    except:
                        lgr.error('winProg getSizeAndMachine failed to get size from %s' % line)
                if 'Size of .text section' in line: 
                    lgr.debug('winProg readpe got %s' % line)
                    parts = line.split()
                    size_s = parts[4]
                    try:
                        size = int(size_s, 16)
                    except:
                        lgr.error('winProg getSizeAndMachine failed to get size from %s' % line)
                elif 'Machine' in line:
                    parts = line.split()
                    machine = parts[2]
            if size is None:
                lgr.error('winProg getSizeAndMachine failed to get size for path %s' % full_path)
    else:
        lgr.debug('winProg getSizeAndMachine failed find file at path %s' % full_path)
    return size, machine, image_base, addr_of_text

def getText(full_path, lgr):
    size, machine, image_base, text_offset = getSizeAndMachine(full_path, lgr)
    # TBD fix binary size vs text size
    retval = Text(image_base, text_offset, size)
    retval.text_size = size
    retval.text_start = image_base
    return retval

def getRelocate(full_path, lgr):
    ''' This is not used.  See IDA resimUtils for dumpImports. '''
    lgr.debug('winProg getRelocate for %s' % full_path)
    if full_path is None:
        lgr.warning('winProg getRelocate called with full_path of None')
        return None
    retval = {}
    if os.path.isfile(full_path):
        cmd = 'readpe -d -i %s' % full_path
        lgr.debug('cmd %s' % cmd)
        with subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as ps:
            output = ps.communicate()
            library = None
            get_library = False
            for line in output[0].decode("utf-8").splitlines():
                if 'IMAGE_DIRECTORY_ENTRY_IMPORT:' in line: 
                    parts = line.split()
                    import_base_s = parts[1]
                    try:
                        import_base = int(import_base_s, 16)
                        lgr.debug('got import base 0x%x' % import_base)
                    except:
                        lgr.error('winProg getRelocate failed to get import base from %s' % line)
                else:
                    parts = line.split()
                    if parts[0].strip() == 'Library':
                        get_library = True
                        lgr.debug('get library')
                    elif parts[0].strip() == 'Hint:':
                        entry = int(parts[1].strip())
                    elif parts[0].strip() == 'Name:':
                        if get_library:
                            library = parts[1].strip()
                            retval[library] = {}
                            get_library = False
                        else:
                            fun = parts[1].strip()
                            retval[library][fun] = entry
    for lib in retval:
        lgr.debug('Library: %s' % lib)
        for fun in retval[lib]:
            lgr.debug('\t%s  0x%x' % (fun, retval[lib][fun]))

                    

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
        ''' Assumes this is running  alone  and nothing is being debugged '''
        self.prog_string = prog_string
        self.lgr.debug('toNewProc %s' % prog_string)
        self.top.rmSyscall('toCreateProc')
        phys_current_task = self.task_utils.getPhysCurrentTask()
        self.cur_task_break = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             phys_current_task, self.mem_utils.WORD_SIZE, 0)
        self.cur_task_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.toNewProcHap, prog_string, self.cur_task_break)
        self.current_tasks = self.task_utils.getTaskList()
        #SIM_run_alone(SIM_continue, 0)

    def toNewProcHap(self, prog_string, third, forth, memory):
        ''' We might be in the new process '''
        if self.cur_task_hap is None:
            return
        #self.lgr.debug('winProg toNewProcHap for proc %s' % prog_string)
        cur_thread = SIM_get_mem_op_value_le(memory)
        tid, comm = self.task_utils.getTidCommFromThreadRec(cur_thread)
        self.context_manager.newProg(prog_string, tid)
        cur_proc = self.task_utils.getCurProcRec(cur_thread_in=cur_thread)
        if cur_proc not in self.current_tasks:
            proc = ntpath.basename(prog_string)
            self.lgr.debug('winProg does %s start with %s?' % (proc, comm))
            if proc.startswith(comm):
                self.lgr.debug('winProg toNewProcHap got new %s tid:%s' % (comm, tid))
                SIM_run_alone(self.rmNewProcHap, self.cur_task_hap)
                self.cur_task_hap = None
                self.task_utils.addProgram(tid, prog_string)
                self.context_manager.addTask(tid)

                self.mode_hap = RES_hap_add_callback_obj("Core_Mode_Change", self.cpu, 0, self.findText, tid)

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

    def runToText(self, want_tid):
        self.lgr.debug('winProg runToText want_tid %s' % want_tid)
        eproc = self.task_utils.getCurProcRec()
        load_addr = getLoadAddress(self.cpu, self.mem_utils, eproc, self.prog_string, self.lgr)
        if load_addr is None:
            self.lgr.error('winprog failed to get load addess for %s' % want_tid)
            return
        self.lgr.debug('winProg runToText load_addr 0x%x' % load_addr)
        print('Program %s image base is 0x%x' % (self.prog_string, load_addr))
        self.context_manager.setDebugTid()
        self.top.debugExitHap()
        full_path = self.top.getFullPath(fname=self.prog_string)
        self.lgr.debug('winProg got full_path %s from prog %s' % (full_path, self.prog_string))
        self.top.setFullPath(full_path)
        size, machine, image_base, text_offset = getSizeAndMachine(full_path, self.lgr)
        if size is None:
            self.lgr.error('winProg runToText unable to get size.  Is path to executable defined in the ini file RESIM_root_prefix?')
            self.top.quit()
            return 
        text_addr = load_addr + text_offset
        self.lgr.debug('winProg runToText got size 0x%x' % size)
        self.so_map.addText(self.prog_string, want_tid, load_addr, size, machine, image_base, text_offset, full_path)
        self.top.trackThreads()
        proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, text_addr, size, 0)
        want_pid = want_tid.split('-')[0]
        self.text_hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.textHap, want_pid, proc_break, 'text_hap')
        self.lgr.debug('winProg runToText set break at 0x%x size 0x%x context %s' % (text_addr, size, self.cpu.current_context))

    def findText(self, want_tid, one, old, new):
        if self.mode_hap is None:
            return
        cpu, comm, this_tid = self.task_utils.curThread() 
        if want_tid != this_tid:
            #self.lgr.debug('findText, mode changed but wrong tid, wanted %s got %s' % (want_tid, this_tid))
            return
        self.lgr.debug('winProg findText tid %s' % this_tid)
        SIM_run_alone(self.rmFindTextHap, None)
        SIM_run_alone(self.runToText, want_tid)

    def rmHapAlone(self, param_name):
        self.top.rmSyscall(param_name, context = self.context_manager.getDefaultContextName())

    def debugAlone(self, dumb=None):
        self.lgr.debug('winMonitor debugAlone, call top debug')
        SIM_run_alone(self.top.debug, False)

    def textHap(self, pid, third, forth, memory):
        self.lgr.debug('winProg textHap') 
        if self.text_hap is None:
            return
        cpu, comm, this_tid = self.task_utils.curThread() 
        if this_tid is None:
            return
        this_pid = this_tid.split('-')[0]
        
        if this_pid != pid:
            return
        sp = self.mem_utils.getRegValue(self.cpu, 'sp')
        self.lgr.debug('winProg textHap record stack base tid:%s sp 0x%x' % (this_tid, sp))
        self.top.recordStackBase(this_tid, sp)
        self.context_manager.genDeleteHap(self.text_hap)
        self.lgr.debug('winProg textHap call stopAndGo')
        #SIM_run_alone(self.top.stopAndGo, self.debugAlone)
        self.top.stopAndGo(self.debugAlone)
