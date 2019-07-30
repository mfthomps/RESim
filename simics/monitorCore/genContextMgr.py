from simics import *
'''
Track task context and set/remove beakpoints & haps accordingly.  Currently recognises two contexts:
default & RESim.  Also has a carve-out for "maze_exit" breakpoints/haps, managed as an attribute of 
the hap.  Designed to watch a single thread group.
There is one instance of this module per cell.
'''
class GenBreakpoint():
    def __init__(self, cell, addr_type, mode, addr, length, flags, handle, lgr):
        self.cell = cell
        self.addr_type = addr_type
        self.mode = mode
        self.addr = addr
        self.length = length
        self.flags = flags
        self.break_num = None
        self.lgr = lgr
        self.handle = handle

        self.set()

    def show(self):
        print('\tbreak_handle: %s num: %s  add:0x%x' % (str(self.handle), str(self.break_num), self.addr))

    def set(self):
        #self.break_num = SIM_breakpoint(self.cell, self.addr_type, self.mode, self.addr, self.length, self.flags)
        ''' do set in hap? '''
        pass
        #self.lgr.debug('GenBreakpoint set done in hap, the break handle is %d' % self.handle)

    def clear(self):
        if self.break_num is not None:
            SIM_delete_breakpoint(self.break_num)
            #self.lgr.debug('GenBreakpoint clear breakpoint %d break handle is %d' % (self.break_num, self.handle))
            self.break_num = None

class GenHap():
    def __init__(self, hap_type, callback, parameter, handle, lgr, breakpoint_list, name, immediate=True):
        ''' breakpoint_start and breakpont_end are GenBreakpoint types '''
        self.hap_type = hap_type
        self.callback = callback
        self.parameter = parameter
        self.breakpoint_list = breakpoint_list
        self.lgr = lgr
        self.hap_num = None
        self.handle = handle
        self.name = name
        self.set(immediate)

    def show(self):
        if self.handle is not None and self.hap_num is not None:
            print('hap_handle: %d  num: %d name: %s' % (self.handle, self.hap_num, self.name))
            for bp in self.breakpoint_list:
                bp.show()

    def hapAlone(self, (bs, be)):
        self.hap_num = SIM_hap_add_callback_range(self.hap_type, self.callback, self.parameter, bs.break_num, be.break_num)
        #self.lgr.debug('GenHap alone set hap_handle %s assigned hap %s name: %s on range %s %s (0x%x 0x%x) break handles %s %s' % (str(self.handle), 
        #          str(self.hap_num), self.name, str(bs.break_num), str(be.break_num), 
        #          bs.addr, be.addr, str(bs.handle), str(be.handle)))

    def set(self, immediate=True):
        if len(self.breakpoint_list) > 1:
            for bp in self.breakpoint_list:
                bp.break_num = SIM_breakpoint(bp.cell, bp.addr_type, bp.mode, bp.addr, bp.length, bp.flags)
                #self.lgr.debug('GenHap breakpoint created for hap_handle %d  assigned breakpoint num %d' % (self.handle, bp.break_num))
            bs = self.breakpoint_list[0]
            be = self.breakpoint_list[-1]
            #self.lgr.debug('GenHap callback range')
            if immediate:
                self.hap_num = SIM_hap_add_callback_range(self.hap_type, self.callback, self.parameter, bs.break_num, be.break_num)
                #self.lgr.debug('GenHap set hap_handle %s assigned hap %s name: %s on range %s %s (0x%x 0x%x) break handles %s %s' % (str(self.handle), 
                #           str(self.hap_num), self.name, str(bs.break_num), str(be.break_num), 
                #           bs.addr, be.addr, str(bs.handle), str(be.handle)))
            else:
                SIM_run_alone(self.hapAlone, (bs, be))
        elif len(self.breakpoint_list) == 1:
            bp = self.breakpoint_list[0]
            #self.lgr.debug('bp.cell is %s' % str(bp.cell))
            bp.break_num = SIM_breakpoint(bp.cell, bp.addr_type, bp.mode, bp.addr, bp.length, bp.flags)
            self.hap_num = SIM_hap_add_callback_index(self.hap_type, self.callback, self.parameter, bp.break_num)
            #self.lgr.debug('GenHap set hap_handle %s assigned hap %s name: %s on break %s (0x%x) break_handle %s' % (str(self.handle), str(self.hap_num), 
            #                self.name, str(bp.break_num), bp.addr, str(bp.handle)))
        else:
            self.lgr.error('GenHap, no breakpoints')

    def clear(self, dumb=None):
        if self.hap_num is not None:
            for bp in self.breakpoint_list:
                bp.clear()
            SIM_hap_delete_callback_id(self.hap_type, self.hap_num)
            #self.lgr.debug('GenHap clear hap %d handle %d' % (self.hap_num, self.handle))
            self.hap_num = None
   
class GenContextMgr():
    def __init__(self, top, cell_name, task_utils, param, cpu, lgr):
        self.top = top
        self.cell_name = cell_name
        self.task_utils = task_utils
        self.param = param
        self.task_utils = task_utils
        self.mem_utils = task_utils.getMemUtils()
        self.debugging_pid = None
        self.debugging_cellname = None
        self.debugging_cell = None
        self.cpu = cpu
        ''' watch multiple tasks, e.g., threads '''
        self.watch_rec_list = {}
        self.watch_rec_list_saved = {}
        self.pending_watch_pids = []
        self.nowatch_list = []
        self.watching_tasks = False
        self.single_thread = False
        self.lgr = lgr
        self.ida_message = None
        self.exit_break_num = None
        self.exit_cb_num = None
        self.phys_current_task = task_utils.getPhysCurrentTask()
        self.task_break = None
        self.task_hap = None
        self.breakpoints = []
        self.haps = []
        self.break_handle = 0
        self.hap_handle = 0
        self.text_start = None
        self.text_end = None
        obj = SIM_get_object(cell_name)
        self.default_context = obj.cell_context
        context = 'RESim_%s' % cell_name
        cmd = 'new-context %s' % context
        SIM_run_command(cmd)
        obj = SIM_get_object(context)
        self.resim_context = obj
        self.lgr.debug('context_manager cell %s resim_context defined as obj %s' % (self.cell_name, str(obj)))

        ''' avoid searching all task recs to know if pid being watched '''
        self.pid_cache = []

        ''' watch pointers to task recs to catch kills '''
        self.task_rec_hap = {}
        self.task_rec_bp = {}
        ''' avoid multiple calls to taskRecHap '''
        self.demise_cache = []

    def getRealBreak(self, break_handle):
        for hap in self.haps:
            for bp in hap.breakpoint_list:
                if bp.handle == break_handle:
                    return bp.break_num
        return None

    def getBreakHandle(self, real_bp):
        for hap in self.haps:
            #self.lgr.debug('getBreakHandle hap %s' % (hap.name))
            for bp in hap.breakpoint_list:
                #self.lgr.debug('getBreakHandle look for %d got %d' % (real_bp, bp.break_num))
                if bp.break_num == real_bp:
                    return bp.handle
        return None

    def showHaps(self):
        for hap in self.haps:
            hap.show()

    def getRESimContext(self):
        return self.debugging_cell

    def recordText(self, start, end):
        self.text_start = start
        self.text_end = end

    def getText(self):
        return self.text_start, self.text_end

    def nextHapHandle(self):
        self.hap_handle = self.hap_handle+1
        return self.hap_handle 

    def nextBreakHandle(self):
        self.break_handle = self.break_handle+1
        return self.break_handle 

    def genBreakpoint(self, cell, addr_type, mode, addr, length, flags):
        ''' create a GenContextManager breakpoint.  This is not yet set.
            Determine if the context should be resim, e.g., only when one of our
            debugging processes is schedule.
        '''
        handle = self.nextBreakHandle()
        if self.debugging_pid is not None and addr_type == Sim_Break_Linear:
            cell = self.resim_context
            #self.lgr.debug('gen break with resim context %s' % str(self.resim_context))
        bp = GenBreakpoint(cell, addr_type, mode, addr, length, flags, handle, self.lgr) 
        self.breakpoints.append(bp)
        #self.lgr.debug('genBreakpoint handle %d number of breakpoints is now %d' % (handle, len(self.breakpoints)))
        return handle

    def genDeleteBreakpoint(self, handle):
        #self.lgr.debug('genDeleteBreakpoint handle %d  -- do not delete, will be done in GenHap' % handle)
        #for bp in self.breakpoints:
        #    if bp.handle == handle:
        #        bp.clear()
        #        self.breakpoints.remove(bp)
        #        return
        #self.lgr.debug('genDeleteBreakpoint could not find break handle %d' % handle)
        pass

    def genDeleteHap(self, hap_handle, immediate=False):
        if hap_handle is None:
            self.lgr.error('genDelteHap called with handle of none')
            return
        #self.lgr.debug('genDeleteHap hap_handle %d' % hap_handle)
        hap_copy = list(self.haps)
        for hap in hap_copy:
            if hap.handle == hap_handle:
                if immediate:
                    hap.clear(None)
                else:
                    SIM_run_alone(hap.clear, None)
                #self.lgr.debug('num breaks in hap %d is %d' % (hap_handle, len(hap.breakpoint_list)))
                for bp in hap.breakpoint_list:
                    if bp in self.breakpoints:
                        self.breakpoints.remove(bp)
                        #self.lgr.debug('removing bp %d from hap_handle %d  break_num %s' % (bp.handle, hap_handle, str(bp.break_num)))
                    else:
                        self.lgr.error('genDeleteHap bp not in list, handle %d ' % (bp.handle))
                #self.lgr.debug('genDeleteHap removing hap %d from list' % hap.handle)
                self.haps.remove(hap)
                return
        #self.lgr.debug('genDeleteHap could not find hap_num %d' % hap_handle)

    def genHapIndex(self, hap_type, callback, parameter, handle, name=None):
        #self.lgr.debug('genHapIndex break_handle %d' % handle)
        for bp in self.breakpoints:
            if bp.handle == handle:
                hap_handle = self.nextHapHandle()
                hap = GenHap(hap_type, callback, parameter, hap_handle, self.lgr, [bp], name)
                self.haps.append(hap)
                return hap.handle
        #self.lgr.error('genHapIndex failed to find break %d' % breakpoint)

    def genHapRange(self, hap_type, callback, parameter, handle_start, handle_end, name=None):
        #self.lgr.debug('genHapRange break_handle %d %d' % (handle_start, handle_end))
        bp_start = None
        bp_list = []
        for bp in self.breakpoints:
            if bp.handle >= handle_start:
                bp_list.append(bp)
            if bp.handle == handle_end:
                hap_handle = self.nextHapHandle()
                hap = GenHap(hap_type, callback, parameter, hap_handle, self.lgr, bp_list, name, immediate=False)
                self.haps.append(hap)
                return hap.handle
        #self.lgr.error('genHapRange failed to find break for handles %d or %d' % (breakpoint_start, breakpoint_end))

    def setAllBreak(self):
        for bp in self.breakpoints:
            bp.set()

    def setAllHap(self, only_maze_breaks=False):
        for hap in self.haps:
            if (not only_maze_breaks and hap.name != 'exitMaze') or (only_maze_breaks and hap.name == 'exitMaze'):
                hap.set()

    def clearAllBreak(self):
        ''' Called to clear breaks within the resim context '''
        for bp in self.breakpoints:
            #if bp.cell == self.resim_context:
            bp.clear()
        
    def clearAllHap(self, keep_maze_breaks=False):
        #self.lgr.debug('clearAllHap start')
        
        for hap in self.haps:
            if not keep_maze_breaks or hap.name != 'exitMaze':
                hap.clear()
        #self.lgr.debug('clearAllHap finish')

    def getThreadRecs(self):
        return self.watch_rec_list.keys()

    def getThreadPids(self):
        retval = []
        for rec in self.watch_rec_list:
            pid = self.watch_rec_list[rec]
            self.lgr.debug('genContextManager getThreadPids append %d to returned thread pid list' % (pid))
            retval.append(pid)
        return retval

    def addNoWatch(self):
        ''' only watch maze exits for the current task. NOTE: assumes those are set after call to this function'''
        self.lgr.debug('contextManager cell %s addNoWatch' % self.cell_name)
        if len(self.nowatch_list) == 0 and len(self.watch_rec_list) == 0:
            ''' had not been watching and tasks.  start so we can not watch this one '''
            self.setTaskHap()
            self.watching_tasks=True
            self.lgr.debug('contextManager addNoWatch began watching tasks')
        rec = self.task_utils.getCurTaskRec() 
        self.nowatch_list.append(rec)
        self.lgr.debug('contextManager addNoWatch for rec 0x%x' % rec)
        SIM_run_alone(self.clearAllHap, True)

    def rmNoWatch(self):
        ''' restart watching the current task, assumes it was added via addNoWatch '''
        rec = self.task_utils.getCurTaskRec() 
        if rec in self.nowatch_list:
            self.nowatch_list.remove(rec)
            self.lgr.debug('contextManager rmNoWatch, rec 0x%x removed from nowatch list' % rec)
            if len(self.nowatch_list) == 0 and len(self.watch_rec_list) == 0:
                ''' stop all task watching '''
                self.stopWatchTasks()
                SIM_run_alone(self.setAllHap, False)
                self.lgr.debug('contextManager addNoWatch stopped watching tasks, enabled all HAPs')
            else:
                ''' restart watching '''
                SIM_run_alone(self.setAllHap, False)
        else:
            self.lgr.error('contextManager rmNoWatch, rec 0x%x not in nowatch list' % rec)

        
    def changedThread(self, cpu, third, forth, memory):
        ''' guts of context managment.  set or remove breakpoints/haps 
            depending on whether we are tracking the newly scheduled process '''
        if self.task_hap is None:
            return
        # get the value that will be written into the current thread address
        new_addr = SIM_get_mem_op_value_le(memory)
        pid = self.mem_utils.readWord32(cpu, new_addr + self.param.ts_pid)
        prev_task = self.task_utils.getCurTaskRec()
        prev_pid = self.mem_utils.readWord32(cpu, prev_task + self.param.ts_pid)
        #self.lgr.debug('changeThread from %d to %d new_addr 0x%x watchlist len is %d' % (prev_pid, pid, new_addr, len(self.watch_rec_list)))
        pid = None
        if len(self.pending_watch_pids) > 0:
            ''' Are we waiting to watch pids that have not yet been scheduled?
                We don't have the process rec until it is ready to schedule. '''
            pid = self.mem_utils.readWord32(cpu, new_addr + self.param.ts_pid)
            if pid in self.pending_watch_pids:
                self.lgr.debug('changedThread, pending add pid %d to watched processes' % pid)
                self.watch_rec_list[new_addr] = pid
                self.pending_watch_pids.remove(pid)
                self.watchExit(rec=new_addr, pid=pid)
          

        if not self.watching_tasks and \
               (new_addr in self.watch_rec_list or (len(self.watch_rec_list) == 0 and  len(self.nowatch_list) > 0)) \
               and not (self.single_thread and pid != self.debugging_pid):
            ''' Not currently watching processes, but new process should be watched '''
            if self.debugging_pid is not None:
                cpu.current_context = self.resim_context
                #self.lgr.debug('resim_context')
            pid = self.mem_utils.readWord32(cpu, new_addr + self.param.ts_pid)
            #self.lgr.debug('Now scheduled %d new_addr 0x%x' % (pid, new_addr))
            self.watching_tasks = True
            self.setAllBreak()
            only_maze_breaks = False
            if new_addr in self.nowatch_list:
                only_maze_breaks = True
                #self.lgr.debug('contextManager changedThread, only do maze breaks')
            SIM_run_alone(self.setAllHap, only_maze_breaks)
        elif self.watching_tasks:
            if prev_task in self.nowatch_list:
                if new_addr not in self.nowatch_list:
                    ''' was watching only maze exits, watch everything but maze'''
                    #self.lgr.debug('was watching only maze, now watch all ')
                    SIM_run_alone(self.clearAllHap, False)
                    SIM_run_alone(self.setAllHap, False)
            elif new_addr in self.nowatch_list:
                ''' was watching everything, watch only maze '''
                #self.lgr.debug('Now only watch maze')
                SIM_run_alone(self.clearAllHap, False)
                SIM_run_alone(self.setAllHap, True)
            elif len(self.watch_rec_list) > 0 and new_addr not in self.watch_rec_list:
                ''' Watching processes, but new process should not be watched '''
                if self.debugging_pid is not None:
                    cpu.current_context = self.default_context
                    #self.lgr.debug('default_context')
                #self.lgr.debug('No longer scheduled')
                self.watching_tasks = False
                self.clearAllBreak()
                SIM_run_alone(self.clearAllHap, False)

    def watchOnlyThis(self):
        ctask = self.task_utils.getCurTaskRec()
        cur_pid = self.mem_utils.readWord32(self.cpu, ctask + self.param.ts_pid)
        pcopy = list(self.pid_cache)
        for pid in pcopy:
            if pid != cur_pid:
                self.rmTask(pid)

    def rmTask(self, pid, killed=False):
        ''' remove a pid from the list of task records being watched.  return True if this is the last thread. '''
        retval = False
        rec = self.task_utils.getRecAddrForPid(pid)
        if rec is None and killed:
            ''' assume record already gone '''
            for r in self.watch_rec_list:
                if self.watch_rec_list[r] == pid:
                    rec = r
                    self.lgr.debug('contextManager rmTask %d rec already gone, remove its entries' % pid)
                    break
        if rec in self.watch_rec_list:
            del self.watch_rec_list[rec]
            self.lgr.debug('rmTask removing rec 0x%x for pid %d, len now %d' % (rec, pid, len(self.watch_rec_list)))
            if pid in self.pid_cache:
                self.pid_cache.remove(pid)
                self.lgr.debug('rmTask remove %d from cache, cache now %s' % (pid, str(self.pid_cache)))
            
            if pid in self.task_rec_bp and self.task_rec_bp[pid] is not None:
                SIM_delete_breakpoint(self.task_rec_bp[pid])
                SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.task_rec_hap[pid])        
                del self.task_rec_bp[pid]
                del self.task_rec_hap[pid]
            if len(self.watch_rec_list) == 0:
                self.lgr.debug('contextManager rmTask watch_rec_list empty, clear debugging_pid')
                self.debugging_pid = None
                self.debugging_cellname = None
                self.debugging_cell = None
                self.cpu.current_context = self.default_context
                self.stopWatchTasks()
                retval = True
            elif pid == self.debugging_pid:
                self.debugging_pid = self.pid_cache[0]
                self.lgr.debug('rmTask debugging_pid now %d' % self.debugging_pid)
            else:
                self.lgr.debug('rmTask remaining debug recs %s' % str(self.watch_rec_list))
        return retval

    def addTask(self, pid):
        rec = self.task_utils.getRecAddrForPid(pid)
        if rec not in self.watch_rec_list:
            if rec is None:
                self.lgr.debug('genContextManager, addTask got rec of None for pid %d, pending' % pid)
                self.pending_watch_pids.append(pid)
            else:
                self.lgr.debug('genContextManager, addTask pid %d add rec 0x%x' % (pid, rec))
                self.watch_rec_list[rec] = pid
                self.watchExit(rec=rec, pid=pid)
            if pid not in self.pid_cache:
                self.pid_cache.append(pid)
        else:
            self.lgr.debug('addTask, already has rec 0x%x for PID %d' % (rec, pid))

    def amWatching(self, pid):
        ctask = self.task_utils.getCurTaskRec()
        dumb, comm, cur_pid  = self.task_utils.curProc()
        if pid == cur_pid and (ctask in self.watch_rec_list or len(self.watch_rec_list)==0):
            return True
        elif pid in self.pid_cache:
            return True
        else:
            return False

    def restoreDebug(self):
        self.debugging_pid = self.debugging_pid_saved
        self.watch_rec_list = self.watch_rec_list_saved.copy()
        for ctask in self.watch_rec_list:
            self.pid_cache.append(self.watch_rec_list[ctask])
        self.cpu.current_context = self.resim_context
        self.lgr.debug('contextManager restoreDebug set cpu context to resim')

    def stopWatchTasks(self):
        if self.task_break is None:
            self.lgr.debug('stopWatchTasks already stopped')
            return
        SIM_delete_breakpoint(self.task_break)
        SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_hap)
        self.task_hap = None
        self.task_break = None
        self.watching_tasks = False
        self.watch_rec_list_saved = self.watch_rec_list.copy()
        self.debugging_pid_saved = self.debugging_pid
        self.watch_rec_list = {}
        
        for pid in self.task_rec_bp:    
            if self.task_rec_bp[pid] is not None:
                SIM_delete_breakpoint(self.task_rec_bp[pid])
                SIM_hap_delete_callback_id('Core_Breakpoint_Memop', self.task_rec_hap[pid])        
        self.task_rec_bp = {}
        self.task_rec_hap = {}
        self.pid_cache = []
        self.debugging_pid = None

        cpu, dumb, dumb2  = self.task_utils.curProc()
        cpu.current_context = self.default_context
        self.lgr.debug('stopWatchTasks reverted %s to default context %s' % (cpu.name, str(self.default_context)))

    def setTaskHap(self):
        print('debugging_cell is %s' % self.debugging_cell)
        self.task_break = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             self.phys_current_task, self.mem_utils.WORD_SIZE, 0)
        self.task_hap = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.changedThread, self.cpu, self.task_break)
        self.lgr.debug('setTaskHap cell %s break %d set on physical 0x%x' % (self.cell_name, self.task_break, self.phys_current_task))

    def watchTasks(self):
        if self.task_break is not None:
            #self.lgr.debug('watchTasks called, but already watching')
            return
        self.setTaskHap()
        self.watching_tasks = True
        ctask = self.task_utils.getCurTaskRec()
        if ctask in self.watch_rec_list:
            self.lgr.debug('watchTasks, current task already being watched')
            return
        pid = self.mem_utils.readWord32(self.cpu, ctask + self.param.ts_pid)
        self.lgr.debug('watchTasks cell %s watch record 0x%x pid: %d' % (self.cell_name, ctask, pid))
        self.watch_rec_list[ctask] = pid
        if pid not in self.pid_cache:
            self.pid_cache.append(pid)
        self.watchExit()
      
    def changeDebugPid(self, pid):
        if pid not in self.pid_cache:
            self.lgr.error('contextManager changeDebugPid not in pid cache %d' % pid)
            return
        self.debugging_pid = pid

    def singleThread(self, single):
        self.single_thread = single

    def setDebugPid(self, debugging_pid, debugging_cellname):
        self.default_context = self.cpu.current_context
        self.cpu.current_context = self.resim_context
        self.lgr.debug('setDebugPid %d, resim_context' % debugging_pid)
        self.debugging_pid = debugging_pid
        self.debugging_cellname = debugging_cellname
        self.debugging_cell = self.top.getCell()
        if debugging_pid not in self.pid_cache:
            self.pid_cache.append(debugging_pid)

    def resetAlone(self, pid):
        self.lgr.debug('contextManager resetAlone')
        dead_rec = self.task_utils.getRecAddrForPid(pid)
        if dead_rec is not None:
            list_addr = self.task_utils.getTaskListPtr(dead_rec)
            self.lgr.debug('contextMgr resetAlone rec 0x%x of pid %d still found though written by maybe not dead after all? new list_addr is 0x%x' % (dead_rec, 
                pid, list_addr))

            SIM_delete_breakpoint(self.task_rec_bp[pid])
            self.task_rec_bp[pid] = None
            SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_rec_hap[pid])
            self.task_rec_hap[pid] = None
            self.watchExit(rec=dead_rec, pid = pid)
        else: 
            ''' who knew? death comes betweeen the breakpoint and the "run alone" scheduling '''
            self.lgr.debug('contextManager resetAlone pid:%d rec no longer found' % (pid))
            exit_syscall = self.top.getSyscall(self.cell_name, 'exit_group')
            if exit_syscall is not None:
                ida_msg = 'pid:%d exit via kill?' % pid
                exit_syscall.handleExit(pid, ida_msg, killed=True)
            else:
                self.rmTask(pid)
        self.demise_cache.remove(pid)

    def taskRecHap(self, pid, third, forth, memory):
        if pid not in self.task_rec_hap or pid in self.demise_cache:
            return
        dumb, comm, cur_pid  = self.task_utils.curProc()
        self.lgr.debug('contextManager taskRecHap demise of pid:%d by the hand of cur_pid %d?' % (pid, cur_pid))
        dead_rec = self.task_utils.getRecAddrForPid(pid)
        if dead_rec is not None:
            self.lgr.debug('contextManager taskRecHap got record 0x%x for %d, call resetAlone' % (dead_rec, pid))
            self.demise_cache.append(pid)
            SIM_run_alone(self.resetAlone, pid)

        else: 
            value = SIM_get_mem_op_value_le(memory)
            self.lgr.debug('contextManager taskRecHap pid:%d wrote 0x%x to 0x%x watching for demise of %d' % (cur_pid, value, memory.logical_address, pid))
            exit_syscall = self.top.getSyscall(self.cell_name, 'exit_group')
            if exit_syscall is not None:
                ida_msg = 'pid:%d exit via kill?' % pid
                exit_syscall.handleExit(pid, ida_msg, killed=True)
            else:
                self.rmTask(pid)

    def watchExit(self, rec=None, pid=None):
        dumb, comm, cur_pid  = self.task_utils.curProc()
        if pid is None:
            pid = cur_pid
            rec = self.task_utils.getCurTaskRec() 
        list_addr = self.task_utils.getTaskListPtr(rec)
        if list_addr is None:
            self.lgr.error('contextManager watchExit failed to get list_addr pid %d cur_pid %d' % (pid, cur_pid))
            return
        cell = self.default_context
        #cell = self.resim_context
        self.task_rec_bp[pid] = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Write, list_addr, self.mem_utils.WORD_SIZE, 0)
        #bp = self.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Write, list_addr, self.mem_utils.WORD_SIZE, 0)
        self.lgr.debug('contextManager watchExit cur pid:%d set list break %d at 0x%x for pid %d context %s' % (cur_pid, self.task_rec_bp[pid], 
             list_addr, pid, str(cell)))
        #self.task_rec_hap[pid] = self.genHapIndex("Core_Breakpoint_Memop", self.taskRecHap, pid, bp)
        self.task_rec_hap[pid] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.taskRecHap, pid, self.task_rec_bp[pid])

    def setExitBreaks(self):
        self.lgr.debug('contextManager setExitBreaks')
        for pid in self.task_rec_bp:
            rec = self.task_utils.getRecAddrForPid(pid)
            self.watchExit(rec, pid)

    def clearExitBreaks(self):
        self.lgr.debug('contextManager clearExitBreaks')
        for pid in self.task_rec_bp:
            if self.task_rec_bp[pid] is not None:
                SIM_delete_breakpoint(self.task_rec_bp[pid])
                self.task_rec_bp[pid] = None
                self.lgr.debug('contextManager clearExitBreaks pid:%d' % pid)
        for pid in self.task_rec_hap:
            if self.task_rec_hap[pid] is not None:
                SIM_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_rec_hap[pid])
                self.task_rec_hap[pid] = None

    def resetBackStop(self):
        pass

    def getIdaMessage(self):
        return self.ida_message

    def getDebugPid(self):
        return self.debugging_pid, self.debugging_cellname, self.cpu

    def showIdaMessage(self):
        print 'genMonitor says: %s' % self.ida_message
        self.lgr.debug('genMonitor says: %s' % self.ida_message)

    def setIdaMessage(self, message):
        #self.lgr.debug('ida message set to %s' % message)
        self.ida_message = message

    def getRESimContext(self):
        return self.resim_context
