from simics import *
from resimHaps import *
'''
Track task context and set/remove beakpoints & haps accordingly.  Currently recognises two contexts:
default & RESim.  Also has a carve-out for "maze_exit" breakpoints/haps, managed as an attribute of 
the hap.  Designed to watch a single thread group.
There is one instance of this module per cell.
'''
class GenBreakpoint():
    def __init__(self, cell, addr_type, mode, addr, length, flags, handle, lgr, prefix=None):
        self.cell = cell
        self.addr_type = addr_type
        self.mode = mode
        self.addr = addr
        self.length = length
        self.flags = flags
        self.break_num = None
        self.lgr = lgr
        self.handle = handle
        self.prefix = prefix
        if addr is None:
            lgr.error('GenBreakpoint called with addr of None.')

    def show(self):
        print('\tbreak_handle: %s num: %s  add:0x%x' % (str(self.handle), str(self.break_num), self.addr))

    def clear(self):
        if self.break_num is not None:
            #self.lgr.debug('GenBreakpoint clear breakpoint %d break handle is %d' % (self.break_num, self.handle))
            SIM_delete_breakpoint(self.break_num)
            self.break_num = None

class GenHap():
    def __init__(self, hap_type, callback, parameter, handle, lgr, breakpoint_list, name, immediate=True):
        ''' breakpoint_start and breakpont_end are GenBreakpoint types '''
        self.hap_type = hap_type
        self.callback = callback
        ''' used with afl '''
        self.parameter = parameter
        for bp in breakpoint_list:
            if bp.addr is None:
                lgr.error('GenHap %s found breakpoint with addr of None' % name)
        self.breakpoint_list = breakpoint_list
        self.lgr = lgr
        self.hap_num = None
        self.handle = handle
        self.name = name
        self.set(immediate)

    def show(self):
        if self.handle is not None and self.hap_num is not None:
            print('hap_handle: %d  num: %d name: %s context: %s' % (self.handle, self.hap_num, self.name, self.getContext()))
            #self.lgr.debug('hap_handle: %d  num: %d name: %s context: %s' % (self.handle, self.hap_num, self.name, self.getContext()))
            for bp in self.breakpoint_list:
                bp.show()
        elif self.handle is not None:
            self.lgr.debug('hap_handle: %d name: %s, context: disabled context: %s' % (self.handle, self.name, self.getContext()))
            print('hap_handle: %d name: %s, context: disabled context: %s' % (self.handle, self.name, self.getContext()))

    #def hapAlone(self, (bs, be)):
    def hapAlone(self, breaks):
        bs, be = breaks
        #self.lgr.debug('GenHap alone set hap_handle %s name: %s on range %s %s (0x%x 0x%x) break handles %s %s' % (str(self.handle), 
        #          self.name, str(bs.break_num), str(be.break_num), 
        #          bs.addr, be.addr, str(bs.handle), str(be.handle)))
        self.hap_num = RES_hap_add_callback_obj_range(self.hap_type, bp.cell, 0, self.callback, self.parameter, bs.break_num, be.break_num)
        #self.lgr.debug('GenHap alone set hap_handle %s assigned hap %s name: %s on range %s %s (0x%x 0x%x) break handles %s %s' % (str(self.handle), 
        #          str(self.hap_num), self.name, str(bs.break_num), str(be.break_num), 
        #          bs.addr, be.addr, str(bs.handle), str(be.handle)))

    def set(self, immediate=True):
        ''' NOTE: different calls to SIM_brekapoint below '''
        if len(self.breakpoint_list) > 1:
            for bp in self.breakpoint_list:
                bp.break_num = SIM_breakpoint(bp.cell, bp.addr_type, bp.mode, bp.addr, bp.length, bp.flags)
                if bp.prefix is not None:
                    command = 'set-prefix %d "%s"' % (bp.break_num, bp.prefix)
                    SIM_run_alone(SIM_run_command, command)
                    #self.lgr.debug('contextManager prefix cmd: %s' % command)

                #self.lgr.debug('GenHap breakpoint created for hap_handle %d  assigned breakpoint num %d' % (self.handle, bp.break_num))
            bs = self.breakpoint_list[0]
            be = self.breakpoint_list[-1]
            #self.lgr.debug('GenHap callback range')
            if immediate:
                #self.lgr.debug('GenHap set hap_handle %s assigned name: %s on range %s %s (0x%x 0x%x) break handles %s %s' % (str(self.handle), 
                #           self.name, str(bs.break_num), str(be.break_num), 
                #           bs.addr, be.addr, str(bs.handle), str(be.handle)))
                self.hap_num = RES_hap_add_callback_obj_range(self.hap_type, bp.cell, 0, self.callback, self.parameter, bs.break_num, be.break_num)
                #self.lgr.debug('GenHap set hap_handle %s assigned hap %s name: %s on range %s %s (0x%x 0x%x) break handles %s %s' % (str(self.handle), 
                #           str(self.hap_num), self.name, str(bs.break_num), str(be.break_num), 
                #           bs.addr, be.addr, str(bs.handle), str(be.handle)))
            else:
                SIM_run_alone(self.hapAlone, (bs, be))
        elif len(self.breakpoint_list) == 1:
            bp = self.breakpoint_list[0]
            #self.lgr.debug('bp.cell is %s addr %s' % (str(bp.cell), str(bp.addr)))
            if bp.addr is None:
                self.lgr.error('contextManager, set bp.addr is none within HAP %s' % self.name)
                return
            bp.break_num = SIM_breakpoint(bp.cell, bp.addr_type, bp.mode, bp.addr, bp.length, bp.flags)
            if bp.prefix is not None:
                command = 'set-prefix %d "%s"' % (bp.break_num, bp.prefix)
                SIM_run_alone(SIM_run_command, command)
                #self.lgr.debug('contextManager prefix cmd: %s' % command)
            #self.lgr.debug('GenHap set hap_handle %s name: %s on break %s (0x%x) break_handle %s cell %s ' % (str(self.handle), 
            #              self.name, str(bp.break_num), bp.addr, str(bp.handle), bp.cell))
            self.hap_num = RES_hap_add_callback_index(self.hap_type, self.callback, self.parameter, bp.break_num)
            #self.lgr.debug('GenHap set hap_handle %s assigned hap %s name: %s on break %s (0x%x) break_handle %s' % (str(self.handle), str(self.hap_num), 
            #                self.name, str(bp.break_num), bp.addr, str(bp.handle)))
        else:
            self.lgr.error('GenHap, no breakpoints')

    def clear(self, dumb=None):
        if self.hap_num is not None:
            for bp in self.breakpoint_list:
                bp.clear()
            #self.lgr.debug('GenHap clear hap %s %d handle %d' % (self.name, self.hap_num, self.handle))
            RES_hap_delete_callback_id(self.hap_type, self.hap_num)
            #self.lgr.debug('GenHap back from clear ')
            self.hap_num = None

    def getContext(self):
        retval = None
        if len(self.breakpoint_list) > 0:
            retval = self.breakpoint_list[0].cell 
        else:
            self.lgr.error('GenHap, no breakpoints')
        return retval
   
class GenContextMgr():
    def __init__(self, top, cell_name, task_utils, param, cpu, lgr):
        self.top = top
        self.cell_name = cell_name
        self.task_utils = task_utils
        self.param = param
        self.task_utils = task_utils
        self.mem_utils = task_utils.getMemUtils()
        self.debugging_pid = None
        self.debugging_pid_saved = None
        self.debugging_comm = []
        self.debugging_cell = None
        self.cpu = cpu
        self.pageFaultGen = None
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
        self.catch_pid = None
        self.catch_callback = None
        self.watch_only_this = False
        ''' used with afl '''
        self.callback = None
        self.exit_callback = None  

        ''' experiment with tracking task switches among watched pids '''
        self.task_switch = {}

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
        self.group_leader = None

        ''' watch pointers to task recs to catch kills '''
        self.task_rec_hap = {}
        self.task_rec_bp = {}
        self.task_rec_watch = {}
        ''' avoid multiple calls to taskRecHap '''
        self.demise_cache = []

        ''' used by pageFaultGen to supress breaking on apparent kills '''
        self.watching_page_faults = False

        ''' Do not watch these pids '''
        self.no_watch = []

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
        self.lgr.debug('contextManager showHaps')
        for hap in self.haps:
            hap.show()

    #def getRESimContext(self):
    #    return self.debugging_cell

    def recordText(self, start, end):
        self.lgr.debug('contextMgr recordText 0x%x 0x%x' % (start, end))
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

    def genBreakpoint(self, cell, addr_type, mode, addr, length, flags, prefix=None):
        ''' create a GenContextManager breakpoint.  This is not yet set.
            Determine if the context should be resim, e.g., only when one of our
            debugging processes is schedule.
        '''
        handle = self.nextBreakHandle()
        if cell is None:
            if self.debugging_pid is not None and addr_type == Sim_Break_Linear:
                cell = self.resim_context
            else:
                cell = self.default_context
            #self.lgr.debug('gen break with resim context %s' % str(self.resim_context))
        bp = GenBreakpoint(cell, addr_type, mode, addr, length, flags, handle, self.lgr, prefix=prefix) 
        self.breakpoints.append(bp)
        #self.lgr.debug('genBreakpoint handle %d number of breakpoints is now %d prefix %s context %s' % (handle, len(self.breakpoints), prefix, cell))
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
            self.lgr.warning('genDelteHap called with handle of none')
            return
        if isinstance(hap_handle, str):
            self.lgr.error('contextManager genDeleteHap hap_handle is string? %s' % hap_handle)
            return 
        #self.lgr.debug('genDeleteHap hap_handle %d immediate: %r' % (hap_handle, immediate))
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
                        #self.lgr.debug('genDeleteHap removing bp %d from hap_handle %d  break_num %s' % (bp.handle, hap_handle, str(bp.break_num)))
                        self.breakpoints.remove(bp)
                    else:
                        self.lgr.warning('genDeleteHap bp not in list, handle %d ' % (bp.handle))
                #self.lgr.debug('genDeleteHap removing hap %d from list' % hap.handle)
                self.haps.remove(hap)
                return
        #self.lgr.debug('genDeleteHap could not find hap_num %d' % hap_handle)

    def genHapIndex(self, hap_type, callback, parameter, handle, name=None):
        #self.lgr.debug('genHapIndex break_handle %d' % handle)
        retval = None
        for bp in self.breakpoints:
            if bp.handle == handle:
                hap_handle = self.nextHapHandle()
                hap = GenHap(hap_type, callback, parameter, hap_handle, self.lgr, [bp], name)
                self.haps.append(hap)
                retval = hap.handle
                break
        #self.lgr.error('genHapIndex failed to find break %d' % breakpoint)
        return retval

    def genHapRange(self, hap_type, callback, parameter, handle_start, handle_end, name=None):
        #self.lgr.debug('genHapRange break_handle %d %d' % (handle_start, handle_end))
        bp_start = None
        bp_list = []
        for bp in self.breakpoints:
            if bp.handle >= handle_start:
                bp_list.append(bp)
            if bp.handle == handle_end:
                hap_handle = self.nextHapHandle()
                hap = GenHap(hap_type, callback, parameter, hap_handle, self.lgr, bp_list, name, immediate=True)
                #self.lgr.debug('contextManager genHapRange set hap %s on %d breaks' % (name, len(bp_list)))
                self.haps.append(hap)
                return hap.handle
        #self.lgr.error('genHapRange failed to find break for handles %d or %d' % (breakpoint_start, breakpoint_end))
        return None


    def setAllHap(self, only_maze_breaks=False):
        if self.watchingTasks(): 
            for hap in self.haps:
                if hap.getContext() == self.getRESimContext():
                    if (not only_maze_breaks and hap.name != 'exitMaze') or (only_maze_breaks and hap.name == 'exitMaze'):
                        hap.set()
        else:
            for hap in self.haps:
                if (not only_maze_breaks and hap.name != 'exitMaze') or (only_maze_breaks and hap.name == 'exitMaze'):
                    hap.set()

    def clearAllBreak(self, dumb):
        #self.lgr.debug('contextManager clearAllBreak')
        ''' Called to clear breaks within the resim context '''
        for bp in self.breakpoints:
            #if bp.cell == self.resim_context:
            bp.clear()
        
    def clearAllHap(self, keep_maze_breaks=False):
        #self.lgr.debug('clearAllHap start')
        ''' clear all haps, excepting maze breakout haps per input switch 
            If self.watch_rec_list is empty, then clear regardless of context.
            Otherwise, if not empty, then clear only resim context.
        '''
        if self.watchingTasks(): 
            for hap in self.haps:
                if hap.getContext() == self.getRESimContext():
                    if not keep_maze_breaks or hap.name != 'exitMaze':
                        hap.clear()
        else:
            for hap in self.haps:
                if not keep_maze_breaks or hap.name != 'exitMaze':
                    hap.clear()

        #self.lgr.debug('clearAllHap finish')
        if self.pageFaultGen is not None:
            self.pageFaultGen.stopPageFaults()

    def getThreadRecs(self):
        return self.watch_rec_list.keys()

    def getThreadPids(self):
        retval = []
        for rec in self.watch_rec_list:
            pid = self.watch_rec_list[rec]
            #self.lgr.debug('genContextManager getThreadPids append %d to returned thread pid list' % (pid))
            retval.append(pid)
        return retval

    def getWatchList(self):
        return self.watch_rec_list

    def watchingTasks(self): 
        if len(self.watch_rec_list) == 0:
            return False
        else:
            return True

    def getNoWatchList(self):
        return self.nowatch_list

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

    def alterWatches(self, new_task, prev_task):
        ''' Determine what type of context and breakpoints to set 
            
                self.watch_rec_list -- tasks that we are watching.  When these tasks are scheduled
                                       the cpu should be given the resim context.
                self.nowatch_list -- List of tasks currently trying to break out of mazes.

                self.watching_tasks -- were we watching any tasks?
            If watch_rec_list is empty, we are not watching any specific task and all haps are
            set using the default context and the cpu should have the default context.  Otherwise,
            the cpu should have the resim context when those tasks are scheduled.
  
            The toExecve function sets haps using the default context.  

            Maze breakpoints and context
               Maze breakpoints, e.g., those used to find breakout points should have default context
               if not debugging (watch_list empty), and resim context if watch_rec_list is not empty.  
       
               Haps used for breakout attempts are named "exitMaze". 
               During breakout attempts the thread of interest will be in the nowatch_list.
               When not sheduled, all exitMaze haps should be disabled.
               When scheduled exitMaze haps are enabled but all other haps for that context are disabled.

            self.watching_tasks --  Was the previous task being watched?
      
            setAllHap(only_maze_breaks)
            clearAllHap(keep_maze_breaks)

            
        '''
        if not self.watching_tasks:
            ''' Was not watching any task '''
            if new_task in self.watch_rec_list:
                self.watching_tasks = True
                self.restoreDebugContext()
                ''' Should watch new task '''
                if new_task not in self.nowatch_list:
                    ''' should watch all but maze ''' 
                    SIM_run_alone(self.setAllHap, False)
                    #self.lgr.debug('contextManager DEBUG, was not watching, new task in debug list, watch all but maze')
                else:
                    ''' should only watch maze breaks '''
                    SIM_run_alone(self.setAllHap, True)
                    #self.lgr.debug('contextManager DEBUG, was not watching, new task in debug list but in maze breakout, watch ONLY maze breaks')
            else:
                '''New task not in watch_rec_list'''
                if len(self.watch_rec_list) == 0:
                    ''' no debug tasks '''
                    if new_task in self.nowatch_list:
                        ''' Set only the maze break '''
                        ''' Was not watching anything, so set current task break '''
                        SIM_run_alone(self.setAllHap, True)
                        #self.lgr.debug('contextManager DEBUG, was not watching, no debug list but task in maze breakout, watch ONLY maze breaks')
                    else:
                        ''' Set all but the maze breaks '''
                        SIM_run_alone(self.setAllHap, False)
                        #self.lgr.debug('contextManager DEBUG, was not watching, no debug list not in maze breakout, watch all but maze')
                else:
                    ''' Some other tasks are in the debug list '''
                    if new_task in self.nowatch_list:
                        SIM_run_alone(self.setAllHap, True)
                        #self.lgr.debug('contextManager DEBUG, was not watching, has a debug list; task in maze breakout, watch ONLY maze breaks')
                    else:
                        #self.lgr.debug('contextManager DEBUG, was not watching, has a debug list; task NOT in maze breakout, keep not watching')
                        pass
        else:
            ''' was watching tasks '''
            if new_task in self.watch_rec_list:
                ''' should be watching new tasks '''
                if new_task in self.nowatch_list:
                    ''' but it is in  the nowatch list clear all but maze'''
                    SIM_run_alone(self.clearAllHap, True)
                    #self.lgr.debug('contextManager DEBUG, was watching, task in debug list; task in maze breakout, delete all but maze breaks')
                elif prev_task in self.nowatch_list:
                    SIM_run_alone(self.clearAllHap, False)
                    SIM_run_alone(self.setAllHap, False)
                    #self.lgr.debug('contextManager DEBUG, was watching, task in debug list; not in maze breakout, previous was in maze, delete haps and create all but maze')
                else:
                    #self.lgr.debug('contextManager DEBUG, was watching, task in debug list; not in maze breakout, previous not in maze, haps should be good as is.')
                    pass
            else:
                ''' New task not in debug list '''
                if new_task in self.nowatch_list:
                    if prev_task in self.nowatch_list:
                        #self.lgr.debug('contextManager DEBUG, was watching, task NOT in debug list; task in maze breakout, as was the previous task, should be good as is.')
                        pass
                    else:
                        #self.lgr.debug('contextManager DEBUG, was watching, task NOT in debug list; task in maze breakout, previous task was not, delete all and set only maze.')
                        SIM_run_alone(self.clearAllHap, False)
                        SIM_run_alone(self.setAllHap, True)
                else:
                    ''' New task not in maze breakout'''
                    #self.lgr.debug('contextManager DEBUG, was watching, task NOT in debug list; task not in maze breakout.  Delete all haps.')
                    self.restoreDefaultContext() 
                    SIM_run_alone(self.clearAllHap, False)
                    self.watching_tasks = False
                    if len(self.watch_rec_list) == 0 and len(self.nowatch_list) == 0:
                        #self.lgr.debug('contextManager DEBUG, nothing else to watch, stop task rec monitoring') 
                        self.stopWatchTasks()
        
    def changedThread(self, cpu, third, forth, memory):
        ''' guts of context managment.  set or remove breakpoints/haps 
            depending on whether we are tracking the newly scheduled process '''
        if self.task_hap is None:
            return
        # get the value that will be written into the current thread address
        new_addr = SIM_get_mem_op_value_le(memory)
        prev_task = self.task_utils.getCurTaskRec()

        
        #DEBUG BLOCK
        pid = self.mem_utils.readWord32(cpu, new_addr + self.param.ts_pid)
        comm = self.mem_utils.readString(cpu, new_addr + self.param.ts_comm, 16)
        prev_pid = self.mem_utils.readWord32(cpu, prev_task + self.param.ts_pid)
        prev_comm = self.mem_utils.readString(cpu, prev_task + self.param.ts_comm, 16)
        '''
        self.lgr.debug('changeThread from %d (%s) to %d (%s) new_addr 0x%x watchlist len is %d debugging_comm is %s context %s watchingTasks %r' % (prev_pid, 
            prev_comm, pid, comm, new_addr, len(self.watch_rec_list), str(self.debugging_comm), cpu.current_context, self.watching_tasks))
        '''
       
       
        if len(self.pending_watch_pids) > 0:
            ''' Are we waiting to watch pids that have not yet been scheduled?
                We don't have the process rec until it is ready to schedule. '''
            if pid in self.pending_watch_pids:
                #self.lgr.debug('changedThread, pending add pid %d to watched processes' % pid)
                self.watch_rec_list[new_addr] = pid
                self.pending_watch_pids.remove(pid)
                self.watchExit(rec=new_addr, pid=pid)
        if pid not in self.pid_cache and comm in self.debugging_comm and pid not in self.no_watch:
           group_leader = self.mem_utils.readPtr(cpu, new_addr + self.param.ts_group_leader)
           leader_pid = self.mem_utils.readWord32(cpu, group_leader + self.param.ts_pid)
           add_it = False
           if leader_pid in self.pid_cache:
               add_it = True
           elif pid == leader_pid:
               parent = self.mem_utils.readPtr(cpu, new_addr + self.param.ts_real_parent)
               if parent in self.watch_rec_list:
                   parent_pid = self.mem_utils.readWord32(cpu, parent + self.param.ts_pid)
                   self.lgr.debug('contextManager new clone %d is its own leader, but parent %d is in cache.  Call the parent the leader.' % (pid, parent_pid))
                   add_it = True
                   leader_pid = parent_pid
               else:
                   #self.lgr.debug('contextManager pid:%d (%s) not in cache, nor is parent in watch_rec_list 0x%x' % (pid, comm, parent))
                   pass
           if add_it:
               ''' TBD, we have no reason to believe this clone is created by the group leader? Using parent or real_parent is no help'''
               self.lgr.debug('contextManager adding clone %d (%s) leader is %d' % (pid, comm, leader_pid))
               self.addTask(pid, new_addr)
               self.top.addProc(pid, leader_pid, comm, clone=True)
               self.watchExit(new_addr, pid)
               self.top.recordStackClone(pid, leader_pid)
           else:
               pass
               #self.lgr.debug('contextManager pid:%d (%s) not in cache, group leader 0x%x  leader pid %d' % (pid, comm, group_leader, leader_pid))
        elif pid in self.pid_cache and new_addr not in self.watch_rec_list:
            self.lgr.debug('***********   pid in cache, but new_addr not in watch list? eh?')

        self.alterWatches(new_addr, prev_task)
        if self.catch_pid == pid:
            self.lgr.debug('contextManager changedThread do catch_callback for pid %d' % pid)
            #SIM_break_simulation('in pid %d' % pid)
      
            SIM_run_alone(self.catch_callback, None)
            self.catch_pid = None
              
    def catchPid(self, pid, callback):
        self.catch_pid = pid
        self.catch_callback = callback 

    def watchAll(self):
        self.watch_only_this = False

    def watchOnlyThis(self):
        ctask = self.task_utils.getCurTaskRec()
        cur_pid = self.mem_utils.readWord32(self.cpu, ctask + self.param.ts_pid)
        pcopy = list(self.pid_cache)
        for pid in pcopy:
            if pid != cur_pid:
                self.rmTask(pid)
        self.watch_only_this = True

    def delPidRecAlone(self, pid):
        SIM_delete_breakpoint(self.task_rec_bp[pid])
        self.lgr.debug('contextManger rmTask pid %d' % pid)
        if pid in self.task_rec_hap and self.task_rec_hap[pid] is not None:
            RES_hap_delete_callback_id('Core_Breakpoint_Memop', self.task_rec_hap[pid])        
        del self.task_rec_bp[pid]
        del self.task_rec_hap[pid]
        del self.task_rec_watch[pid]
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
            #self.lgr.debug('rmTask removing rec 0x%x for pid %d, len now %d' % (rec, pid, len(self.watch_rec_list)))
            if pid in self.pid_cache:
                self.pid_cache.remove(pid)
                self.lgr.debug('rmTask remove %d from cache, cache now %s' % (pid, str(self.pid_cache)))
            
            if pid in self.task_rec_bp and self.task_rec_bp[pid] is not None:
                self.delPidRecAlone(pid)
            if len(self.watch_rec_list) == 0:
                if len(self.debugging_comm) == 0:
                    self.lgr.warning('contextManager rmTask debugging_comm is None')
               
                if len(self.pending_watch_pids) > 0:
                    self.debugging_pid = self.pending_watch_pids[0]
                    self.lgr.debug('contextManager rmTask, list empty but found pending watch pid %d, make it the debug pid' % self.debugging_pid)
                else:
                    #self.debugging_comm = None
                    #self.debugging_cell = None
                    pids = []
                    for comm in self.debugging_comm:
                        comm_pids = self.task_utils.getPidsForComm(comm) 
                        pids.extend(comm_pids)
                    if len(pids) == 0 or (len(pids)==1 and pids[0]==pid):
                        self.lgr.debug('contextManager rmTask watch_rec_list empty, clear debugging_pid')
                        self.cpu.current_context = self.default_context
                        self.stopWatchTasks()
                        retval = True
                    else:
                        ''' TBD fix to handle multiple comms '''
                        self.lgr.debug('contextManager rmTask, still pids for comm %s, was fork? set dbg pid to %d pids was %s' % (str(self.debugging_comm), pids[-1], str(pids)))
                        if self.top.swapSOPid(pid, pids[-1]):
                            ''' replace SOMap pid with new one from fork '''
                            self.lgr.debug('Adding task %d and setting debugging pid' % pids[-1])
                            self.addTask(pids[-1])
                            self.debugging_pid = pids[-1]
                        else:
                            ''' TBD poor hueristic for deciding it was not a fork '''
                            self.cpu.current_context = self.default_context
                            self.stopWatchTasks()
                            retval = True
            elif pid == self.debugging_pid:
                self.debugging_pid = self.pid_cache[0]
                self.lgr.debug('rmTask debugging_pid now %d' % self.debugging_pid)
            else:
                self.lgr.debug('rmTask remaining debug recs %s' % str(self.watch_rec_list))
        return retval

    def addTask(self, pid, rec=None):
        if rec is None:
            rec = self.task_utils.getRecAddrForPid(pid)
        if rec not in self.watch_rec_list:
            if rec is None:
                #self.lgr.debug('genContextManager, addTask got rec of None for pid %d, pending' % pid)
                self.pending_watch_pids.append(pid)
            else:
                #self.lgr.debug('genContextManager, addTask pid %d add rec 0x%x' % (pid, rec))
                self.watch_rec_list[rec] = pid
                self.watchExit(rec=rec, pid=pid)
            if pid not in self.pid_cache:
                self.pid_cache.append(pid)
        else:
            #self.lgr.debug('addTask, already has rec 0x%x for PID %d' % (rec, pid))
            pass

    def watchingThis(self):
        ctask = self.task_utils.getCurTaskRec()
        dumb, comm, cur_pid  = self.task_utils.curProc()
        if cur_pid in self.pid_cache or ctask in self.watch_rec_list or cur_pid in self.task_rec_hap or cur_pid in self.demise_cache:
            #self.lgr.debug('am watching pid:%d' % cur_pid)
            return True
        else:
            #self.lgr.debug('not watching %d' % cur_pid)
            return False

    def amWatching(self, pid):
        ctask = self.task_utils.getCurTaskRec()
        dumb, comm, cur_pid  = self.task_utils.curProc()
       
        if pid == cur_pid and (ctask in self.watch_rec_list or len(self.watch_rec_list)==0):
            return True
        elif pid in self.pid_cache:
            return True
        elif pid == self.task_utils.recentExitPid():
            return True
        else:
            return False

    def restoreDefaultContext(self):
        self.cpu.current_context = self.default_context
        #self.lgr.debug('contextManager restoreDefaultContext')

    def restoreDebugContext(self):
        self.cpu.current_context = self.resim_context
        #self.lgr.debug('contextManager restoreDebugContext')

    def restoreDebug(self):
        self.debugging_pid = self.debugging_pid_saved
        self.watch_rec_list = self.watch_rec_list_saved.copy()
        for ctask in self.watch_rec_list:
            self.pid_cache.append(self.watch_rec_list[ctask])
        self.cpu.current_context = self.resim_context
        self.lgr.debug('contextManager restoreDebug set cpu context to resim, debugging_pid to %s' % str(self.debugging_pid))

    def stopWatchPid(self, pid):
        SIM_run_alone(self.stopWatchPidAlone, pid)

    def stopWatchPidAlone(self, pid):
        if pid in self.task_rec_bp:
            if self.task_rec_bp[pid] is not None:
                #self.lgr.debug('stopWatchPid delete bp %d' % self.task_rec_bp[pid])
                SIM_delete_breakpoint(self.task_rec_bp[pid])
                RES_hap_delete_callback_id('Core_Breakpoint_Memop', self.task_rec_hap[pid])        
            del self.task_rec_bp[pid]
            del self.task_rec_hap[pid]
        ctask = self.task_utils.getCurTaskRec()
        cur_pid = self.mem_utils.readWord32(self.cpu, ctask + self.param.ts_pid)
        if pid == cur_pid and self.debugging_pid is not None:
            ''' we are stopping due to a clone doing an exec or something similar.  in any event, remove haps and change context if needed '''
            ''' TBD, do this in some other function? '''
            SIM_run_alone(self.clearAllHap, False)
            self.watching_tasks = False
            self.restoreDefaultContext() 
            self.lgr.debug('No longer watching pid %d' % pid)
        
    def stopWatchTasks(self):
        self.stopWatchTasksAlone(None)
        #SIM_run_alone(self.stopWatchTasksAlone, None)

    def stopWatchTasksAlone(self, dumb):
        if self.task_break is None:
            self.lgr.debug('stopWatchTasks already stopped')
            return
        self.lgr.debug('stopWatchTasks delete hap')
        SIM_delete_breakpoint(self.task_break)
        if self.task_hap is not None:
            RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_hap)
        self.task_hap = None
        self.task_break = None
        self.watching_tasks = False
        self.watch_rec_list_saved = self.watch_rec_list.copy()
        if self.debugging_pid is not None:
            self.debugging_pid_saved = self.debugging_pid
        self.watch_rec_list = {}
       
        ''' stop watching for death of tasks ''' 
        for pid in self.task_rec_bp:    
            if self.task_rec_bp[pid] is not None:
                #self.lgr.debug('stopWatchTasks delete bp %d' % self.task_rec_bp[pid])
                SIM_delete_breakpoint(self.task_rec_bp[pid])
                if pid in self.task_rec_hap and self.task_rec_hap[pid] is not None:
                    RES_hap_delete_callback_id('Core_Breakpoint_Memop', self.task_rec_hap[pid])        
        self.task_rec_bp = {}
        self.task_rec_hap = {}
        self.task_rec_watch = {}
        self.pid_cache = []
        self.debugging_pid = None

        cpu, dumb, dumb2  = self.task_utils.curProc()
        cpu.current_context = self.default_context
        self.lgr.debug('stopWatchTasks reverted %s to default context %s' % (cpu.name, str(self.default_context)))

    def resetWatchTasks(self, dumb=None):
        ''' Intended for use when going back in time '''
        self.lgr.debug('resetWatchTasks')
        self.stopWatchTasks()
        self.watchTasks(set_debug_pid = True)
        if not self.watch_only_this:
            ctask = self.task_utils.getCurTaskRec()
            pid = self.mem_utils.readWord32(self.cpu, ctask + self.param.ts_pid)
            self.lgr.debug('resetWatchTasks pid %d' % pid)
            if pid == 1:
                self.lgr.debug('resetWatchTasks got leader pid of 1, skip')
                return
            leader_pid = self.task_utils.getGroupLeaderPid(pid)
            pid_list = self.task_utils.getGroupPids(leader_pid)
            for pid in pid_list:
                if pid == 1:
                    self.lgr.debug('resetWatchTasks got pid of 1, skip')
                else:
                    self.addTask(pid)

    def setTaskHap(self):
        #print('genContextManager setTaskHap debugging_cell is %s' % self.debugging_cell)
        self.task_break = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                             self.phys_current_task, self.mem_utils.WORD_SIZE, 0)
        #self.lgr.debug('genContextManager setTaskHap bp %d' % self.task_break)
        self.task_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.changedThread, self.cpu, self.task_break)
        #self.lgr.debug('setTaskHap cell %s break %d set on physical 0x%x' % (self.cell_name, self.task_break, self.phys_current_task))

    def restoreWatchTasks(self):
        self.watching_tasks = True
        if self.debugging_pid is not None:
            self.lgr.debug('contextManager restoreWatchTasks cpu context to resim')
            self.cpu.current_context = self.resim_context

    def watchTasks(self, set_debug_pid = False):
        if self.task_break is not None:
            self.lgr.debug('watchTasks called, but already watching')
            return
        ctask = self.task_utils.getCurTaskRec()
        cell, comm, pid  = self.task_utils.curProc()
        if pid == 1:
            self.lgr.debug('contextManager watchTasks, pid is 1, ignore')
            return
        if self.task_break is None:
            self.setTaskHap()
        self.watching_tasks = True
        if self.watchExit():
            #self.pageFaultGen.recordPageFaults()
            if ctask in self.watch_rec_list:
                self.lgr.debug('watchTasks, current task already being watched')
                return
            #self.lgr.debug('watchTasks cell %s watch record 0x%x pid: %d set_debug_pid: %r' % (self.cell_name, ctask, pid, set_debug_pid))
            self.watch_rec_list[ctask] = pid
        else:
            self.lgr.warning('watchTasks, call to watchExit failed pid %d' % pid)
        if pid not in self.pid_cache:
            self.pid_cache.append(pid)
        group_leader = self.task_utils.getGroupLeaderPid(pid)
        if group_leader != self.group_leader:
            #self.lgr.debug('contextManager watchTasks x set group leader to %d' % group_leader)
            self.group_leader = group_leader
        if set_debug_pid:
            self.setDebugPid()
        if comm not in self.debugging_comm:
            self.debugging_comm.append(comm)
      
    def changeDebugPid(self, pid):
        if pid not in self.pid_cache:
            if len(self.pid_cache) > 0:
                self.lgr.error('contextManager changeDebugPid not in pid cache %d' % pid)
            return
        self.lgr.debug('changeDebugPid to %d' % pid)
        self.debugging_pid = pid

    def singleThread(self, single):
        self.single_thread = single

    def setDebugPid(self):
        if self.debugging_pid is not None:
            self.lgr.debug('contextManager setDebugPid already set to %d' % self.debugging_pid)
            return
        cell, comm, cur_pid  = self.task_utils.curProc()
        #self.default_context = self.cpu.current_context
        self.cpu.current_context = self.resim_context
        self.lgr.debug('contextManager setDebugPid %d, (%s) restored cpu to resim_context' % (cur_pid, comm))
        self.debugging_pid = cur_pid
        if comm not in self.debugging_comm:
            self.debugging_comm.append(comm)
        self.debugging_cell = self.top.getCell()
        if cur_pid not in self.pid_cache:
            self.pid_cache.append(cur_pid)

    def killGroup(self, lead_pid, exit_syscall):
        self.top.rmDebugExitHap()
        self.lgr.debug('contextManager killGroup lead %d' % lead_pid)
        pids = []
        if lead_pid == self.group_leader:
            for comm in self.debugging_comm:
                pids = self.task_utils.getPidsForComm(comm) 
                if lead_pid in pids:
                    break
            add_task = None
            for p in pids:
                if p not in self.pid_cache:
                    self.lgr.debug('killGroup found pid %d not in cache, was it a fork?  IGNORING killgroup' % p)
                    add_task =p
                    break
            if add_task is not None:
                self.lgr.debug('contextManager killGroup add_task is not None, swap pids')
                self.top.swapSOPid(self.debugging_pid, p)
                self.addTask(add_task)
            else:
                self.lgr.debug('contextManager killGroup %d is leader, pid_cache is %s' % (lead_pid, str(self.pid_cache)))
                cache_copy = list(self.pid_cache)
                for pid in cache_copy:
                    ida_msg = 'killed %d member of group led by %d' % (pid, lead_pid) 
                    exit_syscall.handleExit(pid, ida_msg, killed=True, retain_so=True)
                    #self.rmTask(pid, killed=True)
                    #if pid in self.demise_cache:
                    #    self.demise_cache.remove(pid)
                    if self.pageFaultGen is not None and self.exit_callback is None:
                        if self.pageFaultGen.handleExit(pid, lead_pid):
                            print('SEGV on pid %d?' % pid)
                            self.lgr.debug('genContextManager SEGV on pid %d -- stop trace of exit_syscall' % pid)
                            exit_syscall.stopTrace() 
                            break
                self.clearExitBreaks()
        elif self.group_leader != None:
            self.lgr.debug('contextManager killGroup NOT leader.  got %d, leader was %d' % (lead_pid, self.group_leader))
            if self.pageFaultGen is not None and self.exit_callback is None:
                self.pageFaultGen.handleExit(lead_pid, self.group_leader)
        else:
            self.lgr.debug('contextManager killGroup NO leader.  got %d' % (lead_pid))
            if self.pageFaultGen is not None and self.exit_callback is None:
                self.pageFaultGen.handleExit(lead_pid, lead_pid)


    def deadParrot(self, pid):
        ''' who knew? death comes betweeen the breakpoint and the "run alone" scheduling '''
        self.lgr.debug('contextManager deadParror pid %d' % pid)
        exit_syscall = self.top.getSyscall(self.cell_name, 'exit_group')
        if exit_syscall is not None and not self.watching_page_faults:
            ida_msg = 'pid:%d exit via kill?' % pid
            self.lgr.debug('contextManager deadParrot pid:%d rec no longer found call killGroup' % (pid))
            self.killGroup(pid, exit_syscall)
            self.rmTask(pid)
            #exit_syscall.handleExit(pid, ida_msg, killed=True)
        else:
            self.rmTask(pid)
            if self.pageFaultGen is not None and self.exit_callback is None:
                group_leader = self.task_utils.getGroupLeaderPid(pid)
                self.pageFaultGen.handleExit(pid, group_leader)
            self.clearExitBreaks()
            self.lgr.debug('contextManager deadParrot pid:%d rec no longer found removed task' % (pid))
        if self.exit_callback is not None:
            self.exit_callback()
        self.task_utils.setExitPid(pid)
        print('Process %d exited.' % pid)

    def resetAlone(self, pid):
        self.lgr.debug('contextManager resetAlone')
        dead_rec = self.task_utils.getRecAddrForPid(pid)
        if dead_rec is not None:
            list_addr = self.task_utils.getTaskListPtr(dead_rec)
            if list_addr is not None:
                self.lgr.debug('contextMgr resetAlone rec 0x%x of pid %d still found though written by maybe not dead after all? new list_addr is 0x%x' % (dead_rec, 
                    pid, list_addr))

                SIM_delete_breakpoint(self.task_rec_bp[pid])
                del self.task_rec_bp[pid] 
                RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_rec_hap[pid])
                del self.task_rec_hap[pid] 
                del self.task_rec_watch[pid] 
                self.watchExit(rec=dead_rec, pid = pid)
            else:
                self.lgr.debug('contextMgr resetAlone rec 0x%x of pid %d EXCEPT new list_addr is None call deadParrot' % (dead_rec, pid))
                self.deadParrot(pid)
        else: 
            self.lgr.debug('contextMgr resetAlone pid %d no record for pid, call deadParrot' % (pid))
            self.deadParrot(pid)
        if pid in self.demise_cache:
            self.demise_cache.remove(pid)

    def taskRecHap(self, pid, third, forth, memory):
        self.lgr.debug('taskRecHap pid %d' % pid)
        if pid not in self.task_rec_hap or pid in self.demise_cache:
            return
        dumb, comm, cur_pid  = self.task_utils.curProc()
        self.lgr.debug('contextManager taskRecHap demise of pid:%d by the hand of cur_pid %d?' % (pid, cur_pid))
        dead_rec = self.task_utils.getRecAddrForPid(pid)
        if dead_rec is not None:
            if pid != cur_pid:
                self.lgr.debug('contextManager taskRecHap got record 0x%x for %d, call resetAlone' % (dead_rec, pid))
                self.demise_cache.append(pid)
                SIM_run_alone(self.resetAlone, pid)
            else:
                self.lgr.debug('Pid %d messing with its own task rec?  Let it go.' % pid)

        else: 
            value = SIM_get_mem_op_value_le(memory)
            self.lgr.debug('contextManager taskRecHap pid:%d wrote 0x%x to 0x%x watching for demise of %d' % (cur_pid, value, memory.logical_address, pid))
            exit_syscall = self.top.getSyscall(self.cell_name, 'exit_group')
            if exit_syscall is not None and not self.watching_page_faults:
                ida_msg = 'pid:%d exit via kill?' % pid
                self.killGroup(pid, exit_syscall)
                #exit_syscall.handleExit(pid, ida_msg, killed=True)
            else:
                self.rmTask(pid)
            if self.exit_callback is not None:
                self.exit_callback()

    def setExitCallback(self, callback):
        self.exit_callback = callback

    def watchGroupExits(self, pid=None):
        if pid is None:
            dumb, comm, cur_pid  = self.task_utils.curProc()
        else:
            cur_pid = pid
        leader_pid = self.task_utils.getGroupLeaderPid(cur_pid)
        if leader_pid is None:
            self.lgr.error('contextManager watchGroupExits no group leader for %d' % cur_pid) 
        self.lgr.debug('contextManager watchGroupExit cur_pid %d, leader %d' % (cur_pid, leader_pid))
        pid_dict = self.task_utils.getGroupPids(leader_pid)
        for pid in pid_dict:
            self.watchExit(rec=pid_dict[pid], pid=pid)

    def watchExit(self, rec=None, pid=None):
        retval = True
        ''' set breakpoint on task record that points to this (or the given) pid '''
        #self.lgr.debug('contextManager watchExit')
        dumb, comm, cur_pid  = self.task_utils.curProc()
        if pid is None and cur_pid == 1:
            self.lgr.debug('watchExit for pid 1, ignore')
            return False
        if pid is None:
            pid = cur_pid
            rec = self.task_utils.getCurTaskRec() 
        elif rec is None:
            rec = self.task_utils.getRecAddrForPid(pid)
        if rec is None:
            #self.lgr.debug('contextManager watchExit failed to get list_addr pid %d cur_pid %d ' % (pid, cur_pid))
            return False
        list_addr = self.task_utils.getTaskListPtr(rec)
        if list_addr is None:
            ''' suspect the thread is in the kernel, e.g., on a syscall, and has not yet been formally scheduled, and thus
                has no place in the task list? OR all threads share the same next_ts pointer'''
            #self.lgr.debug('contextManager watchExit failed to get list_addr pid %d cur_pid %d rec 0x%x' % (pid, cur_pid, rec))
            return False
        
        if pid not in self.task_rec_bp or self.task_rec_bp[pid] is None:
            watch_pid, watch_comm = self.task_utils.getPidCommFromNext(list_addr)
            if watch_pid in self.pid_cache:
                #cell = self.resim_context
                cell = self.default_context
            else:
                cell = self.default_context
                #cell = self.resim_context
            #self.lgr.debug('Watching next record of pid:%d (%s) for death of pid:%d break on 0x%x context: %s' % (watch_pid, watch_comm, pid, list_addr, cell))
            self.task_rec_bp[pid] = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Write, list_addr, self.mem_utils.WORD_SIZE, 0)
            #bp = self.genBreakpoint(cell, Sim_Break_Linear, Sim_Access_Write, list_addr, self.mem_utils.WORD_SIZE, 0)
            #self.lgr.debug('contextManager watchExit cur pid:%d set list break %d at 0x%x for pid %d context %s' % (cur_pid, self.task_rec_bp[pid], 
            #     list_addr, pid, str(cell)))
            #self.task_rec_hap[pid] = self.genHapIndex("Core_Breakpoint_Memop", self.taskRecHap, pid, bp)
            #self.lgr.debug('contextManager watchExit pid %d bp: %d' % (pid, self.task_rec_bp[pid]))
            self.task_rec_hap[pid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.taskRecHap, pid, self.task_rec_bp[pid])
            self.task_rec_watch[pid] = list_addr
        else:
            #self.lgr.debug('contextManager watchExit, already watching for pid %d' % pid)
            pass
        return retval

    def auditExitBreaks(self):
        for pid in self.task_rec_watch:
            rec = self.task_utils.getRecAddrForPid(pid)
            if rec is None:
                self.lgr.debug('contextManager auditExitBreaks failed to get task record for pid %d' % pid)
            else:     
                list_addr = self.task_utils.getTaskListPtr(rec)
                if list_addr is None:
                    ''' suspect the thread is in the kernel, e.g., on a syscall, and has not yet been formally scheduled, and thus
                        has no place in the task list? '''
                    self.lgr.debug('contextManager auditExitBreaks failed to get list_addr pid %d rec 0x%x' % (pid, rec))
                elif self.task_rec_watch[pid] is None:
                    watch_pid, watch_comm = self.task_utils.getPidCommFromNext(list_addr) 
                    self.lgr.debug('contextManager auditExitBreaks rec_watch for %d is None, but taskUtils reports %d' % (pid, watch_pid)) 
                elif list_addr != self.task_rec_watch[pid]:
                    watch_pid, watch_comm = self.task_utils.getPidCommFromNext(list_addr) 
                    prev_pid, prev_comm = self.task_utils.getPidCommFromNext(self.task_rec_watch[pid]) 
                    self.lgr.debug('contextManager auditExitBreaks changed in record watch for death of %d, was watching %d, now %d' % (pid, watch_pid, prev_pid))
        
    def setExitBreaks(self):
        #self.lgr.debug('contextManager setExitBreaks')
        for pid in self.task_rec_bp:
            rec = self.task_utils.getRecAddrForPid(pid)
            self.watchExit(rec, pid)

    def clearExitBreaks(self):
        SIM_run_alone(self.clearExitBreaksAlone, None)

    def clearExitBreaksAlone(self, dumb):
        self.lgr.debug('contextManager clearExitBreaks')
        for pid in self.task_rec_bp:
            if self.task_rec_bp[pid] is not None:
                SIM_delete_breakpoint(self.task_rec_bp[pid])
                self.task_rec_bp[pid] = None
                #self.lgr.debug('contextManager clearExitBreaks pid:%d' % pid)
        for pid in self.task_rec_hap:
            if self.task_rec_hap[pid] is not None:
                RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_rec_hap[pid])
                self.task_rec_hap[pid] = None

    def resetBackStop(self):
        pass

    def getIdaMessage(self):
        return self.ida_message

    def getDebugPid(self):
        return self.debugging_pid, self.cpu

    def showIdaMessage(self):
        print('genMonitor says: %s' % self.ida_message)
        self.lgr.debug('genMonitor says: %s' % self.ida_message)

    def setIdaMessage(self, message):
        #self.lgr.debug('ida message set to %s' % message)
        self.ida_message = message

    def getRESimContext(self):
        return self.resim_context

    def getDefaultContext(self):
        return self.default_context

    def watchPageFaults(self, watching):
        self.watching_page_faults = watching

    def callMe(self, pageFaultGen):
        self.pageFaultGen = pageFaultGen

    def getWatchPids(self):
        return self.task_rec_bp.keys()

    def noWatch(self, pid):
        self.no_watch.append(pid)
        if pid in self.pid_cache:
            self.pid_cache.remove(pid)
        self.rmTask(pid)
        self.lgr.debug('contectManager noWatch pid:%d' % pid)
