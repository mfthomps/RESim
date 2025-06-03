from simics import *
from resimHaps import *
import winProg
import resimSimicsUtils
import os
import memUtils
from taskUtils import COMM_SIZE
'''
Track task context and set/remove beakpoints & haps accordingly.  Currently recognises two contexts:
default & RESim.  Also has a carve-out for "maze_exit" breakpoints/haps, managed as an attribute of 
the hap.  Designed to watch a single thread group.
There is one instance of this module per cell.


REVISED context scheme.
   default -- set when not one of the following
   debug  -- for process (and its threads) currently being debugged.  
   ignore -- set when scheduled programs that are to be ignored.  
   suspend -- set while executing from a skipped so/dll.

   ignoring programs -- keeps a list of programs to be ignored.  When scheduled, the ignore
   context is set.  It is not intended that any breakpoints have this context.

   skipping code -- suspend tracing while in a given so/dll, and restore when some other dll 
   is entered.  When the dll is hit, the suspend context is set, haps are cleared and then
   breaks are set on all good code, with the suspend context.  Keeps a list of pid-threads
   that are in suspend and restores suspend context when these are scheduled.  When unscheduled,
   new context depends on new process.


NOTE: PIDs in this module are generally numeric pids without thread qualifications,
except for interfaces are tids.
Thread records are used to find the current process (PID).

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
        self.enabled = True
        if addr is None:
            lgr.error('GenBreakpoint called with addr of None.')

    def show(self):
        print('\tbreak_handle: %s num: %s  add:0x%x enabled: %r' % (str(self.handle), str(self.break_num), self.addr, self.enabled))
        self.lgr.debug('\tbreak_handle: %s num: %s  add:0x%x enabled: %r' % (str(self.handle), str(self.break_num), self.addr, self.enabled))

    def clear(self):
        if self.break_num is not None:
            #self.lgr.debug('GenBreakpoint clear breakpoint %d break handle is %d' % (self.break_num, self.handle))
            RES_delete_breakpoint(self.break_num)
            #self.lgr.debug('GenBreakpoint back from clear breakpoint %d break handle is %d' % (self.break_num, self.handle))
            self.break_num = None

    def disable(self):
        SIM_disable_breakpoint(self.break_num)
        self.enabled = False

    def enable(self):
        #self.lgr.debug('GenBreakpoint enable break_num %d' % self.break_num)
        SIM_enable_breakpoint(self.break_num)
        self.enabled = True

class GenHap():
    def __init__(self, hap_type, callback, parameter, handle, lgr, breakpoint_list, name, disable_forward, conf, cpu, immediate=True):
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
        self.conf = conf
        self.cpu = cpu
        self.disable_forward = disable_forward
        self.set(immediate)
        self.disabled = False

    def show(self):
        if self.handle is not None and self.hap_num is not None:
            print('hap_handle: %d  num: %d name: %s context: %s' % (self.handle, self.hap_num, self.name, self.getContext()))
            self.lgr.debug('hap_handle: %d  num: %d name: %s context: %s' % (self.handle, self.hap_num, self.name, self.getContext()))
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
            # TBD remove breakpoint ranges. Simics has no way to ensure sequential bp's
            for bp in self.breakpoint_list:
                bp.break_num = SIM_breakpoint(bp.cell, bp.addr_type, bp.mode, bp.addr, bp.length, bp.flags)
                if bp.prefix is not None:
                    resimSimicsUtils.setBreakpointPrefix(self.conf, bp.break_num, bp.prefix)
                    #command = 'set-prefix %d "%s"' % (bp.break_num, bp.prefix)
                    #SIM_run_alone(SIM_run_command, command)
                    #self.lgr.debug('contextManager prefix cmd: %s' % command)

                #self.lgr.debug('GenHap breakpoint created for hap_handle %d  assigned breakpoint num %d cell %s' % (self.handle, bp.break_num, bp.cell))
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
            #self.lgr.debug('GenHap set call breakpoint')
            bp.break_num = SIM_breakpoint(bp.cell, bp.addr_type, bp.mode, bp.addr, bp.length, bp.flags)
            #self.lgr.debug('GenHap set back from call breakpoint')
            if bp.prefix is not None:
                resimSimicsUtils.setBreakpointPrefix(self.conf, bp.break_num, bp.prefix)
                #command = 'set-prefix %d "%s"' % (bp.break_num, bp.prefix)
                #self.lgr.debug('contextManager prefix cmd: %s' % command)
                #SIM_run_alone(SIM_run_command, command)
                #self.lgr.debug('contextManager prefix cmd: %s' % command)
            #self.lgr.debug('GenHap set hap_handle %s name: %s on breakpoint %s (0x%x) break_handle %s cell %s ' % (str(self.handle), 
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

    def disable(self, direction='forward', filter=None):
        if not (direction == 'forward' and not self.disable_forward):
            for bp in self.breakpoint_list:
                bp.disable()
            self.disabled = True

    def enable(self):
        #self.lgr.debug('GenHap enable %s cycles: 0x%x' % (self.name, self.cpu.cycles))
        for bp in self.breakpoint_list:       
            #self.lgr.debug('GenHap enable bp %d cycles: 0x%x' % (bp.break_num, self.cpu.cycles))
            bp.enable()
        self.disabled = False

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
        self.debugging_tid = None
        self.debugging_tid_saved = None
        self.debugging_comm = []
        self.debugging_cell = None
        self.cpu = cpu
        self.pageFaultGen = None
        ''' watch multiple tasks, e.g., threads '''
        self.watch_rec_list = {}
        self.watch_rec_list_saved = {}
        self.pending_watch_tids = []
        self.nowatch_list = []
        self.suspend_watch_list = []
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
        #self.text_start = None
        #self.text_end = None
        self.catch_tid = None
        self.catch_callback = None
        self.watch_only_this = False
        ''' used with afl '''
        self.callback = None
        self.exit_callback = None  


        self.context_map = {}
        self.map_context = {}

        obj = SIM_get_object(cell_name)
        self.default_context = obj.cell_context
        self.context_map[obj.cell_context] = cell_name
        self.map_context[cell_name] = obj.cell_context

        context = 'RESim_%s' % cell_name
        cmd = 'new-context %s' % context
        SIM_run_command(cmd)
        obj = SIM_get_object(context)
        self.resim_context = obj
        self.context_map[obj] = context
        self.map_context[context] = obj
        self.lgr.debug('context_manager cell %s resim_context defined as obj %s' % (self.cell_name, str(obj)))

        ignore = 'ignore_%s' % cell_name
        cmd = 'new-context %s' % ignore
        SIM_run_command(cmd)
        obj = SIM_get_object(ignore)
        self.ignore_context = obj
        self.lgr.debug('context_manager cell %s ignore_context defined as obj %s' % (self.cell_name, str(obj)))

        suspend = 'suspend_%s' % cell_name
        cmd = 'new-context %s' % suspend
        SIM_run_command(cmd)
        obj = SIM_get_object(suspend)
        self.suspend_context = obj
        self.lgr.debug('context_manager cell %s suspend_context defined as obj %s' % (self.cell_name, str(obj)))

        ''' avoid searching all task recs to know if tid being watched '''
        self.tid_cache = []
        self.group_leader = None

        ''' watch pointers to task recs to catch kills '''
        self.task_rec_hap = {}
        self.task_rec_bp = {}
        self.task_rec_watch = {}
        ''' avoid multiple calls to taskRecHap '''
        self.demise_cache = []

        ''' used by pageFaultGen to supress breaking on apparent kills '''
        self.watching_page_faults = False

        ''' Do not watch these tids, while debugging other tids '''
        self.no_watch = []
        ''' Ignore programs while tracing all with no debugging '''
        self.ignore_progs = [] 
        self.ignore_tids = [] 

        self.only_progs = [] 

        self.ignore_threads = []

        self.watch_for_prog = []
        self.watch_for_prog_callback = {}
        self.current_tasks = []

        self.comm_prog_map = {}
        self.soMap = None

        ''' keep track of this ourselves because when simics reverses it does not know if it
            is afoot or horseback. '''
        self.current_context = self.default_context
        self.reverse_context = False

        ''' ad hoc scheme for detecting that a clone was execve'd, and thus we should not be watching any more. '''
        self.my_clones = {}

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

    def getHapName(self, real_bp):
        for hap in self.haps:
            #self.lgr.debug('getBreakHandle hap %s' % (hap.name))
            for bp in hap.breakpoint_list:
                #self.lgr.debug('getBreakHandle look for %d got %d' % (real_bp, bp.break_num))
                if bp.break_num == real_bp:
                    return hap.name
        return None

    def showHaps(self, filter=None):
        self.lgr.debug('contextManager showHaps')
        for hap in self.haps:
            if filter is not None:
                if filter in hap.name:
                    hap.show()
            else:
                hap.show()

    #def getRESimContext(self):
    #    return self.debugging_cell

    #def recordText(self, start, end):
    #    self.lgr.debug('contextMgr recordText 0x%x 0x%x' % (start, end))
    #    self.text_start = start
    #    self.text_end = end

    #def getText(self):
    #    return self.text_start, self.text_end

    def nextHapHandle(self):
        self.hap_handle = self.hap_handle+1
        return self.hap_handle 

    def nextBreakHandle(self):
        self.break_handle = self.break_handle+1
        return self.break_handle 

    def getBPContext(self, handle):
        for bp in self.breakpoints:
            if bp.handle == handle:
                return bp.cell
        return None

    def genBreakpoint(self, cell, addr_type, mode, addr, length, flags, prefix=None):
        ''' create a GenContextManager breakpoint.  This is not yet set.
            Determine if the context should be resim, e.g., only when one of our
            debugging processes is schedule.
        '''
        handle = self.nextBreakHandle()
        if cell is None:
            if self.debugging_tid is not None and addr_type == Sim_Break_Linear:
                cell = self.resim_context
            else:
                cell = self.default_context
            #self.lgr.debug('gen break with context %s' % str(cell))
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

    def genDisableHap(self, hap_handle):
        for hap in self.haps:
            if hap.handle == hap_handle:
                hap.disable()
                break

    def genEnableHap(self, hap_handle):
        for hap in self.haps:
            if hap.handle == hap_handle:
                #self.lgr.debug('contextManager genEnableHap handle %d is hap %s, enable it' % (hap_handle, hap.name))
                hap.enable()
                break

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

    def genHapIndex(self, hap_type, callback, parameter, handle, name=None, disable_forward=True):
        #self.lgr.debug('genHapIndex break_handle %d' % handle)
        retval = None
        for bp in self.breakpoints:
            if bp.handle == handle:
                hap_handle = self.nextHapHandle()
                hap = GenHap(hap_type, callback, parameter, hap_handle, self.lgr, [bp], name, disable_forward, self.top.conf, self.cpu)
                self.haps.append(hap)
                retval = hap.handle
                break
        #if retval is None:
        #    self.lgr.error('genHapIndex failed to find break %d' % breakpoint)
        return retval

    def genHapRange(self, hap_type, callback, parameter, handle_start, handle_end, name=None, disable_forward=True):
        #self.lgr.debug('genHapRange break_handle %d %d' % (handle_start, handle_end))
        bp_start = None
        bp_list = []
        for bp in self.breakpoints:
            if bp.handle >= handle_start:
                bp_list.append(bp)
            if bp.handle == handle_end:
                hap_handle = self.nextHapHandle()
                hap = GenHap(hap_type, callback, parameter, hap_handle, self.lgr, bp_list, name, disable_forward, self.top.conf, self.cpu, immediate=True)
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

    def getThreadRecs(self):
        return self.watch_rec_list.keys()

    def getThreadTids(self):
        retval = []
        for rec in self.watch_rec_list:
            tid = self.watch_rec_list[rec]
            #self.lgr.debug('contextManager getThreadTids append %s to returned thread tid list' % (tid))
            retval.append(tid)
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

    def addSuspendWatch(self):
        ''' suspend watching of specific tid'''
        self.lgr.debug('contextManager cell %s addSuspendWatch' % self.cell_name)
        if self.top.isWindows(target=self.cell_name):
            rec = self.task_utils.getCurThreadRec()
        else:
            rec = self.task_utils.getCurThreadRec() 
        self.suspend_watch_list.append(rec)
        #SIM_run_alone(self.restoreSuspendContext, None)
        self.restoreSuspendContext()
        context = SIM_object_name(self.cpu.current_context)
        self.lgr.debug('contextManager addSuspendWatch for rec 0x%x context: %s' % (rec, context))

    def rmSuspendWatch(self):
        ''' Remove suspend watching of specific tid 
            If debugging, restore debug context. Otherwise restore default context.
        '''
        if self.top.isWindows(target=self.cell_name):
            rec = self.task_utils.getCurThreadRec()
        else:
            rec = self.task_utils.getCurThreadRec() 
        if rec in self.suspend_watch_list:
            self.suspend_watch_list.remove(rec)
            if self.debugging_tid is not None:
                #self.lgr.debug('contextManager rmSuspendWatch restore RESim context')
                SIM_run_alone(self.restoreDebugContext, None)
                #self.restoreDebugContext()
            else:
                SIM_run_alone(self.restoreDefaultContext, None)
                #self.restoreDefaultContext()
            context = SIM_object_name(self.cpu.current_context)
            #self.lgr.debug('contextManager rmSuspendWatch for rec 0x%x context now %s' % (rec, context))
        #else:
        #    #self.lgr.error('contextManager rmSuspendWatch rec 0x%x not in list' % rec)
        #    SIM_break_simulation('fix this')

    def addNoWatch(self):
        ''' only watch maze exits for the current task. NOTE: assumes those are set after call to this function'''
        ''' TBD remove nowatch_list after testing maze '''
        self.lgr.debug('contextManager cell %s addNoWatch' % self.cell_name)
        if len(self.nowatch_list) == 0 and len(self.watch_rec_list) == 0:
            ''' had not been watching and tasks.  start so we can not watch this one '''
            self.setTaskHap()
            self.watching_tasks=True
            self.lgr.debug('contextManager addNoWatch began watching tasks')
        if self.top.isWindows(target=self.cell_name):
            rec = self.task_utils.getCurThreadRec()
        else:
            rec = self.task_utils.getCurThreadRec() 
        self.nowatch_list.append(rec)
        self.lgr.debug('contextManager addNoWatch for rec 0x%x' % rec)

    def rmNoWatch(self):
        ''' restart watching the current task, assumes it was added via addNoWatch '''
        if self.top.isWindows(target=self.cell_name):
            rec = self.task_utils.getCurThreadRec()
        else:
            rec = self.task_utils.getCurThreadRec() 
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

    def isSuspended(self, task):
        retval = False
        if task in self.suspend_watch_list:
            retval = True
        return retval

    def alterWatches(self, new_task, prev_task, tid):
        # Change context depending...
        if self.isSuspended(new_task):
            SIM_run_alone(self.restoreSuspendContext, None)
            #self.restoreSuspendContext()
        elif new_task in self.watch_rec_list:
            if not self.isDebugContext() and self.debugging_tid is not None:
                #self.lgr.debug('contextManager alterWatches restore RESim context tid:%s' % tid)
                #SIM_run_alone(self.restoreDebugContext, None)
                self.restoreDebugContext()
            else:
                #self.lgr.debug('contextManager alterWatches tid:%s already was debug context' % tid)
                pass
        elif self.isDebugContext():
            #self.lgr.debug('contextManager alterWatches tid:%s restored default context' % tid)
            #SIM_run_alone(self.restoreDefaultContext, None)
            self.restoreDefaultContext()
        elif self.debugging_tid is None:
            #SIM_run_alone(self.restoreDefaultContext, None)
            self.restoreDefaultContext()

    def onlyOrIgnore(self, tid, comm, new_addr):

        ''' Handle igoring of processes 
            Assumes we only ignore when not debugging.
            However we could be switching to a suspended thread
        '''
        if tid is None:
            return False
        retval = False       
        #self.lgr.debug('onlyOrIgnore comm %s' % comm)
        if tid in self.ignore_threads:
            #self.lgr.debug('onlyOrIgnore tid:%s in ignore_threads' % tid)
            if self.cpu.current_context != self.ignore_context:
                #SIM_run_alone(self.restoreIgnoreContext, None)
                self.restoreIgnoreContext()
            retval = True
        elif len(self.ignore_progs) > 0 and self.debugging_tid is None:
            if comm in self.ignore_progs:
                #self.lgr.debug('onlyOrIgnore found comm %s' % comm)
                if self.cpu.current_context != self.ignore_context:
                    #self.lgr.debug('ignoring context for tid:%s comm %s' % (tid, comm))
                    #SIM_run_alone(self.restoreIgnoreContext, None)
                    self.restoreIgnoreContext()
                retval = True 
            elif len(self.suspend_watch_list) > 0:
                if new_addr is not None and self.isSuspended(new_addr):
                    #SIM_run_alone(self.restoreSuspendContext, None)
                    self.restoreSuspendContext()
                    retval = True 
                else:
                    #SIM_run_alone(self.restoreDefaultContext, None)
                    self.restoreDefaultContext()
                    if len(self.watch_for_prog) > 0: 
                        self.checkFirstSchedule(new_addr, tid, comm)
            else:
                #SIM_run_alone(self.restoreDefaultContext, None)
                self.restoreDefaultContext()
                if len(self.watch_for_prog) > 0: 
                    self.checkFirstSchedule(new_addr, tid, comm)
        elif len(self.only_progs) > 0 and self.debugging_tid is None:
            #self.lgr.debug('onlyOrIgnore tid:%s comm %s' % (tid, comm))
            if comm not in self.only_progs:
                if self.cpu.current_context != self.ignore_context:
                    #self.lgr.debug('ignoring context for comm tid:%s %s' % (tid, comm))
                    #SIM_run_alone(self.restoreIgnoreContext, None)
                    self.restoreIgnoreContext()
                retval = True 
            elif len(self.suspend_watch_list) > 0:
                if new_addr is not None and self.isSuspended(new_addr):
                    #self.lgr.debug('restore suspend context for tid:%s comm %s' % (tid, comm))
                    #SIM_run_alone(self.restoreSuspendContext, None)
                    self.restoreSuspendContext()
                    retval = True 
                else:
                    #SIM_run_alone(self.restoreDefaultContext, None)
                    self.restoreDefaultContext()
                    if len(self.watch_for_prog) > 0: 
                        self.checkFirstSchedule(new_addr, tid, comm)
            else:
                #SIM_run_alone(self.restoreDefaultContext, None)
                self.restoreDefaultContext()
                if len(self.watch_for_prog) > 0:
                    self.checkFirstSchedule(new_addr, tid, comm)
                if tid not in self.task_rec_bp or self.task_rec_bp[tid] is None:
                    #self.lgr.debug('contextManager is in only_prog, watch exit for tid: %s' % tid)
                    self.watchExit(tid=tid)
                #self.lgr.debug('restore default context for tid:%s comm %s' % (tid, comm))
            
            if tid is not None and self.catch_tid is not None:
                #self.lgr.debug('contextManager onlyOrIgnore self.catch_tid %s  tid %s' % (self.catch_tid, tid))
                if (self.catch_tid == tid or (self.catch_tid.endswith('-') and self.catch_tid[:-1] == tid.split('-')[0])):
                    #self.lgr.debug('contextManager onlyOrIgnore thread do catch_callback for tid %s' % tid)
                    #SIM_break_simulation('in tid %s' % tid)
                    if self.catch_callback is not None: 
                        self.lgr.debug('contextManager onlyOrIgnore do catch callback tid:%s' % tid)
                        SIM_run_alone(self.catch_callback, tid)
                    else:
                        SIM_break_simulation('changed thread, now in tid %s' % tid)
                    self.catch_tid = None
              
        return retval
    
      
    def changedThread(self, cpu, third, forth, memory):
        ''' guts of context managment.  set or remove breakpoints/haps 
            depending on whether we are tracking the newly scheduled process.
            Also manages breakpoints/haps for maze exits.  TBD alter so that if 
            maze is not an issue, no breakpoints are deleted or restored and we
            only rely on context. '''
        #self.lgr.debug('contextManager changedThread')
        if self.task_hap is None or self.reverse_context:
            return
        # get the value that will be written into the current thread address
        new_addr = memUtils.memoryValue(self.cpu, memory)
        thread_id = None
        if self.top.isWindows(target=self.cell_name):
            ptr = new_addr + self.param.proc_ptr
            phys_block = cpu.iface.processor_info.logical_to_physical(ptr, Sim_Access_Read)
            proc_addr = self.mem_utils.readPhysPtr(self.cpu, phys_block.address)
            if proc_addr is None:
                self.lgr.debug('contextManager changedThread proc_addr is None reading from ptr 0x%x' % ptr)
                return
            pid = self.mem_utils.readWord32(cpu, proc_addr + self.param.ts_pid)
            thread_id = self.task_utils.getThreadId(rec=new_addr)
            if pid is not None and thread_id is not None:
                tid = '%d-%d' % (pid, thread_id)
            else:
                self.lgr.debug('contextManager bad pid %s or thread_id %s' % (pid, thread_id))
        else:
           proc_addr = new_addr
           tid = str(self.mem_utils.readWord32(cpu, proc_addr + self.param.ts_pid))
        exit_tid = self.task_utils.getExitTid()
        #self.lgr.debug('contextManager changedThread exit_tid: %s' % exit_tid)
        if exit_tid is not None and tid.startswith(exit_tid):
            if self.top.isWindows(target=self.cell_name):
                if '-' in exit_tid:
                    self.lgr.debug('contextManager changedThread to exiting tid %s, bail' % tid)
                else:
                    self.lgr.debug('contextManager changedThread to exiting Process tid %s, bail' % tid)
            else:
                self.lgr.debug('contextManager changedThread to exiting tid %s, bail' % tid)
            return 
        prev_task = self.task_utils.getCurThreadRec()
        comm = self.mem_utils.readString(cpu, proc_addr + self.param.ts_comm, 16)
        
        #DEBUG BLOCK  Every thing until END can be commented out for performance/noise
        # SEE alterWatches for context juggling
        # TBD fix to use prev_tid
        #if self.top.isWindows():
        #    prev_proc = self.task_utils.getCurProcRec()
        #    prev_pid = self.mem_utils.readWord32(cpu, prev_proc + self.param.ts_pid)
        #    prev_thread_id = self.task_utils.getThreadId(rec=prev_task)
        #    prev_tid = '%d-%d' % (prev_pid, prev_thread_id)
        #else:
        #    prev_proc = prev_task
        #    prev_tid = str(self.mem_utils.readWord32(cpu, prev_proc + self.param.ts_pid))
        #prev_comm = self.mem_utils.readString(cpu, prev_proc + self.param.ts_comm, 16)

        #if self.top.isWindows(target=self.cell_name):
        #    self.lgr.debug('changeThread from %s (%s) to %s (%s) new_addr 0x%x watchlist len is %d debugging_comm is %s context %s watchingTasks %r cycles: 0x%x' % (prev_tid, 
        #        prev_comm, tid, comm, new_addr, len(self.watch_rec_list), str(self.debugging_comm), cpu.current_context, self.watching_tasks, self.cpu.cycles))
        #else:
        #    self.lgr.debug('changeThread from %s (%s) to %s (%s) new_addr 0x%x watchlist len is %d debugging_comm is %s context %s watchingTasks %r cycles: 0x%x' % (prev_tid, 
        #        prev_comm, tid, comm, new_addr, len(self.watch_rec_list), str(self.debugging_comm), cpu.current_context, self.watching_tasks, self.cpu.cycles))
        #END DEBUG BLOCK
        if comm is None:
            self.lgr.debug('contextManager comm is None for tid:%s, bail' % tid)
            return
        if self.onlyOrIgnore(tid, comm, new_addr):
            return 
        else:
            self.checkFirstSchedule(new_addr, tid, comm)
        if len(self.pending_watch_tids) > 0:
            ''' Are we waiting to watch tids that have not yet been scheduled?
                We don't have the process rec until it is ready to schedule. '''
            if tid in self.pending_watch_tids:
                self.lgr.debug('changedThread, pending add tid %s to watched processes' % tid)
                self.watch_rec_list[new_addr] = tid
                self.pending_watch_tids.remove(tid)
                self.watchExit(rec=new_addr, tid=tid)
        add_task = False
        if not self.top.isWindows(target=self.cell_name) and tid not in self.tid_cache and comm in self.debugging_comm and tid not in self.no_watch:
           ''' TBD fix for windows '''
           group_leader = self.mem_utils.readPtr(cpu, new_addr + self.param.ts_group_leader)
           leader_pid = self.mem_utils.readWord32(cpu, group_leader + self.param.ts_pid)
           leader_tid = str(leader_pid)
           add_task = False
           if leader_tid in self.tid_cache:
               add_task = True
           elif tid == leader_tid:
               parent = self.mem_utils.readPtr(cpu, new_addr + self.param.ts_real_parent)
               if parent in self.watch_rec_list:
                   parent_pid = self.mem_utils.readWord32(cpu, parent + self.param.ts_pid)
                   parent_tid = str(parent_pid)
                   self.lgr.debug('contextManager new clone %s comm: %s is its own leader, but parent %s is in cache.  Call the parent the leader.' % (tid, comm, parent_tid))
                   add_task = True
                   leader_tid = parent_tid
               else:
                   #self.lgr.debug('contextManager tid:%s (%s) not in cache, nor is parent in watch_rec_list 0x%x' % (tid, comm, parent))
                   pass
           if add_task:
               ''' TBD, we have no reason to believe this clone is created by the group leader? Using parent or real_parent is no help'''
               self.lgr.debug('contextManager adding clone %s (%s) leader is %s' % (tid, comm, leader_tid))
               ''' add task, but do not try to watch exit since we do not have proper context yet.  Will watch below'''
               self.addTask(tid, new_addr, watch_exit=False)
               self.task_utils.didClone(leader_tid, tid)
               self.my_clones[tid] = comm
           else:
               pass
               #self.lgr.debug('contextManager tid:%s (%s) not in cache, group leader 0x%x  leader tid %s' % (tid, comm, group_leader, leader_tid))
        elif not self.top.isWindows(target=self.cell_name) and tid in self.tid_cache and new_addr not in self.watch_rec_list:
            self.lgr.debug('***********   tid %s in cache, but new_addr 0x%x not in watch list? eh?' % (tid, new_addr))
        elif self.top.isWindows(target=self.cell_name):
            if tid not in self.tid_cache  and tid != self.task_utils.recentExitTid():
                pid = tid.split('-')[0]
                if pid != self.task_utils.recentExitTid():
                    for tid_item in self.tid_cache:
                        pid_item = tid_item.split('-')[0]
                        if pid_item == pid:
                            add_task=True
                            leader_tid = None
                            break 
            if add_task:
                #self.lgr.debug('contextManager changedThread, adding windows tasks new addr 0x%x' % new_addr)
                self.addTask(tid, new_addr, watch_exit=False)
                self.tid_cache.append(tid)

        self.alterWatches(new_addr, prev_task, tid)
        if add_task:
            self.top.addProc(tid, leader_tid, comm, clone=True)
            self.watchExit(new_addr, tid)
            # TBD do we need this?  results in a mode hap and recording stack at start of execve?
            if not self.top.isWindows():
                self.top.recordStackClone(tid, leader_tid)
        if self.catch_tid is not None:
            #self.lgr.debug('contextManager changedThread self.catch_tid is %s,  tid %s' % (self.catch_tid, tid))
            #if self.catch_tid == tid or (self.catch_tid == '-1' and tid in self.tid_cache) or (self.catch_tid == '-2' and tid != '0') or \
            if self.catch_tid == tid or (self.catch_tid == '-1' and self.amWatching(tid)) or (self.catch_tid == '-2' and tid != '0') or \
                                        (self.catch_tid.endswith('-') and self.catch_tid[:-1] == tid.split('-')[0]):
                self.lgr.debug('contextManager changedThread do catch_callback for tid %s' % tid)
                if self.catch_callback is not None: 
                    SIM_run_alone(self.catch_callback, tid)
                else:
                    SIM_break_simulation('changed thread, now in tid %s' % tid)
                self.catch_tid = None
              
    def catchTid(self, tid, callback):
        if self.top.isWindows():
            if '-' not in tid:
                self.catch_tid = tid+'-'
            else:
                self.catch_tid = tid
        else:
            self.catch_tid = tid
        self.catch_callback = callback 
        self.lgr.debug('contectManager catchTid %s callback %s' % (self.catch_tid, str(callback)))
        self.setTaskHap(tid=tid)

    def watchAll(self):
        self.watch_only_this = False

    def watchOnlyThis(self):
        cur_tid = self.task_utils.curTID()
        tcopy = list(self.tid_cache)
        for tid in tcopy:
            if tid != cur_tid:
                self.rmTask(tid)
        self.watch_only_this = True

    def delTidRecAlone(self, tid):
        RES_delete_breakpoint(self.task_rec_bp[tid])
        self.lgr.debug('contextManger delTidRecAlone rmTask tid %s' % tid)
        if tid in self.task_rec_hap and self.task_rec_hap[tid] is not None:
            RES_hap_delete_callback_id('Core_Breakpoint_Memop', self.task_rec_hap[tid])        
        del self.task_rec_bp[tid]
        del self.task_rec_hap[tid]
        del self.task_rec_watch[tid]

    def rmTask(self, tid, killed=False):
        ''' remove a tid from the list of task records being watched.  return True if this is the last thread. '''
        #self.lgr.debug('contextManager rmTask tid %s' % tid)
        retval = False
        rec = self.task_utils.getRecAddrForTid(tid)
        if rec is None and killed:
            ''' assume record already gone '''
            for r in self.watch_rec_list:
                if self.watch_rec_list[r] == tid:
                    rec = r
                    self.lgr.debug('contextManager rmTask tid %s rec already gone, remove its entries' % tid)
                    break
        if rec in self.watch_rec_list:
            del self.watch_rec_list[rec]
            #self.lgr.debug('rmTask removing rec 0x%x for tid %s, len now %d' % (rec, tid, len(self.watch_rec_list)))
            if tid in self.tid_cache:
                self.tid_cache.remove(tid)
                #self.lgr.debug('rmTask remove %s from cache, cache now %s' % (tid, str(self.tid_cache)))
            if tid in self.task_rec_bp and self.task_rec_bp[tid] is not None:
                self.delTidRecAlone(tid)
            if len(self.watch_rec_list) == 0:
                if len(self.debugging_comm) == 0:
                    self.lgr.warning('contextManager rmTask debugging_comm is None')
               
                if len(self.pending_watch_tids) > 0:
                    self.debugging_tid = self.pending_watch_tids[0]
                    self.lgr.debug('contextManager rmTask, list empty but found pending watch tid %s, make it the debugging_tid' % self.debugging_tid)
                else:
                    #self.debugging_comm = None
                    #self.debugging_cell = None
                    tids = []
                    for comm in self.debugging_comm:
                        comm_tids = self.task_utils.getTidsForComm(comm) 
                        tids.extend(comm_tids)
                    if len(tids) == 0 or (len(tids)==1 and tids[0]==tid):
                        #self.lgr.debug('contextManager rmTask watch_rec_list empty, clear debugging_tid')
                        SIM_run_alone(self.restoreDefaultContext, None)
                        #self.cpu.current_context = self.default_context
                        retval = True
                    else:
                        ''' TBD fix to handle multiple comms '''
                        self.lgr.debug('contextManager rmTask, still tids for comm %s, was fork? set dbg tid to %s tids was %s' % (str(self.debugging_comm), tids[-1], str(tids)))
                        if self.top.swapSOTid(tid, tids[-1]):
                            ''' replace SOMap pid with new one from fork '''
                            self.lgr.debug('Adding task %s and setting debugging_tid' % tids[-1])
                            self.addTask(tids[-1])
                            self.debugging_tid = tids[-1]
                        else:
                            ''' TBD poor hueristic for deciding it was not a fork '''
                            #self.cpu.current_context = self.default_context
                            SIM_run_alone(self.restoreDefaultContext, None)
                            #self.stopWatchTasks()
                            SIM_run_alone(self.stopWatchTasksAlone, None)
                            retval = True
            elif tid == self.debugging_tid:
                self.debugging_tid = self.tid_cache[0]
                self.lgr.debug('contextManager rmTask debugging_tid now %s' % self.debugging_tid)
            else:
                self.lgr.debug('contextManager rmTask remaining debug recs %s' % str(self.watch_rec_list))
        return retval

    def addTask(self, tid, rec=None, watch_exit=True):
        if self.top.isVxDKM():
            return
        if rec is None:
            rec = self.task_utils.getRecAddrForTid(tid)
        if rec not in self.watch_rec_list:
            if rec is None:
                self.lgr.debug('contextManager, addTask got rec of None for tid %s, pending cycle: 0x%x' % (tid, self.cpu.cycles))
                self.pending_watch_tids.append(tid)
            else:
                self.lgr.debug('contextManager, addTask tid %s add rec 0x%x watch_exit %r cycle: 0x%x' % (tid, rec, watch_exit, self.cpu.cycles))
                self.watch_rec_list[rec] = tid
                if watch_exit:
                    self.watchExit(rec=rec, tid=tid)
            if tid not in self.tid_cache:
                self.tid_cache.append(tid)
        else:
            #self.lgr.debug('addTask, already has rec 0x%x for tid:%s' % (rec, tid))
            pass

    def watchingThis(self):
        # DOES not imply debugging
        ctask = self.task_utils.getCurThreadRec()
        cur_tid  = self.task_utils.curTID()
        if cur_tid in self.tid_cache or ctask in self.watch_rec_list or cur_tid in self.task_rec_hap or cur_tid in self.demise_cache:
            #self.lgr.debug('contextManager watchingThis am watching tid:%s' % cur_tid)
            #self.lgr.debug('cache %s  watch_rec_list %s task_rec_hap  %s  demise %s' % (str(self.tid_cache), str(self.watch_rec_list), str(self.task_rec_hap), self.demise_cache))
            return True
        else:
            #self.lgr.debug('contextManager watchingThis not watching %s' % cur_tid)
            return False

    def isCloneWrongComm(self, tid, cur_tid, cur_comm):
        retval = False
        if tid == cur_tid:
            tid_comm = cur_comm
        else:
            tid_comm = self.task_utils.getCommFromTid(tid)
        #if tid in self.my_clones:
        #    self.lgr.debug('remove this tid:%s in my_clones as comm %s tid_comm is %s' % (tid, self.my_clones[tid], tid_comm))
        #else:
        #    self.lgr.debug('remove this tid:%s NOT in my_clones tid_comm is %s' % (tid, tid_comm))
        if tid in self.my_clones and tid_comm != self.my_clones[tid]:
            self.lgr.debug('contextManager isCloneWrongComm, tid:%s comm changed from %s to %s, assume execve and stop watching' % (tid, self.my_clones[tid], tid_comm))
            del self.my_clones[tid]
            self.stopWatchTid(tid, force=True) 
            retval = True
        return retval

    def amWatching(self, tid):
        retval = False
        # Might imply debugging
        ctask = self.task_utils.getCurThreadRec()
        cpu, cur_comm, cur_tid = self.task_utils.curThread()
        if self.isCloneWrongComm(tid, cur_tid, cur_comm):
            pass
        else: 
            # TBD point of checking watch_rec_list len of zero? 
            if tid == cur_tid and (ctask in self.watch_rec_list or (self.debugging_tid is not None and len(self.watch_rec_list)==0)):
                retval = True
            elif tid in self.tid_cache:
                retval = True
            elif tid == self.task_utils.recentExitTid():
                retval = True
        return retval

    def restoreIgnoreContext(self, dumb=None):
        #self.lgr.debug('contextManager restoreIgnoreContext')
        self.cpu.current_context = self.ignore_context
        self.current_context = self.ignore_context
        #self.lgr.debug('contextManager restoreIgnoreContext')

    def restoreSuspendContext(self, dumb=None):
        #self.lgr.debug('contextManager restoreSuspendContext')
        self.cpu.current_context = self.suspend_context
        self.current_context = self.suspend_context
        #self.lgr.debug('contextManager restoreSuspendContext')

    def restoreDefaultContext(self, dumb=None):
        self.cpu.current_context = self.default_context
        self.current_context = self.default_context
        #self.lgr.debug('contextManager restoreDefaultContext')

    def restoreDebugContext(self, dumb=None):
        self.cpu.current_context = self.resim_context
        self.current_context = self.resim_context
        #self.lgr.debug('contextManager restoreDebugContext')

    def stopDebug(self):
        self.lgr.debug('contextManager stopDebug')
        self.debugging_tid = None
        self.debugging_tid_saved = None
        self.watch_rec_list = {}
        self.watch_rec_list_saved = {}
        self.tid_cache = []
        self.restoreDefaultContext()

    def restoreDebug(self):
        if self.debugging_tid is not None:
            self.debugging_tid = self.debugging_tid_saved
            self.lgr.debug('contextManager restoreDebug set cpu context to resim, debugging_tid to %s' % self.debugging_tid)
        self.lgr.debug('contextManager restoreDebug set len list %d len saved %d' % (len(self.watch_rec_list), len(self.watch_rec_list_saved)))
        if len(self.watch_rec_list_saved) > 0:
            self.watch_rec_list = self.watch_rec_list_saved.copy()
        else:
            self.lgr.debug('contextManager restoreDebug set refused to copy empty saved watch_rec_list')

        for ctask in self.watch_rec_list:
            self.tid_cache.append(self.watch_rec_list[ctask])
        self.lgr.debug('contextManager restoreDebug restore RESim context, watch_rec_list len now %d' % len(self.watch_rec_list)) 
        #SIM_run_alone(self.restoreDebugContext, None)
        # assuming already running alone
        self.restoreDebugContext()

    def stopWatchTid(self, tid, force=False):
        self.lgr.debug('contextManager stopWatchTid for tid:%s' % tid)
        if tid in self.task_rec_bp:
            if self.task_rec_bp[tid] is not None:
                self.lgr.debug('contextManager stopWatchTid delete bp %d' % self.task_rec_bp[tid])
                RES_delete_breakpoint(self.task_rec_bp[tid])
                hap = self.task_rec_hap[tid]
                SIM_run_alone(RES_delete_mem_hap, hap)
            del self.task_rec_bp[tid]
            del self.task_rec_hap[tid]
        cur_tid = self.task_utils.curTID()
        if force or (tid == cur_tid and self.debugging_tid is not None):
            ''' we are stopping due to a clone doing an exec or something similar.  in any event, remove haps and change context if needed '''
            ''' TBD, do this in some other function? '''
            self.watching_tasks = False
            if tid in self.watch_rec_list_saved:
                self.watch_rec_list_saved.remove(tid)
            ctask = self.task_utils.getCurThreadRec()
            if ctask in self.watch_rec_list:
                del self.watch_rec_list[ctask]
            SIM_run_alone(self.restoreDefaultContext, None)
            self.lgr.debug('contextManager stopWatchTid No longer watching tid:%s' % tid)
            if tid in self.tid_cache:
                self.tid_cache.remove(tid)
        
    def stopWatchTasks(self):
        self.lgr.debug('contextManager stopWatchTasks')
        #self.stopWatchTasksAlone(None)
        SIM_run_alone(self.stopWatchTasksAlone, None)

    def stopWatchTasksAlone(self, dumb=None):
        if self.task_break is None:
            #self.lgr.debug('stopWatchTasks already stopped')
            return
        self.lgr.debug('contextManager stopWatchTasksAlone delete hap')
        RES_delete_breakpoint(self.task_break)
        if self.task_hap is not None:
            RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_hap)
        self.task_hap = None
        self.task_break = None
        self.watching_tasks = False
        if len(self.watch_rec_list) > 0:
            self.watch_rec_list_saved = self.watch_rec_list.copy()
        else:
            self.lgr.debug('contextManager stopWatchTasksAlone possible race condition, refusing to copy empty watch_rec_list to saved')
        if self.debugging_tid is not None:
            self.debugging_tid_saved = self.debugging_tid
        self.lgr.debug('contextManager stopWatchTasksAlone cleared watch_rec_list')
        self.watch_rec_list = {}
       
        ''' stop watching for death of tasks ''' 
        for tid in self.task_rec_bp:    
            if self.task_rec_bp[tid] is not None:
                #self.lgr.debug('stopWatchTasksAlone task_rec_bp delete bp %d' % self.task_rec_bp[tid])
                RES_delete_breakpoint(self.task_rec_bp[tid])
                if tid in self.task_rec_hap and self.task_rec_hap[tid] is not None:
                    RES_hap_delete_callback_id('Core_Breakpoint_Memop', self.task_rec_hap[tid])        
        self.task_rec_bp = {}
        self.task_rec_hap = {}
        self.task_rec_watch = {}
        self.my_clones = {}
        self.tid_cache = []
        self.debugging_tid = None

        self.restoreDefaultContext()
        self.lgr.debug('stopWatchTasks reverted %s to default context %s All watch lists deleted debugging_tid to None' % (self.cpu.name, str(self.default_context)))

    def resetWatchTasks(self, dumb=None):
        ''' Intended for use when going back in time '''
        tid = self.debugging_tid
        if tid is None: 
            tid = self.debugging_tid_saved
        if tid is None:
            tid  = self.task_utils.curTID()
            #self.lgr.debug('resetWatchTasks tid was not, got current as tid:%s' % tid)
        #self.lgr.debug('resetWatchTasks tid:%s' % tid)
        self.stopWatchTasksAlone(None)
        self.lgr.debug('resetWatchTasks back from stopWatch')
        self.watchTasks(set_debug_tid = True, tid=tid)
        #self.lgr.debug('resetWatchTasks back from watchTasks')
        if not self.watch_only_this:
            self.lgr.debug('resetWatchTasks tid %s' % tid)
            if tid == 1:
                self.lgr.debug('resetWatchTasks got leader tid of 1, skip')
                return
            leader_tid = self.task_utils.getGroupLeaderTid(tid)
            if leader_tid is None:
                self.lgr.debug('contextManager resetWatchTask got no leader tid for tid %s' % tid)
            else:
                tid_list = self.task_utils.getGroupTids(leader_tid)
                for tid in tid_list:
                    if tid == 1:
                        self.lgr.debug('resetWatchTasks got tid of 1, skip')
                    else:
                        self.addTask(tid)

    def setTaskHap(self, tid=None):
        #
        # Set a hap on the address containing the pointer to the currently scheduled task
        #
        if self.task_hap is None:
            self.task_break = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, 
                                 self.phys_current_task, self.mem_utils.WORD_SIZE, 0)
            self.lgr.debug('contextManager setTaskHap bp %d' % self.task_break)
            self.task_hap = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.changedThread, self.cpu, self.task_break)
            self.lgr.debug('setTaskHap cell %s break %s set on physical 0x%x' % (self.cell_name, self.task_break, self.phys_current_task))
        dumb, comm, cur_tid  = self.task_utils.curThread()
        if tid is None or tid == cur_tid:
            self.onlyOrIgnore(tid, comm, None)

    def restoreWatchTasks(self):
        self.watching_tasks = True
        if self.debugging_tid is not None:
            self.lgr.debug('contextManager restoreWatchTasks restore RESim context')
            self.restoreDebugContext()

    def watchTasks(self, set_debug_tid = False, tid=None, restore_debug=True):
        if self.top.isVxDKM():
            return
        self.lgr.debug('contextManager watchTasks set_debug_tid: %r' % set_debug_tid)
        if self.task_break is not None:
            self.lgr.debug('contextManager watchTasks called, but already watching')
            #return
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread()
        else:
            comm = self.task_utils.getCommFromTid(tid)
        if tid == '1':
            self.lgr.debug('contextManager watchTasks, tid is 1, ignore')
            return
        if self.task_break is None:
            self.setTaskHap()
        self.watching_tasks = True
        if len(self.watch_rec_list) == 0 and restore_debug:
            self.lgr.debug('watchTasks, call restoreDebug')
            self.restoreDebug()
        if set_debug_tid:
            self.lgr.warning('watchTasks, call to setDebugTid')
            self.setDebugTid(force=True)
        if comm is not None and comm not in self.debugging_comm:
            self.debugging_comm.append(comm)
        if self.watchExit(tid=tid):
            #self.pageFaultGen.recordPageFaults()
            ctask = self.task_utils.getRecAddrForTid(tid)
            if ctask in self.watch_rec_list:
                self.lgr.debug('watchTasks, tid:%s already being watched' % tid)
                return
            self.lgr.debug('watchTasks cell %s watch record 0x%x tid:%s set_debug_tid: %r' % (self.cell_name, ctask, tid, set_debug_tid))
            self.watch_rec_list[ctask] = tid
        else:
            self.lgr.warning('watchTasks, call to watchExit failed tid %s' % tid)
        if tid not in self.tid_cache:
            self.tid_cache.append(tid)
        group_leader = self.task_utils.getGroupLeaderTid(tid)
        if group_leader != self.group_leader:
            self.lgr.debug('contextManager watchTasks x set group leader to %s' % group_leader)
            self.group_leader = group_leader
      
    def changeDebugTid(self, tid):
        if tid not in self.tid_cache:
            if len(self.tid_cache) > 0:
                self.lgr.error('contextManager changeDebugTid not in tid cache %s' % tid)
            return
        self.lgr.debug('changeDebugTid to %s' % tid)
        self.debugging_tid = tid

    def singleThread(self, single):
        self.single_thread = single

    def setDebugTid(self, force=False):
        if self.debugging_tid is not None and not force:
            self.lgr.debug('contextManager setDebugTid already set to %s' % self.debugging_tid)
            return
        dumb, comm, dumb1  = self.task_utils.curThread()
        cur_tid = self.task_utils.curTID()
        #self.default_context = self.cpu.current_context
        self.lgr.debug('contextManager setDebugTid debugging_tid to %s, (%s) restore RESim context' % (cur_tid, comm))
        #SIM_run_alone(self.restoreDebugContext, None)
        self.restoreDebugContext()
        self.debugging_tid = cur_tid
        self.debugging_tid_saved = self.debugging_tid
        if comm is not None and comm not in self.debugging_comm:
            self.debugging_comm.append(comm)
        self.debugging_cell = self.top.getCell()
        if cur_tid not in self.tid_cache:
            self.tid_cache.append(cur_tid)

    def killGroup(self, lead_tid, exit_syscall):
        self.top.rmDebugExitHap()
        self.lgr.debug('contextManager killGroup lead %s' % lead_tid)
        tids = []
        if lead_tid == self.group_leader:
            for comm in self.debugging_comm:
                tids = self.task_utils.getTidsForComm(comm) 
                if lead_tid in tids:
                    break
            add_task = None
            for p in tids:
                if p not in self.tid_cache:
                    self.lgr.debug('killGroup found tid %s not in cache, was it a fork?  IGNORING killgroup' % p)
                    add_task =p
                    break
            if add_task is not None:
                self.lgr.debug('contextManager killGroup add_task is not None, swap tids')
                self.top.swapSOTid(self.debugging_tid, p)
                self.addTask(add_task)
            else:
                self.lgr.debug('contextManager killGroup %s is leader, tid_cache is %s' % (lead_tid, str(self.tid_cache)))
                cache_copy = list(self.tid_cache)
                for tid in cache_copy:
                    ida_msg = 'killed %s member of group led by %s' % (tid, lead_tid) 
                    exit_syscall.handleExit(tid, ida_msg, killed=True, retain_so=True)
                    if self.pageFaultGen is not None and self.exit_callback is None:
                        if self.pageFaultGen.handleExit(tid, lead_tid):
                            print('SEGV on tid %s?' % tid)
                            self.lgr.debug('contextManager SEGV on tid %s -- stop trace of exit_syscall' % tid)
                            exit_syscall.stopTrace() 
                            break
                self.clearExitBreaks()
        elif self.group_leader != None:
            self.lgr.debug('contextManager killGroup NOT leader.  got %s, leader was %s' % (lead_tid, self.group_leader))
            if self.pageFaultGen is not None and self.exit_callback is None:
                self.pageFaultGen.handleExit(lead_tid, self.group_leader)
        else:
            self.lgr.debug('contextManager killGroup NO leader.  got %s' % (lead_tid))
            if self.pageFaultGen is not None and self.exit_callback is None:
                self.pageFaultGen.handleExit(lead_tid, lead_tid)


    def deadParrot(self, tid):
        if self.task_utils.isExitTid(tid):
            self.lgr.debug('contextManager deadParrot tid %s already reported, remove this task and ignore death' % tid)
            self.rmTask(tid, killed=True)
            return
        ''' who knew? death comes betweeen the breakpoint and the "run alone" scheduling '''
        self.lgr.debug('contextManager deadParrot tid %s' % tid)
        exit_syscall = self.top.getSyscall(self.cell_name, 'exit_group')
        if exit_syscall is not None and not self.watching_page_faults:
            ida_msg = 'tid:%s exit via kill?' % tid
            self.lgr.debug('contextManager deadParrot tid:%s rec no longer found call killGroup' % (tid))
            self.killGroup(tid, exit_syscall)
            self.rmTask(tid)
        else:
            self.rmTask(tid)
            if self.pageFaultGen is not None and self.exit_callback is None:
                group_leader = self.task_utils.getGroupLeaderTid(tid)
                self.pageFaultGen.handleExit(tid, group_leader)
            self.clearExitBreaks()
            self.lgr.debug('contextManager deadParrot tid:%s rec no longer found removed task' % (tid))
        if self.exit_callback is not None:
            group_leader = self.task_utils.getGroupLeaderTid(tid)
            self.pageFaultGen.handleExit(tid, group_leader, report_only=True)
            self.lgr.debug('contextManager deadParrot do exit_callback')
            self.exit_callback()
        self.task_utils.setExitTid(tid)
        self.tidExit(tid)
        print('Process %s exited.' % tid)

    def resetAlone(self, tid):
        #self.lgr.debug('contextManager resetAlone')
        dead_rec = self.task_utils.getRecAddrForTid(tid)
        if dead_rec is not None:
            list_addr = self.task_utils.getTaskListPtr(dead_rec)
            if list_addr is not None:
                self.lgr.debug('contextMgr resetAlone rec 0x%x of tid %s still found though written by maybe not dead after all? new list_addr is 0x%x' % (dead_rec, 
                    tid, list_addr))

                RES_delete_breakpoint(self.task_rec_bp[tid])
                del self.task_rec_bp[tid] 
                RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_rec_hap[tid])
                del self.task_rec_hap[tid] 
                del self.task_rec_watch[tid] 
                self.watchExit(rec=dead_rec, tid = tid)
            else:
                self.lgr.debug('contextMgr resetAlone rec 0x%x of tid %s EXCEPT new list_addr is None call deadParrot' % (dead_rec, tid))
                self.deadParrot(tid)
        else: 
            self.lgr.debug('contextMgr resetAlone tid %s no record for tid, call deadParrot' % (tid))
            self.deadParrot(tid)
        if tid in self.demise_cache:
            self.demise_cache.remove(tid)

    def taskRecHap(self, tid, third, forth, memory):
        self.lgr.debug('taskRecHap tid %s cycle: 0x%x' % (tid, self.cpu.cycles))
        if tid not in self.task_rec_hap or tid in self.demise_cache:
            return
        cpu, cur_comm, cur_tid = self.task_utils.curThread()
        if self.isCloneWrongComm(tid, cur_tid, cur_comm):
            self.lgr.debug('contextManager taskRecHap found clone with changed comm, bail')
            pass
        else:
            self.lgr.debug('contextManager taskRecHap rec point to that of tid:%s altered by cur_tid %s?' % (tid, cur_tid))
            dead_rec = self.task_utils.getRecAddrForTid(tid)
            if self.top.isWindows(target=self.cell_name) and dead_rec is not None and cur_tid == 4:
                #TBD could it be any other tid?
                self.lgr.debug('contextManager System (tid 4) wrote to task rec that had pointed to %t' % tid)
                list_addr = self.task_utils.getTaskListPtr(dead_rec)
                if list_addr is not None:
                    self.lgr.debug('contextManager list_addr now 0x%x' % list_addr)
    
            elif dead_rec is not None:
                if tid != cur_tid:
                    self.lgr.debug('contextManager taskRecHap got record 0x%x for %s, call resetAlone' % (dead_rec, tid))
                    self.demise_cache.append(tid)
                    SIM_run_alone(self.resetAlone, tid)
                else:
                    self.lgr.debug('tid %s messing with its own task rec?  Let it go.' % tid)
    
            else: 
                value = memUtils.getMemoryValue(memory)
                self.lgr.debug('contextManager taskRecHap tid:%s wrote 0x%x to 0x%x watching for demise of %s' % (cur_tid, value, memory.logical_address, tid))
                exit_syscall = self.top.getSyscall(self.cell_name, 'exit_group')
                if exit_syscall is not None and not self.watching_page_faults:
                    ida_msg = 'tid:%s exit via kill?' % tid
                    self.killGroup(tid, exit_syscall)
                else:
                    self.rmTask(tid)
                if self.exit_callback is not None:
                    self.exit_callback()
                self.tidExit(tid)

    def setExitCallback(self, callback):
        ''' callback to be invoked when/if program exits.  intended for use recording exits that occur during playAFL'''
        #self.lgr.debug('contextManager setExitCallback to %s' % str(callback))
        self.exit_callback = callback

    def watchGroupExits(self, tid=None):
        if tid is None:
            cur_tid  = self.task_utils.curTID()
        else:
            cur_tid = tid
        leader_tid = self.task_utils.getGroupLeaderTid(cur_tid)
        if leader_tid is None:
            self.lgr.error('contextManager watchGroupExits no group leader for %s' % cur_tid) 
        tid_dict = self.task_utils.getGroupTids(leader_tid)
        #self.lgr.debug('contextManager watchGroupExits cur_tid %s, leader %s, got %d items from getGroupTids' % (cur_tid, leader_tid, len(tid_dict)))
        for tid in tid_dict:
            self.watchExit(rec=tid_dict[tid], tid=tid)

    def watchExit(self, rec=None, tid=None):
        retval = True
        ''' set breakpoint on task record that points to this (or the given) tid '''
        # TBD This asssume all threads die together.  On windows we assume the EPROCESS record is removed
        # and in Linux we assume the group leader is removed.
        #self.lgr.debug('contextManager watchExit tid:%s' % tid)
        cur_tid  = self.task_utils.curTID()
        if tid is None and cur_tid == '1':
            self.lgr.debug('contextManager watchExit for tid 1, ignore')
            return False
        if tid is None:
            tid = cur_tid
            rec = self.task_utils.getCurThreadRec() 
        elif rec is None:
            self.lgr.debug('contextManager watchExit call getRecAddrForTid %s' % tid)
            rec = self.task_utils.getRecAddrForTid(tid)
        if rec is None:
            self.lgr.debug('contextManager watchExit failed to get list_addr tid:%s cur_tid %s ' % (tid, cur_tid))
            return False
        list_addr = self.task_utils.getTaskListPtr(rec)
        if list_addr is None:
            ''' suspect the thread is in the kernel, e.g., on a syscall, and has not yet been formally scheduled, and thus
                has no place in the task list? OR all threads share the same next_ts pointer'''
            self.lgr.debug('contextManager watchExit failed to get list_addr tid %s cur_tid %s rec 0x%x' % (tid, cur_tid, rec))
            return False
        
        if tid not in self.task_rec_bp or self.task_rec_bp[tid] is None:
            cell = self.default_context
            watch_tid, watch_comm = self.task_utils.getTidCommFromNext(list_addr)
            if not self.top.isWindows(target=self.cell_name):
                if watch_tid == '0':
                    self.lgr.debug('contextManager watchExit, try group next')
                    watch_tid, watch_comm = self.task_utils.getTidCommFromGroupNext(list_addr)
                    if self.debugging_tid is not None and self.amWatching(watch_tid):
                        cell = self.resim_context
            if watch_tid == '0' and not self.top.isWindows():
                # TBD um, windows pid zero points to this process as being next?
                self.lgr.debug('contextManager watchExit, seems to be pid 0, ignore it')
                return False
            #self.lgr.debug('getnContext Watching next record of tid:%s (%s) for death of tid:%s break on 0x%x context: %s' % (watch_tid, watch_comm, tid, list_addr, cell))
            #self.task_rec_bp[tid] = SIM_breakpoint(cell, Sim_Break_Linear, Sim_Access_Write, list_addr, self.mem_utils.WORD_SIZE, 0)
            ''' Use physical so it works with an Only list '''
            list_addr_phys = self.mem_utils.v2p(self.cpu, list_addr)
            self.task_rec_bp[tid] = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Write, list_addr_phys, self.mem_utils.WORD_SIZE, 0)
            SIM_run_alone(self.watchTaskHapAlone, tid)
            self.task_rec_watch[tid] = list_addr
        else:
            #self.lgr.debug('contextManager watchExit, already watching for tid %s' % tid)
            pass
        return retval

    def watchTaskHapAlone(self, tid):
        if tid in self.task_rec_bp and tid and self.task_rec_bp[tid] is not None:
            if tid not in self.task_rec_hap or self.task_rec_hap[tid] is None:
                #self.lgr.debug('contextManager watchTaskHapAlone tid:%s breakpoint 0x%x' % (tid, self.task_rec_bp[tid]))
                self.task_rec_hap[tid] = RES_hap_add_callback_index("Core_Breakpoint_Memop", self.taskRecHap, tid, self.task_rec_bp[tid])
            else:
                self.lgr.debug('contextManager watchTaskHapAlone tid:%s breakpoint 0x%x ALREADY has hap' % (tid, self.task_rec_bp[tid]))

    def auditExitBreaks(self):
        for tid in self.task_rec_watch:
            rec = self.task_utils.getRecAddrForTid(tid)
            if rec is None:
                self.lgr.debug('contextManager auditExitBreaks failed to get task record for tid %s' % tid)
            else:     
                list_addr = self.task_utils.getTaskListPtr(rec)
                if list_addr is None:
                    ''' suspect the thread is in the kernel, e.g., on a syscall, and has not yet been formally scheduled, and thus
                        has no place in the task list? '''
                    self.lgr.debug('contextManager auditExitBreaks failed to get list_addr tid %s rec 0x%x' % (tid, rec))
                elif self.task_rec_watch[tid] is None:
                    watch_tid, watch_comm = self.task_utils.getTidCommFromNext(list_addr) 
                    self.lgr.debug('contextManager auditExitBreaks rec_watch for %s is None, but taskUtils reports %s' % (tid, watch_tid)) 
                elif list_addr != self.task_rec_watch[tid]:
                    watch_tid, watch_comm = self.task_utils.getTidCommFromNext(list_addr) 
                    prev_tid, prev_comm = self.task_utils.getTidCommFromNext(self.task_rec_watch[tid]) 
                    self.lgr.debug('contextManager auditExitBreaks changed in record watch for death of %s, was watching %s, now %s' % (tid, watch_tid, prev_tid))
        
    def setExitBreaks(self):
        #self.lgr.debug('contextManager setExitBreaks')
        for tid in self.task_rec_bp:
            rec = self.task_utils.getRecAddrForTid(tid)
            if rec is None:
                self.lgr.debug('contextManager setExitBreaks got record addr of none for tid %s' % tid)
            else:
                self.watchExit(rec, tid)

    def clearExitBreaks(self):
        SIM_run_alone(self.clearExitBreaksAlone, None)

    def clearExitBreaksAlone(self, dumb):
        #self.lgr.debug('contextManager clearExitBreaks')
        for tid in self.task_rec_bp:
            if self.task_rec_bp[tid] is not None:
                RES_delete_breakpoint(self.task_rec_bp[tid])
                self.task_rec_bp[tid] = None
                #self.lgr.debug('contextManager clearExitBreaks tid:%s' % tid)
        for tid in self.task_rec_hap:
            if self.task_rec_hap[tid] is not None:
                RES_hap_delete_callback_id("Core_Breakpoint_Memop", self.task_rec_hap[tid])
                self.task_rec_hap[tid] = None

    def resetBackStop(self):
        pass

    def getIdaMessage(self):
        return self.ida_message

    def getDebugTid(self):
        #self.lgr.debug('contextManager return debugging_tid of %s' % self.debugging_tid)
        return self.debugging_tid, self.cpu

    def getSavedDebugTid(self):
        return self.debugging_tid_saved

    def clearDebuggingTid(self):
        self.debugging_tid = None
        self.debugging_tid_saved = None

    def showIdaMessage(self):
        print('genMonitor says: %s' % self.ida_message)
        self.lgr.debug('genMonitor says: %s' % self.ida_message)

    def setIdaMessage(self, message):
        #self.lgr.debug('ida message set to %s' % message)
        self.ida_message = message

    def isDebugContext(self):
        if self.cpu.current_context == self.resim_context:
            return True
        else:
            return False

    def isIgnoreContext(self):
        if self.cpu.current_context == self.ignore_context:
            return True
        else:
            return False

    def setReverseContext(self):
        ''' Tells all haps to ignore because we are reversing or skipping '''
        self.reverse_context = True

    def clearReverseContext(self):
        self.reverse_context = False

    def isReverseContext(self):
        return self.reverse_context

    def getRESimContext(self):
        return self.resim_context

    def getDefaultContext(self):
        return self.default_context

    def getRESimContextName(self):
        return self.context_map[self.resim_context]

    def getDefaultContextName(self):
        return self.context_map[self.default_context]

    def watchPageFaults(self, watching):
        self.watching_page_faults = watching

    def callMe(self, pageFaultGen):
        self.pageFaultGen = pageFaultGen

    def getWatchTids(self):
        self.lgr.debug('getWatchTids len of task_rec_bp is %d  watch_rec_list is %d' % (len(self.task_rec_bp.keys()), len(self.watch_rec_list)))
        #return self.task_rec_bp.keys()
        return self.watch_rec_list.values()

    def noWatch(self, tid):
        self.no_watch.append(tid)
        if tid in self.tid_cache:
            self.tid_cache.remove(tid)
        self.rmTask(tid)
        self.lgr.debug('contectManager noWatch tid:%s' % tid)

    def newProg(self, prog_string, tid):
        if len(self.ignore_progs) > 0:
            base = os.path.basename(prog_string)
            self.lgr.debug('contextManager newProg, ignore tid %s check for base %s' % (tid, base))
            for ignore in self.ignore_progs:
                if base.startswith(ignore):
                    self.lgr.debug('contextManager newProg, ignore tid %s %s' % (tid, base))
                    self.ignore_tids.append(tid)
                    #SIM_run_alone(self.restoreIgnoreContext, None)
                    self.restoreIgnoreContext()

    def tidExit(self, tid):
        self.lgr.debug('contextManager tidExit %s' % tid)
        if tid in self.ignore_tids:
            self.lgr.debug('contextManager tidEXit remove from ignore_pids: %s' % tid)
            self.ignore_tids.remove(tid)
        self.task_utils.setExitTid(tid)

    def ignoreProg(self, prog):
        comm = os.path.basename(prog)[:self.task_utils.commSize()]
        if comm not in self.ignore_progs:
            self.ignore_progs.append(comm)
            self.lgr.debug('contextManager ignoreProg %s' % comm)
            self.setTaskHap()

    def onlyProg(self, prog):
        comm = os.path.basename(prog)[:self.task_utils.commSize()]
        self.comm_prog_map[comm]=prog
        if comm not in self.only_progs:
            self.only_progs.append(comm)
            #self.lgr.debug('contextManager onlyProg %s' % comm)
            self.setTaskHap()
            if prog.startswith('/'):
                existing_tids = self.task_utils.getTidsForComm(comm)
                if len(existing_tids) == 0:
                    ''' watch for first schedule of this in case we are just tracing and not using debugProc '''
                    self.lgr.debug('contextManager onlyProg will watch for first schedule of %s' % comm)
                    self.callWhenFirstScheduled(comm, self.recordProcessText)

    def getIgnoredProgs(self):
            return list(self.ignore_progs)

    def getContextName(self, cell):
        # TBD clarifiy
        retval = None
        if cell in self.context_map:
            retval = self.context_map[cell]
        return retval
        
    def getCellFromContext(self, context_name):
        retval = None
        if context_name in self.map_context:
            retval = self.map_context[context_name]
        return retval

    def getContexts(self):
        ''' return context names '''
        retval = []
        for c in self.map_context:
            retval.append(c)
        return retval 

    def didListLoad(self):
        ''' was an "only" or "ignore" list loaded? '''
        retval = False
        if len(self.only_progs) > 0 or len(self.ignore_progs) > 0:
            retval = True
        return retval

    def loadIgnoreList(self, fname):
        retval = False
        if not self.didListLoad():
            self.lgr.debug('contextManager loadIgnoreList')
            #flist = glob.glob('*.ignore_prog')
            #if len(flist) > 1:
            #    self.lgr.error('Found multiple dll_skip files, only one supported')
            #elif len(flist) == 1:
            if os.path.isfile(fname):
                self.lgr.debug('loadIgnoreList %s' % fname)
                with open(fname) as fh:
                    for line in fh:
                        if line.startswith('#'):
                            continue
                        self.ignoreProg(line.strip())
                        self.lgr.debug('contextManager will ignore %s' % line.strip())
                        retval = True
                '''
                tasks = self.task_utils.getTaskStructs()
                for t in tasks:
                    self.newProg(tasks[t].comm, tasks[t].pid)
                self.restoreDefaultContext()
                '''
            else:
                self.lgr.error('contextManager loadIgnoreList no file at %s' % fname)
        if retval:
            cur_tid = self.task_utils.curTID()
            comm = self.task_utils.getCommFromTid(cur_tid) 
            if comm in self.ignore_progs:
                self.lgr.debug('contextManager loadIgnoreList current comm of %s should be ignored, so set ignore context' % comm)
                self.restoreIgnoreContext()

        return retval

    def loadOnlyList(self, fname):
        retval = False
        if not self.didListLoad():
            self.lgr.debug('contextManager loadOnlyList')
            if os.path.isfile(fname):
                self.lgr.debug('loadOnlyList %s' % fname)
                with open(fname) as fh:
                    for line in fh:
                        if line.startswith('#'):
                            continue
                        self.onlyProg(line.strip())
                        self.lgr.debug('contextManager will watch  %s' % line.strip())
                        retval = True
            else:
                self.lgr.error('contextManager loadOnlyList no file at %s' % fname)
        if retval:
            cur_tid = self.task_utils.curTID()
            if cur_tid is not None:
                comm = self.task_utils.getCommFromTid(cur_tid) 
                if comm not in self.only_progs:
                    self.lgr.debug('contextManager loadOnlyList  current comm of %s should be ignored, so set ignore context' % comm)
                    self.restoreIgnoreContext()
        return retval

    def loadIgnoreThreadList(self, fname):
        retval = False
        if len(self.ignore_threads) == 0:
            self.lgr.debug('contextManager loadIgnoreThreadList')
            if os.path.isfile(fname):
                self.lgr.debug('loadIgnoreThreadList %s' % fname)
                with open(fname) as fh:
                    for line in fh:
                        if line.startswith('#'):
                            continue
                        self.ignore_threads.append(line.strip())
                        self.lgr.debug('contextManager will ignore thread %s' % line.strip())
                        retval = True
            else:
                self.lgr.error('contextManager loadIgnoreThreadList no file at %s' % fname)
        return retval

    def checkExitCallback(self):
        self.lgr.debug('contextManager checkExitCallback callback is %s' % str(self.exit_callback))
        if self.exit_callback is not None:
            self.exit_callback()


    def callWhenFirstScheduled(self, comm, callback):
        self.watch_for_prog.append(comm)
        self.watch_for_prog_callback[comm] = callback
        self.current_tasks = self.task_utils.getTaskList()
        self.setTaskHap()
        self.lgr.debug('contextManager callWhenFirstScheduled comm %s' % comm)

    def listStartsWith(self, the_list, the_value):
        for l in the_list:
            if (len(l) > COMM_SIZE and l.startswith(the_value)) or l == the_value:
                return True
        return False

    def checkFirstSchedule(self, task_rec, tid, comm):
        #self.lgr.debug('contextManager checkFirstSchedule comm %s len current_tasks %d' % (comm, len(self.current_tasks)))
        if task_rec not in self.current_tasks or len(self.current_tasks) == 0: 
            #self.lgr.debug('contextManager checkFirstSchedule tid:%s (%s) not yet in current tasks' % (tid, comm))
            if self.listStartsWith(self.watch_for_prog, comm) and self.listStartsWith(self.watch_for_prog_callback, comm):
                self.lgr.debug('contextManager checkFirstSchedule got first for tid:%s (%s)' % (tid, comm))
                self.watch_for_prog.remove(comm)
                self.watch_for_prog_callback[comm](tid)
                del self.watch_for_prog_callback[comm]

    def recordProcessText(self, tid):
        comm = self.task_utils.getCommFromTid(tid) 
        self.lgr.debug('contextManager recordProcessText for %s' % comm)
        if comm in self.comm_prog_map:
            prog = self.comm_prog_map[comm]
            eproc = self.task_utils.getCurThreadRec()
            full_path = self.top.getFullPath(prog)
            self.lgr.debug('contextManager recordProcessText full path %s' % full_path)
            if self.top.isWindows(target = self.cell_name):  
                win_prog_info = winProg.getWinProgInfo(self.cpu, self.mem_utils, eproc, full_path, self.lgr)
                self.soMap.addText(prog, tid, win_prog_info.load_addr, win_prog_info.text_size, win_prog_info.machine, 
                        win_prog_info.image_base, win_prog_info.text_offset)
            else:
                self.soMap.addText(full_path, prog, tid)
        else:
            self.lgr.debug('contextManager recordProcess text %s not in comm_prog_map' % comm)


    def setSOMap(self, soMap):
        ''' ugly dependency loop needed to set text on first schedule ''' 
        self.soMap = soMap

    def disableAll(self, direction=None, filter=None):
        self.lgr.debug('contextManager disableAll cycle: 0x%x' % self.cpu.cycles)
        for hap in self.haps:
            if filter is None or filter in hap.name:
                hap.disable(direction)
        if filter is None:
            for tid in self.task_rec_bp:
                if self.task_rec_bp[tid] is not None:
                    SIM_disable_breakpoint(self.task_rec_bp[tid])
            if self.task_break is not None:
                SIM_disable_breakpoint(self.task_break)


    def enableAll(self, dumb=None):
        self.lgr.debug('contextManager enableAll cycle 0x%x' % self.cpu.cycles)
        for hap in self.haps:
            hap.enable()
        for tid in self.task_rec_bp:
            if self.task_rec_bp[tid] is not None:
                SIM_enable_breakpoint(self.task_rec_bp[tid])
        if self.task_break is not None:
            SIM_enable_breakpoint(self.task_break)

    def watchingExit(self, tid):
        if tid in self.task_rec_hap and self.task_rec_hap[tid] is not None:
            return True
        else:
            return False

    def isHapDisabled(self, hap_handle):
        for hap in self.haps:
            if hap.handle == hap_handle:
                return hap.disabled
        self.lgr.error('contextManager isHapDisabled called with unknown hap handle %d' % hap_handle)
        
