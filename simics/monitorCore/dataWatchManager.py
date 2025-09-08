from simics import *
import dataWatch
class DataWatchManager():
    ''' Not sure yet.  See where it goes '''
    def __init__(self, top, first_watch, cpu, cell_name, page_ssze, context_manager, mem_utils, task_utils, rev_to_call, param, run_from_snap, 
                 back_stop, compat32, comp_dict, so_map, reverse_mgr, lgr):
        self.rev_to_call = rev_to_call
        self.top = top
        self.first_watch = first_watch
        self.cpu = cpu
        self.cell_name = cell_name
        self.param = param
        self.context_manager = context_manager
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.lgr = lgr
        self.compat32 = compat32
        self.page_size = self.top.PAGE_SIZE
        self.back_stop = back_stop
        self.comp_dict = comp_dict
        self.so_map = so_map
        self.run_from_snap = run_from_snap
        self.reverse_mgr = reverse_mgr
        self.dataWatch = {}
        self.fun_mgr = self.top.getFunMgr()
        self.failed = False
        self.createNewDataWatch()
       
    def failedCreate(self):
        return self.failed 

    def createNewDataWatch(self):
        dum_cpu, comm, tid = self.task_utils.curThread()
        self.lgr.debug('dataWatchManager createNewDataWatch comm %s' % (comm))
        full_path = self.top.getFullPath(fname=comm)
        if full_path is None:
            prog = self.top.getProgName(tid)
            if prog is not None and prog != comm:
                full_path = self.top.getFullPath(fname=prog)
        if full_path is None:
            self.lgr.debug('dataWatchManager createNewDataWatch for comm %s but did not find any prog for it' % comm)
            self.failed = True
            return
        self.lgr.debug('dataWatchManager createNewDataWatch comm %s full path %s' % (comm, full_path))
        root_prefix = self.top.getCompDict(self.cell_name, 'RESIM_ROOT_PREFIX')

        if self.so_map.isDynamic(full_path):
            image_base = self.so_map.getImageBase(full_path)
            load_info = self.so_map.getLoadInfo()
            offset = load_info.addr - image_base
            self.lgr.debug('dataWatchManager createNewDataWatch is dynamic, offset 0x%x image_base 0x%x' % (offset, image_base))
        else:
            offset = 0
        self.fun_mgr.getIDAFuns(full_path, root_prefix, offset)
        self.lgr.debug('dataWatchManager createNewDataWatch set id funs for %s' % full_path)


        self.dataWatch[comm] = dataWatch.DataWatch(self.top, self.cpu, self.cell_name, self.page_size, self.context_manager, 
                  self.mem_utils, self.task_utils, self.rev_to_call, self.param, 
                  self.run_from_snap, self.back_stop, self.compat32, self.comp_dict, self.so_map, self.reverse_mgr, self.lgr)

        self.dataWatch[comm].setFunMgr(self.fun_mgr)
        self.lgr.debug('dataWatchManager created new data watch for comm %s' % comm)


    def recordRead(self, comm, index, phys_addr, linear_addr, start, length, trans_size, cur_comm, cur_tid, op_type):
        ''' comm is comm of dataWatch that sees the current comm is not its own'''
        if cur_comm not in self.dataWatch:
            self.lgr.error('dataWatchManager called with unknown comm %s' % cur_comm)
            return
        eip = self.top.getEIP(cpu=self.cpu)
        self.lgr.debug('dataWatchManager call dataWatch userSpaceRef')
        self.dataWatch[cur_comm].userSpaceRef(eip, cur_tid, linear_addr, start, length, trans_size, op_type)
