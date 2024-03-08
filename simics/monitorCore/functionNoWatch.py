import os
import disableAndRun
from simics import *
class EntryInfo():
    def __init__(self, lib, fun, lib_fun):
        self.lib = lib
        self.fun = fun
        self.lib_fun = lib_fun
        self.image_base = None
        self.hap = None
        self.phys_addr = None

class FunctionNoWatch():
    def __init__(self, top, data_watch, cpu, def_file, cell_name, mem_utils, context_manager, so_map, lgr):
        self.top = top
        self.data_watch = data_watch
        self.cpu = cpu
        self.cell_name = cell_name
        self.mem_utils = mem_utils
        self.so_map = so_map
        self.context_manager = context_manager
        self.lgr = lgr
        self.entry_list = []
        if not os.path.isfile(def_file):
            lgr.error('functionNoWatch failed to find file %s' % def_file)
            return
        with open(def_file) as fh:
            for line in fh:
                line = line.strip()
                if line.startswith ('#') or len(line)==0:
                    continue
                if ':' not in line:
                    self.lgr.error('functionNoWatch missing colon in %s' % line)
                    return 
                self.handleEntry(line)

    def handleEntry(self, entry):
        lib, fun = entry.split(':', 1)
        entry_info = EntryInfo(lib, fun, entry)
        self.entry_list.append(entry_info)
        image_base = self.so_map.getImageBase(lib)
        if image_base is None:
            # No process has loaded this image.  Set a callback for each load of the library
            self.lgr.debug('functionNoWatch handleEntry no process has image loaded, set SO watch callback for %s' % entry)
            self.so_map.addSOWatch(lib, self.libLoadCallback, name=entry)
            self.pending_libs[entry] = entry_info
        else:
            # Library loaded by someone.  Get list of pids
            entry_info.image_base = image_base
            loaded_pids = self.so_map.getSOPidList(lib)
            if len(loaded_pids) == 0:
                self.lgr.error('functionNoWatch handleEntry expected at least one pid for %s' % lib)
                return
            self.lgr.debug('functionNoWatch handleEntry has %d pids with lib loaded' % len(loaded_pids))
            phys = None
            for pid in loaded_pids:
                load_addr = self.so_map.getLoadAddr(lib, tid=str(pid))
                if load_addr is not None:
                    self.lgr.debug('functionNoWatch handleEntry pid %s load addr 0x%x, call getPhys' % (pid, load_addr))
                    phys = self.getPhys(entry_info, load_addr, pid)
                    if phys is not None and phys != 0:
                        self.setBreak(entry_info, phys)

    def libLoadCallback(self, load_addr, lib_fun):
        self.lgr.debug('functionNoWatch libLoadCallback for %s load_addr 0x%x' % (lib_fun, load_addr))
        if lib_fun in self.pending_libs:
            entry_info = self.pending_libs[lib_fun]
            if entry_info.image_base is None:
                entry_info.image_base = self.so_map.getImageBase(entry_info.lib)
            tid = self.top.getTID(target=self.cell_name)
            phys = self.getPhys(entry_info, load_addr, str(tid))
            if phys is not None and phys != 0:
                self.setBreak(entry_info, phys)
            else:
                offset = load_addr - entry_info.image_base
                linear = entry_info.addr + offset
                self.lgr.debug('functionNoWatch libLoadCallback for load_addr 0x%x image_base 0x%x offset 0x%x linear 0x%x' % (load_addr, entry_info.image_base, offset, linear))
                self.pending_pages[entry_info.lib_fun] = entry_info
                self.top.pageCallback(linear, self.pagedIn, name=entry_info.lib_fun)
        else:
            self.lgr.error('functionNoWatch libLoadCallback for %s, but not in pending_libs' % lib_fun)

    def pagedIn(self, linear, name):
        if name not in self.pending_pages:
            self.lgr.error('functionNoWatch pagedIn name %s not in pending_pages' % name)
            return
        entry_info = self.pending_pages[name]
        load_addr = self.so_map.getLoadAddr(entry_info.lib)
        self.lgr.debug('functionNoWatch paged_in load_addr 0x%x name %s linear 0x%x' % (load_addr, name, linear))
        phys = self.getPhys(entry_info, load_addr, None)
        if phys is not None and phys != 0:
            self.setBreak(self.pending_pages[name], phys)

    def getPhys(self, entry_info, load_addr, pid):
        offset = load_addr - entry_info.image_base
        size = self.so_map.getProgSize(entry_info.lib)
        self.lgr.debug('functionNoWatch getPhys got size 0x%x' % size)
        if size is None:
            self.lgr.error('functionNoWatch getPhys failed to get size for %s' % entry_info.lib)
            return None
        end = load_addr + size - 1
        fun_addr = self.top.getFunWithin(entry_info.fun, load_addr, end) 
        if fun_addr is None:
            self.lgr.error('functionNoWatch getPhys failed to get fun_addr for %s' % entry_info.fun)
            return
        linear = fun_addr
        phys_addr = self.mem_utils.v2p(self.cpu, linear, use_pid=pid)
        self.lgr.debug('functionNoWatch getPhys load_addr 0x%x image_base 0x%x offset 0x%x, linear 0x%x pid:%s' % (load_addr, entry_info.image_base, offset, linear, pid))
        #if phys_addr is not None:
        #    # Cancel callbacks
        #    self.so_map.cancelSOWatch(entry_info.lib, entry_info.lib_fun)
        if phys_addr is None:
            self.top.pageCallback(linear, self.pagedIn, name=entry_info.lib_fun, use_pid=pid)
        return phys_addr

    def setBreak(self, entry_info, phys_addr):
        self.lgr.debug('functionNoWatch setBreak phys_addr 0x%x for %s' % (phys_addr, entry_info.lib_fun))
        #self.breakpoints[entry_info.lib_fun] = SIM_breakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_addr, 1, 0)
        #self.hap[entry_info.lib_fun] = SIM_hap_add_callback_index("Core_Breakpoint_Memop", self.bufferHap, entry_info, self.breakpoints[entry_info.lib_fun])
        
        break_num = self.context_manager.genBreakpoint(self.cpu.physical_memory, Sim_Break_Physical, Sim_Access_Execute, phys_addr, 1, 0)
        hap = self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.funHap, entry_info, break_num, 'functionNoWatchEntry')
        entry_info.hap = hap
        entry_info.phys_addr = phys_addr
                
    def funHap(self, entry_info, the_object, break_num, memory):
        if entry_info.hap is None:
            return
        ret_addr = self.data_watch.getReturnAddr() 
        if ret_addr is None:
            self.lgr.error('functionNoWatch funHap failed to get ret_addr for entry %s' % entry_info.lib_fun)
            return
        eip = self.top.getEIP(self.cpu)
        self.lgr.debug('functionNoWatch funHap entry %s eip: 0x%x set break on return addr 0x%x  cycle: 0x%x' % (entry_info.lib_fun, eip, ret_addr, self.cpu.cycles))
        disableAndRun.DisableAndRun(self.cpu, ret_addr, self.context_manager, self.lgr) 

    def rmBreaks(self, immediate=False):
        self.lgr.debug('functionNoWatch rmBreaks immediate %r cycle 0x%x' % (immediate, self.cpu.cycles))
        for entry in self.entry_list:
            if entry.hap is not None:
                self.context_manager.genDeleteHap(entry.hap, immediate=immediate)
                entry.hap = None

    def restoreBreaks(self):
        self.lgr.debug('functionNoWatch restoreBreaks cycle 0x%x' % self.cpu.cycles)
        for entry in self.entry_list:
            if entry.phys_addr is not None and entry.hap is None:
                self.setBreak(entry, entry.phys_addr)

