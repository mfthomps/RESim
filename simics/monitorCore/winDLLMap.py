import os
import pickle
import soMap
import winProg
class Text():
    ''' compat with old linux elfText code without importing... '''
    def __init__(self, address, size):
        self.address = address
        self.size = size 

class DLLInfo():
    def __init__(self, pid, fname, fd):
        self.fname = fname
        self.fd = fd
        self.pid = pid
        self.section_handle = None
        self.addr = None
        self.size = None
    def addSectionHandle(self, section_handle):
        self.section_handle = section_handle
    def addLoadAddress(self, addr, size):
        self.addr = addr 
        self.size = size 
    def match(self, dll_info):
        retval = False
        if dll_info.pid == self.pid and dll_info.addr == self.addr and dll_info.size == self.size and dll_info.fname == self.fname:
            retval = True
        return retval


class WinDLLMap():
    def __init__(self, top, cpu, cell_name, mem_utils, task_utils, run_from_snap, lgr):
        self.cpu = cpu
        self.cell_name = cell_name
        self.task_utils = task_utils
        self.mem_utils = mem_utils
        self.lgr = lgr
        self.top = top
        self.open_files = {}
        self.sections = {}
        self.section_list = []
        self.min_addr = None
        self.max_addr = None
        self.so_watch = []
        self.so_watch_callback = None
        self.text = {}
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)

    def pickleit(self, name):
        somap_file = os.path.join('./', name, self.cell_name, 'soMap.pickle')
        so_pickle = {}
        so_pickle['open_files'] = self.open_files
        so_pickle['sections'] = self.sections
        so_pickle['section_list'] = self.section_list
        so_pickle['text'] = self.text
        fd = open( somap_file, "wb") 
        pickle.dump( so_pickle, fd)
        self.lgr.debug('winDLLMap pickleit to %s ' % (somap_file))

    def loadPickle(self, name):
        somap_file = os.path.join('./', name, self.cell_name, 'soMap.pickle')
        if os.path.isfile(somap_file):
            self.lgr.debug('SOMap pickle from %s' % somap_file)
            so_pickle = pickle.load( open(somap_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            if 'open_files' in so_pickle:
                self.open_files = so_pickle['open_files']
                self.sections = so_pickle['sections']
                self.section_list = so_pickle['section_list']
                for section in self.section_list:
                    if self.min_addr is None or self.min_addr > section.addr:
                        self.min_addr = section.addr
                    ma = section.addr + section.size
                    if self.max_addr is None or self.max_addr < ma:
                        self.max_addr = ma
            if 'text' in so_pickle:
                self.text = so_pickle['text']
                    

    def addFile(self, fname, fd, pid):
        if pid not in self.open_files:
            self.open_files[pid] = {}
        dll_info = DLLInfo(pid, fname, fd)
        self.open_files[pid][fd] = dll_info

    def addText(self, fname, pid, addr, size):
        dll_info = DLLInfo(pid, fname, None)
        dll_info.addr = addr
        dll_info.size = size
        self.section_list.append(dll_info)
        self.text[pid] = dll_info

    def createSection(self, fd, section_handle, pid):
        if pid in self.open_files:
            if fd in self.open_files[pid]:
                self.open_files[pid][fd].addSectionHandle(section_handle) 
                if pid not in self.sections:
                    self.sections[pid] = {}
                self.sections[pid][section_handle] = self.open_files[pid][fd]
                self.lgr.debug('createSection pid %d sec hand 0x%x' % (pid, section_handle))
                #del self.open_files[pid][fd]
                
            else:                
                self.lgr.warning('WinDLLMap createSection fd %d not defined for pid %d' % (fd, pid))
        else:
            self.lgr.warning('WinDLLMap createSection pid %d not defined ' % (pid))

    def isNew(self, new_dll):
        retval = True
        for dll_info in self.section_list:
            if dll_info.match(new_dll):
                retval = False
                break
        return retval
 
    def mapSection(self, pid, section_handle, load_addr, size):
        if pid in self.sections:
            if section_handle in self.sections[pid]:
                self.sections[pid][section_handle].addLoadAddress(load_addr, size)
                if self.isNew(self.sections[pid][section_handle]):
                    self.section_list.append(self.sections[pid][section_handle])
                    self.lgr.debug('WinDLLMap mapSection appended, len now %d' % len(self.section_list))
                    ''' See if we are looking for this SO, e.g., to disable tracing when in it '''
                    self.checkSOWatch(self.sections[pid][section_handle])
                    if self.min_addr is None or self.min_addr > load_addr:
                        self.min_addr = load_addr
                    ma = load_addr + size
                    if self.max_addr is None or self.max_addr < ma:
                        self.max_addr = ma
                else:
                    self.lgr.debug('Ignore existing section pid %d fname %s' % (pid, self.sections[pid][section_handle].fname))
            else:                
                unknown_dll = DLLInfo(pid, 'unknown', -1)
                unknown_dll.addLoadAddress(load_addr, size)
                self.section_list.append(unknown_dll)
                self.lgr.debug('WinDLLMap mapSection section_handle %d not defined for pid %d, add unknown section' % (section_handle, pid))
        else:
            self.lgr.warning('WinDLLMap mapSection pid %d not in sections ' % (pid))

    def checkSOWatch(self, section):
        for fname in self.so_watch:
            #self.lgr.debug('WinDLLMap checkSOWatch does %s endwith %s' % (section.fname, fname))
            if section.fname.endswith(fname):
                if self.so_watch_callback is not None:
                    self.lgr.debug('winDLL checkSOWatch do callback for %s' % fname)
                    self.so_watch_callback(fname, section.addr, section.size) 

    def showSO(self, pid):
        self.lgr.debug('WinDLLMap showSO %d sections' % (len(self.section_list)))
        for section in self.section_list:
            end = section.addr+section.size
            print('pid:%d 0x%x - 0x%x %s' % (section.pid, section.addr, end, section.fname)) 
            self.lgr.debug('winDLLMap showSO pid:%d 0x%x - 0x%x %s' % (section.pid, section.addr, end, section.fname)) 


    def isMainText(self, address):
        ''' TBD fix this ''' 
        return False

    def getSOFile(self, addr_in):
        ''' TBD should'nt this require a pid???'''
        retval = None
        if addr_in is not None:
            for section in self.section_list:
                end = section.addr+section.size
                if addr_in >= section.addr and addr_in <= end:
                    retval = section.fname
                    break 
        return retval

    def isCode(self, addr_in, pid):
        ''' TBD not done '''
        retval = False
        if addr_in >= self.min_addr and addr_in <= self.max_addr:
            retval = True
        else:
            for section in self.section_list:
                if section.pid == pid:
                    end = section.addr+section.size
                    if addr_in >= section.addr and addr_in <= end:
                        retval = True
                        break 
        return retval

    class HackCompat():
        def __init__(self, address, locate, offset, size):
            self.address = address
            self.locate = locate
            self.offset = offset
            self.size = size

    def getSOAddr(self, in_fname, pid=None):
        retval = None
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
        pid = self.getSOPid(pid)
        if pid is None:
            return None
 
        for section in self.section_list:
            if section.pid == pid:
                if os.path.basename(in_fname) == os.path.basename(section.fname):
                    retval = self.HackCompat(section.addr, section.addr, 0, section.size)
                    break 
        return retval

    def getSOPid(self, pid):
        return pid

    def getSOInfo(self, addr_in):
        retval = None, None, None
        cpu, comm, pid = self.task_utils.curProc() 
        if pid is None:
            return retval
        for section in self.section_list:
            if section.pid == pid:
                end = section.addr+section.size
                if addr_in >= section.addr and addr_in <= end:
                    retval = section.fname, section.addr, end
                    break 
        return retval

    def getCodeSections(self, pid):
        retval = []
        for section in self.section_list:
            if section.pid == pid:
                code_section = soMap.CodeSection(section.addr, section.size)
                retval.append(section) 
        return retval

    def addSOWatch(self, fname, callback):
        self.so_watch.append(fname)
        self.so_watch_callback = callback

    def getText(self, pid):
        retval = None
        if pid in self.text:
            retval = Text(self.text[pid].addr, self.text[pid].size)
        else:
            cpu, comm, cur_pid = self.task_utils.curProc() 
            if pid == cur_pid:
                prog_name = self.top.getProgName(pid)
                full_path = self.top.getFullPath(fname=prog_name)
                self.lgr.debug('winDLL getText, no text yet for %s, try reading it from winProg' % prog_name)
                eproc = self.task_utils.getCurTaskRec()
                load_addr = winProg.getTextSection(self.cpu, self.mem_utils, eproc, self.lgr)
                size = winProg.getTextSize(full_path, self.lgr)
                self.top.setFullPath(full_path)
                self.addText(prog_name, pid, load_addr, size)
                retval = Text(load_addr, size)
        return retval
             
    def setIdaFuns(self, ida_funs):
        if ida_funs is None:
            self.lgr.warning('IDA funs is none, no SOMap')
            return
        self.ida_funs = ida_funs
        # TBD see soMap
