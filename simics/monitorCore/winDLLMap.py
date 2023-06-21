import os
import pickle
import json
import ntpath
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
        self.machine = None

    @classmethod
    def copy(cls, info):
        new = cls(info.pid, info.fname, info.fd)
        new.addr = info.addr
        new.size = info.size
        new.machine = info.machine
        return new

    def addSectionHandle(self, section_handle):
        self.section_handle = section_handle
    def addLoadAddress(self, addr, size):
        self.addr = addr 
        self.size = size 
    def addMachine(self, machine):
        self.machine = machine

    def match(self, dll_info):
        retval = False
        if dll_info.pid == self.pid and dll_info.addr == self.addr and dll_info.size == self.size and dll_info.fname == self.fname:
            retval = True
        return retval
    def toString(self):
        retval = '%s pid:%d addr: 0x%x size 0x%x' % (self.fname, self.pid, self.addr, self.size)
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
        self.min_addr = {}
        self.max_addr = {}
        self.so_watch = []
        self.so_watch_callback = None
        self.text = {}
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)
        self.pending_procs = []

    def pickleit(self, name):
        somap_file = os.path.join('./', name, self.cell_name, 'soMap.pickle')
        so_pickle = {}
        so_pickle['open_files'] = self.open_files
        so_pickle['sections'] = self.sections
        so_pickle['section_list'] = self.section_list
        so_pickle['text'] = self.text
        fd = open( somap_file, "wb") 
        pickle.dump( so_pickle, fd)
        self.lgr.debug('winDLLMap pickleit to %s %d text sections' % (somap_file, len(self.text)))

    def loadPickle(self, name):
        self.lgr.debug('winDLL loadPickle %s' % name)
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
                    if section.pid not in self.min_addr:
                        self.min_addr[section.pid] = None
                        self.max_addr[section.pid] = None
                    if self.min_addr[section.pid] is None or self.min_addr[section.pid] > section.addr:
                        self.min_addr[section.pid] = section.addr
                    if section.size is None:
                        self.lgr.error('winDLL loadPickle no size for %s, addr 0x%x pid:%d' % (section.fname, section.addr, section.pid))
                        continue
                    ma = section.addr + section.size
                    if self.max_addr[section.pid] is None or self.max_addr[section.pid] < ma:
                        self.max_addr[section.pid] = ma

                    if section.pid not in self.sections:
                        self.sections[section.pid] = {}
                    if section.section_handle is not None and section.section_handle not in self.sections[section.pid]:
                        self.sections[section.pid][section.section_handle] = section
              
            else:
                self.lgr.debug('windDLL loadPickle no open_files in pickle')
            if 'text' in so_pickle:
                self.text = so_pickle['text']
            else:
                self.lgr.debug('windDLL loadPickle no text in pickle')

        for pid in self.sections:
            
            self.lgr.debug('windDLL loadPickle check pid %d' % pid)
            if pid not in self.text:
                prog = self.top.getProgName(pid)
                if prog is not None:
                    prog_base = os.path.basename(prog)
                    for sec_handle in self.sections[pid]:
                        sec = self.sections[pid][sec_handle]
                        sec_base = ntpath.basename(sec.fname)
                        self.lgr.debug('windDLL loadPickle pid:%d compare %s and %s' % (pid, sec_base, prog_base))
                        if sec_base.startswith(prog_base):
                            self.lgr.debug('winDLL loadPickle pid:%d added missing text for %s' % (pid, sec.fname))
                            self.text[pid] = sec
                else:
                    self.lgr.warning('winDLL loadPickle no prog for pid %d' % pid)
        self.lgr.debug('winDLL loadPickle, have %d texts and %d sections' % (len(self.text), len(self.section_list)))
        for pid in self.text:
            self.lgr.debug('winDLL loadPickle have text for pid %d' % pid)
                    

    def addFile(self, fname, fd, pid):
        if pid not in self.open_files:
            self.open_files[pid] = {}
        dll_info = DLLInfo(pid, fname, fd)
        self.open_files[pid][fd] = dll_info

    def addText(self, fname, pid, addr, size, machine):
        dll_info = DLLInfo(pid, fname, None)
        dll_info.addr = addr
        dll_info.size = size
        dll_info.machine = machine
        self.section_list.append(dll_info)
        self.text[pid] = dll_info
        self.lgr.debug('winDLL addText for pid: %d %s' % (pid, fname))

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
                self.lgr.debug('WinDLLMap is new %s' % new_dll.toString())
                self.lgr.debug('already in list as %s' % dll_info.toString())
                retval = False
                break
        return retval
 
    def mapSection(self, pid, section_handle, load_addr, size):
        if pid in self.sections:
            if section_handle in self.sections[pid]:
                self.sections[pid][section_handle].addLoadAddress(load_addr, size)
                self.lgr.debug('WinDLL mapSection did load address to 0x%x for %s' % (load_addr, self.sections[pid][section_handle].fname))
                if self.isNew(self.sections[pid][section_handle]):
                    section_copy = DLLInfo.copy(self.sections[pid][section_handle])
                    self.section_list.append(section_copy)
                    if pid not in self.text and len(self.pending_procs)>0:
                        self.lgr.debug('winDLL mapSection pid %d not in text' % pid)
                        cpu, comm, pid = self.task_utils.curProc() 
                        rm_pp = None
                        for pp in self.pending_procs:
                            proc_base = ntpath.basename(pp)
                            self.lgr.debug('winDLL mapSection does %s start with %s' % (proc_base, comm))
                            if proc_base.startswith(comm):
                                eproc = self.task_utils.getCurTaskRec()
                                full_path = self.top.getFullPath(fname=pp)
                                win_prog_info = winProg.getWinProgInfo(self.cpu, self.mem_utils, eproc, full_path, self.lgr)
                                self.addText(pp, pid, win_prog_info.text_addr, win_prog_info.text_size, win_prog_info.machine)
                                if win_prog_info.text_size is None:
                                    self.lgr.error('WinDLLMap mapSection text_size is None for %s' % comm)
                                self.lgr.debug('WinDLLMap text mapSection added, len now %d' % len(self.text))
                                rm_pp = pp
                                break
                        if rm_pp is not None:
                            self.pending_procs.remove(rm_pp)

                    self.lgr.debug('WinDLLMap mapSection appended, len now %d' % len(self.section_list))
                    ''' See if we are looking for this SO, e.g., to disable tracing when in it '''
                    self.checkSOWatch(self.sections[pid][section_handle])
                    if pid not in self.max_addr:
                        self.max_addr[pid] = None
                        self.min_addr[pid] = None
                    if self.min_addr[pid] is None or self.min_addr[pid] > load_addr:
                        self.min_addr[pid] = load_addr
                    ma = load_addr + size
                    if self.max_addr[pid] is None or self.max_addr[pid] < ma:
                        self.max_addr[pid] = ma
                else:
                    self.lgr.debug('WinDLLMap Ignore existing section pid %d fname %s' % (pid, self.sections[pid][section_handle].fname))
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
        if pid is None: 
            cpu, comm, pid = self.task_utils.curProc() 
        
        sort_map = {}
        for section in self.section_list:
            if section.pid == pid:
                sort_map[section.addr] = section

        self.lgr.debug('WinDLLMap showSO %d sections' % (len(sort_map)))
        for section_addr in sorted(sort_map):
            section = sort_map[section_addr]
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
                if section.size is not None:
                    end = section.addr+section.size
                    if addr_in >= section.addr and addr_in <= end:
                        retval = section.fname
                        break 
        return retval

    def isCode(self, addr_in, pid):
        ''' TBD not done '''
        retval = False
        if pid in self.min_addr:
            if addr_in >= self.min_addr[pid] and addr_in <= self.max_addr[pid]:
                retval = True
            else:
                for section in self.section_list:
                    if section.pid == pid:
                        end = section.addr+section.size
                        if addr_in >= section.addr and addr_in <= end:
                            retval = True
                            break 
        else:
            self.lgr.error('winDLLMap isCode pid %d not in min/max addr dictionary' % pid)
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
        self.lgr.debug('winDLL getText pid:%s' % pid) 
        if pid in self.text:
            retval = Text(self.text[pid].addr, self.text[pid].size)
        else:
            cpu, comm, cur_pid = self.task_utils.curProc() 
            if pid == cur_pid:
                prog_name = self.top.getProgName(pid)
                full_path = self.top.getFullPath(fname=prog_name)
                self.lgr.debug('winDLL getText, no text yet for %s, try reading it from winProg' % prog_name)
                eproc = self.task_utils.getCurTaskRec()
                win_prog_info = winProg.getWinProgInfo(self.cpu, self.mem_utils, eproc, full_path, self.lgr)
                self.top.setFullPath(full_path)
                self.addText(prog_name, pid, win_prog_info.text_addr, win_prog_info.text_size, win_prog_info.machine)
                retval = Text(win_prog_info.text_addr, win_prog_info.text_size)
        return retval
             
    def setIdaFuns(self, ida_funs):
        if ida_funs is None:
            self.lgr.warning('IDA funs is none, no SOMap')
            return
        self.ida_funs = ida_funs
        # TBD see soMap

    def getSO(self, pid=None, quiet=False):
        self.lgr.debug('winDLL getSO pid %s ' % pid)
        retval = {}
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
        pid = self.getSOPid(pid)
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
        retval['group_leader'] = pid
        if pid in self.sections:
            if pid in self.text and self.text[pid].addr is not None:
                retval['prog_start'] = self.text[pid].addr
                retval['prog_end'] = self.text[pid].addr + self.text[pid].size - 1
                retval['prog'] = self.top.getProgName(pid)
            else:
                self.lgr.debug('winDLL getSO pid %d not in text sections' % pid)
            sort_map = {}
            for section_handle in self.sections[pid]:
                section = self.sections[pid][section_handle]
                if section.addr is not None:
                    sort_map[section.addr] = section
                else:
                    self.lgr.error('winDLL getSO section has none for addr %s' % section.fname)
            retval['sections'] = []
            for locate in sorted(sort_map):
                section = {}
                text_seg = sort_map[locate]
                start = text_seg.addr
                end = locate + text_seg.size
                section['locate'] = locate
                section['end'] = end
                section['offset'] = text_seg.addr
                section['size'] = text_seg.size
                section['file'] = text_seg.fname
                retval['sections'].append(section)
        else:
            self.lgr.debug('no so map for %d' % pid)
        ret_json = json.dumps(retval) 
        if not quiet:
            print(ret_json)
        return ret_json

    def getMachineSize(self, pid):
        retval = None
        if pid in self.text:
            if hasattr(self.text[pid], 'machine'):
               machine = self.text[pid].machine
               if machine is not None:
                   if 'I386' in machine:
                       retval = 32
                   elif 'AMD64' in machine:
                       retval = 64
            else:
                self.lgr.warning('winDLL getMachineSize pid %d missing machine field' % pid) 
        else: 
            self.lgr.error('winDLL getMachineSize pid %d has no text' % pid) 
            for pid in self.text:
                self.lgr.debug('gms pid %d' % pid)
        return retval

    def addPendingProc(self, prog_path):
        self.pending_procs.append(prog_path)
        self.lgr.debug('winDLL addPendingProc %s' % prog_path)
