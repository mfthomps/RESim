import os
import sys
import glob
import pickle
import json
import ntpath
import soMap
import winProg
import resimUtils
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'bin'))
import missingDLLAnalysis
'''
Track DLLs within windows processes.
Tracked by PID as integers for historical reasons.  
Interface variables are TIDs.

TBD Text sizes need to distinguish code from data so that isCode is precise
and data addresses are part of the image for getSO.
'''
class DLLInfo():
    def __init__(self, pid, fname, fd):
        self.fname = fname
        self.local_path = None
        self.fd = fd
        self.pid = pid
        self.section_handle = None
        ''' load address '''
        self.load_addr = None
        ''' offset of text relative to load address '''
        self.text_offset = 0
        ''' size of text '''
        self.size = None
        self.machine = None
        self.image_base = None
        # IF fields are added, add them to copy below.

    @classmethod
    def copy(cls, info):
        new = cls(info.pid, info.fname, info.fd)
        new.load_addr = info.load_addr
        new.size = info.size
        new.text_offset = info.text_offset
        new.machine = info.machine
        new.image_base = info.image_base
        new.local_path = info.local_path
        return new

    def addSectionHandle(self, section_handle):
        self.section_handle = section_handle

    def addLoadAddress(self, load_addr, size):
        self.load_addr = load_addr 
        self.size = size 

    def addMachine(self, machine):
        self.machine = machine

    def addImageBase(self, image_base):
        self.image_base = image_base

    def match(self, dll_info):
        retval = False
        if dll_info.pid == self.pid and dll_info.load_addr == self.load_addr and dll_info.size == self.size and dll_info.fname == self.fname:
            retval = True
        return retval
    def toString(self):
        if self.load_addr is not None:
            retval = '%s pid:%s addr: 0x%x size 0x%x' % (self.fname, self.pid, self.load_addr, self.size)
        elif self.size is not None:
            retval = '%s pid:%s addr: ??? size 0x%x' % (self.fname, self.pid, self.size)
        else:
            retval = '%s pid:%s addr: ??? size ???' % (self.fname, self.pid)
        return retval


class WinDLLMap():
    def __init__(self, top, cpu, cell_name, mem_utils, task_utils, context_manager, run_from_snap, lgr):
        self.cpu = cpu
        self.cell_name = cell_name
        self.task_utils = task_utils
        self.mem_utils = mem_utils
        self.context_manager = context_manager
        self.lgr = lgr
        self.top = top
        self.open_files = {}
        self.sections = {}
        self.section_map = {}
        self.min_addr = {}
        self.max_addr = {}
        self.so_watch_callback = {}
        self.fun_mgr = None
        self.text = {}
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)
        self.pending_procs = []
        self.fun_list_cache = []
        self.unknown_sections = {}
        self.word_sizes = {}
        self.loadWordSizes()
        self.root_prefix = self.top.getCompDict(self.cell_name, 'RESIM_ROOT_PREFIX')
        self.exec_dict = resimUtils.getExecDict(self.root_prefix, lgr=self.lgr)
        if self.exec_dict is not None:
            self.lgr.debug('winDLLMap using exec_dict')
        else:
            self.lgr.debug('winDLLMap NO exec_dict')

    def pickleit(self, name):
        somap_file = os.path.join('./', name, self.cell_name, 'soMap.pickle')
        so_pickle = {}
        so_pickle['open_files'] = self.open_files
        so_pickle['sections'] = self.sections
        #so_pickle['section_list'] = self.section_list
        so_pickle['section_map'] = self.section_map
        so_pickle['text'] = self.text
        fd = open( somap_file, "wb") 
        pickle.dump( so_pickle, fd)
        self.lgr.debug('winDLLMap pickleit to %s %d text sections %d pids in section_map' % (somap_file, len(self.text), len(self.section_map)))

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
                if 'section_list' in so_pickle:
                    section_list = so_pickle['section_list']
                    self.lgr.debug('windDLL compatability %d sections %d section_list' % (len(self.sections), len(section_list)))
                    for section in section_list:
                        if section.pid not in self.section_map:
                            self.section_map[section.pid] = {}
                        self.section_map[section.pid][section.fname] = section
                        if section.fname.lower().endswith('fnet.dll'):
                            self.lgr.debug('FNET addr 0x%x' % section.load_addr)
                else:
                    self.section_map = so_pickle['section_map']
 
                for pid in self.section_map:
                    for fname in self.section_map[pid]:
                        section = self.section_map[pid][fname]
                        if section.load_addr is None:
                            self.lgr.debug('winDLL loadPickle no section.load_addr for %s' % section.fname)
                            continue
                        if section.pid not in self.min_addr:
                            self.min_addr[section.pid] = None
                            self.max_addr[section.pid] = None
                        if (self.min_addr[section.pid] is None or self.min_addr[section.pid] > section.load_addr) and section.load_addr != 0 and section.text_offset is not None:
                            #TBD what is being loaded at addr 0?  Are we getting confused by mapped memory that is not code?
                            self.min_addr[section.pid] = section.load_addr + section.text_offset
                        if section.size is None:
                            self.lgr.warning('winDLL loadPickle no size for %s, addr 0x%x pid:%s' % (section.fname, section.load_addr, section.pid))
                            continue
                        if section.text_offset is not None:
                            ma = section.load_addr + section.text_offset + section.size
                        else:
                            ma = section.load_addr + section.size
                        if self.max_addr[section.pid] is None or self.max_addr[section.pid] < ma:
                            self.max_addr[section.pid] = ma
    
                        if section.pid not in self.sections:
                            self.sections[section.pid] = {}
                        if section.section_handle is not None and section.section_handle not in self.sections[section.pid]:
                            self.sections[section.pid][section.section_handle] = section
                            #if section.fname.lower().endswith('fnet.dll'):
                            #    self.lgr.debug('FNET addr 0x%x' % section.load_addr)
              
            else:
                self.lgr.debug('windDLL loadPickle no open_files in pickle')
            if 'text' in so_pickle:
                self.text = so_pickle['text']
            else:
                self.lgr.debug('windDLL loadPickle no text in pickle')

        for pid in self.sections:
            self.lgr.debug('windDLL loadPickle check pid:%s' % pid)
            if pid not in self.text:
                prog = self.top.getProgName(pid)
                if prog is not None:
                    self.lgr.debug('winDLL TBD is this a windows path? %s if so fix this' % prog)
                    prog_base = ntpath.basename(prog)
                    for sec_handle in self.sections[pid]:
                        sec = self.sections[pid][sec_handle]
                        sec_base = ntpath.basename(sec.fname)
                        #self.lgr.debug('windDLL loadPickle pid:%s compare %s and %s' % (pid, sec_base, prog_base))
                        if sec_base.startswith(prog_base):
                            self.lgr.debug('winDLL loadPickle pid:%s added missing text for %s' % (pid, sec.fname))
                            self.text[pid] = sec
                else:
                    self.lgr.warning('winDLL loadPickle no prog for pid:%s' % pid)
        self.lgr.debug('winDLL loadPickle, have %d texts and %d section list pids' % (len(self.text), len(self.section_map)))
        for pid in self.text:
            self.lgr.debug('winDLL loadPickle have text for pid:%s' % pid)

    def pidFromTID(self, tid):
        if tid is None:
            return None
        # make sure it is string
        tid = str(tid)
        if '-' in tid:
            return int(tid.split('-')[0])
        else:
            return int(tid)

    def addFile(self, fname, fd, tid):
        pid = self.pidFromTID(tid)
        self.lgr.debug('winDLL addFile tid:%s fd:0x%x fname: %s' % (tid, fd, fname))
        if pid not in self.open_files:
            self.open_files[pid] = {}
        full_path = self.top.getFullPath(fname=fname)
        win_prog_info = winProg.getWinProgInfo(self.cpu, self.mem_utils, None, full_path, self.lgr)

        dll_info = DLLInfo(pid, fname, fd)
        dll_info.load_addr = win_prog_info.load_addr
        dll_info.size = win_prog_info.text_size
        dll_info.image_base = win_prog_info.image_base
        dll_info.text_offset = win_prog_info.text_offset
        dll_info.machine = win_prog_info.machine
        if dll_info.image_base is not None:
            self.lgr.debug('winDLL addFile tid:%s image_base 0x%x fname: %s' % (tid, dll_info.image_base, fname))
        else:
            self.lgr.debug('winDLL addFile tid:%s image_base None for fname: %s' % (tid, fname))

        if dll_info.text_offset is not None:
            self.lgr.debug('winDLL addFile tid:%s text_offset 0x%x fname: %s' % (tid, dll_info.text_offset, fname))
        else:
            self.lgr.debug('winDLL addFile tid:%s text_offset None for fname: %s' % (tid, fname))

        self.open_files[pid][fd] = dll_info

    def addText(self, fname, tid, addr, size, machine, image_base, text_offset, local_path):
        pid = self.pidFromTID(tid)
        dll_info = DLLInfo(pid, fname, None)
        dll_info.load_addr = addr
        dll_info.text_offset = text_offset
        dll_info.size = size
        dll_info.machine = machine
        dll_info.image_base = image_base
        dll_info.local_path = local_path
        if pid not in self.section_map:
            self.section_map[pid] = {}
        self.section_map[pid][fname] = dll_info
        self.text[pid] = dll_info
        self.lgr.debug('winDLL addText for pid:%s %s' % (pid, fname))

    def createSection(self, fd, section_handle, tid):
        pid = self.pidFromTID(tid)
        if pid in self.open_files:
            if fd in self.open_files[pid]:
                self.open_files[pid][fd].addSectionHandle(section_handle) 
                if pid not in self.sections:
                    self.sections[pid] = {}
                self.sections[pid][section_handle] = self.open_files[pid][fd]
                self.lgr.debug('winDLL createSection pid:%s section handle 0x%x fname %s' % (pid, section_handle, self.open_files[pid][fd].fname))
                #del self.open_files[pid][fd]
                
            else:                
                self.lgr.warning('WinDLLMap createSection fd %d not defined for pid:%s section_handle 0x%x' % (fd, pid, section_handle))
        else:
            self.lgr.warning('WinDLLMap createSection pid:%s not defined ' % (pid))

    def isNew(self, new_dll, pid):
        retval = True
        if pid in self.section_map:
            for fname in self.section_map[pid]:
                dll_info = self.section_map[pid][fname]
                if dll_info.match(new_dll):
                    self.lgr.debug('already in list as %s' % dll_info.toString())
                    retval = False
                    break
        return retval
 
    def mapSection(self, tid, section_handle, load_addr, size):
        # map a section into the section_map
        pid = self.pidFromTID(tid)
        if pid in self.sections:
            if section_handle in self.sections[pid]:
                if self.isNew(self.sections[pid][section_handle], pid):
                    self.sections[pid][section_handle].addLoadAddress(load_addr, size)
                    self.lgr.debug('WinDLL mapSection tid: %s did load address to 0x%x for %s' % (tid, load_addr, self.sections[pid][section_handle].fname))
                    #self.findLoadAddr(pid, load_addr)
                    section_copy = DLLInfo.copy(self.sections[pid][section_handle])
                    if pid not in self.section_map:
                        self.section_map[pid] = {}
                    
                    already = self.getSOFileFull(load_addr)
                    if already is not None and already != self.sections[pid][section_handle].fname:
                        old = self.section_map[pid][already]
                        self.lgr.debug('winDLL mapSection already have %s at new load addr 0x%x.  Old load addr 0x%x size 0x%x.  Remove old' % (already, load_addr, old.load_addr, old.size))
                        del self.section_map[pid][already]
                    self.section_map[pid][self.sections[pid][section_handle].fname] = section_copy
                    debugging_pid, dumb = self.context_manager.getDebugTid()
                    if debugging_pid is not None:
                        self.addSectionFunction(section_copy, section_copy.load_addr)
                    if pid not in self.text and len(self.pending_procs)>0:
                        self.lgr.debug('winDLL mapSection pid:%s not in text' % pid)
                        cpu, comm, dumb_pid = self.task_utils.curThread() 
                        rm_pp = None
                        for pp in self.pending_procs:
                            proc_base = ntpath.basename(pp)
                            self.lgr.debug('winDLL mapSection does %s start with %s' % (proc_base, comm))
                            if proc_base.startswith(comm):
                                #
                                #  Pending processes. Below is not for DLLs
                                #
                                eproc = self.task_utils.getCurThreadRec()
                                full_path = self.top.getFullPath(fname=pp)
                                win_prog_info = winProg.getWinProgInfo(self.cpu, self.mem_utils, eproc, full_path, self.lgr)
                                self.addText(pp, tid, win_prog_info.load_addr, win_prog_info.text_size, win_prog_info.machine, 
                                            win_prog_info.image_base, win_prog_info.text_offset, full_path)
                                if win_prog_info.text_size is None:
                                    self.lgr.error('WinDLLMap mapSection text_size is None for %s' % comm)
                                if win_prog_info.load_addr is None:
                                    self.lgr.debug('WinDLLMap mapSection load_addr is None for %s' % comm)
                                else:
                                    self.lgr.debug('WinDLLMap mapSection load_addr is 0x%x for %s' % (win_prog_info.load_addr, comm))
                                self.lgr.debug('WinDLLMap text mapSection added, len now %d' % len(self.text))
                                rm_pp = pp
                                break
                        if rm_pp is not None:
                            self.pending_procs.remove(rm_pp)

                    # TBD is pending_procs necessary?  Why not always add text if missing for pid?
                    if pid not in self.text:
                        #self.getText(tid)
                        self.lgr.debug('WinDLLMap mapSection pid %d not yet in self.text, call addText' % pid)
                        eproc = self.task_utils.getCurThreadRec()
                        prog_name = self.top.getProgName(tid)
                        full_path = self.top.getFullPath(fname=prog_name)
                        #self.top.setFullPath(full_path)
                        win_prog_info = winProg.getWinProgInfo(self.cpu, self.mem_utils, eproc, full_path, self.lgr)
                        if win_prog_info is None:
                            self.lgr.error('WinDLLMap mapSection got None for win_prog_info for path %s' % full_path)
                        self.addText(prog_name, tid, win_prog_info.load_addr, win_prog_info.text_size, win_prog_info.machine, win_prog_info.image_base, win_prog_info.text_offset, full_path)
                    elif self.text[pid].load_addr is None:
                        eproc = self.task_utils.getCurThreadRec()
                        prog_name = self.top.getProgName(tid)
                        text_load_addr = winProg.getLoadAddress(self.cpu, self.mem_utils, eproc, prog_name, self.lgr)
                        if text_load_addr is not None:
                            self.text[pid].load_addr = text_load_addr
                            self.lgr.debug('WinDLLMap mapSection got load_addr 0x%x for text for pid %s' % (text_load_addr, pid))

                    self.lgr.debug('WinDLLMap mapSection for pid %s, len for pid now %d' % (pid, len(self.section_map[pid])))
                    ''' See if we are looking for this SO, e.g., to disable tracing when in it '''
                    dll_info = self.sections[pid][section_handle]
                    self.checkSOWatch(dll_info)
                    if pid not in self.max_addr:
                        self.max_addr[pid] = None
                        self.min_addr[pid] = None
                    if (self.min_addr[pid] is None or self.min_addr[pid] > load_addr) and load_addr != 0:
                        # TBD what is loaded at zero?  
                        self.min_addr[pid] = load_addr
                    ma = load_addr + size
                    if self.max_addr[pid] is None or self.max_addr[pid] < ma:
                        self.max_addr[pid] = ma
                else:
                    self.lgr.debug('WinDLLMap Ignore existing section pid:%s fname %s' % (pid, self.sections[pid][section_handle].fname))
            else:                
                if pid in self.unknown_sections and load_addr not in self.unknown_sections[pid]:
                    unknown_dll = DLLInfo(pid, 'unknown', -1)
                    unknown_dll.addLoadAddress(load_addr, size)
                    if pid not in self.section_map:
                        self.section_map[pid] = {}
                    self.section_map[pid]['unknown'] = unknown_dll
                    if pid not in self.unknown_sections:
                        self.unknown_sections[pid] = []
                    self.unknown_sections[pid].append(load_addr)
                    self.lgr.debug('WinDLLMap mapSection section_handle %d not defined for pid:%s, add unknown section' % (section_handle, pid))
        else:
            self.lgr.warning('WinDLLMap mapSection pid:%s not in sections ' % (pid))

    def checkSOWatch(self, section):
        basename = ntpath.basename(section.fname)
        if basename in self.so_watch_callback:
            for name in self.so_watch_callback[basename]:
                if name == 'NONE':
                    self.lgr.debug('winDLL checkSOWatch do callback for %s' % basename)
                    self.so_watch_callback[basename][name](section)
                else:
                    self.lgr.debug('winDLL checkSOWatch do callback for %s, name %s' % (basename, name))
                    self.so_watch_callback[basename][name](section.load_addr, name)

    def showSO(self, tid, filter=None, save=False):
        if tid is None: 
            cpu, comm, tid = self.task_utils.curThread() 
        
        pid = self.pidFromTID(tid)
        sort_map = {}
        if pid not in self.section_map:
            print('pid %s not in section_map' % pid)
            self.lgr.debug('showSO pid %s not in section_map' % pid)
            return
        for fname in self.section_map[pid]:
            section = self.section_map[pid][fname]
            if section.pid == pid:
                if section.load_addr is not None:
                    sort_map[section.load_addr] = section
                else:
                    self.lgr.debug('WinDLLMap no addr for section %s' % section.fname)

        self.lgr.debug('WinDLLMap showSO pid:%d %d sections, %d in pids section_map' % (pid, len(sort_map), len(self.section_map[pid])))
        if save:
            ofile = 'logs/somap-%s.somap' % tid
            ofile_fh = open(ofile, 'w')
        for section_addr in sorted(sort_map):
            section = sort_map[section_addr]
            if filter is None or filter in section.fname:
                if section.size is None:
                    if save:
                        ofile_fh.write('pid:%s 0x%x size UNKNOWN %s\n' % (section.pid, section.load_addr, section.fname)) 
                    else:
                        print('pid:%s 0x%x size UNKNOWN %s' % (section.pid, section.load_addr, section.fname)) 
                   
                else:
                    end = section.load_addr+section.size - 1
                    if save:
                        ofile_fh.write('pid:%s 0x%x - 0x%x %s\n' % (section.pid, section.load_addr, end, section.fname)) 
                    else:
                        print('pid:%s 0x%x - 0x%x %s' % (section.pid, section.load_addr, end, section.fname)) 
                    self.lgr.debug('winDLLMap showSO pid:%s 0x%x - 0x%x %s' % (section.pid, section.load_addr, end, section.fname)) 
        if save:
            ofile_fh.close()

    def listSO(self, filter=None):
        #for pid in self.text:
        #    end = self.text[pid].addr + self.text[pid].size
        #    print('pid:%s  0x%x - 0x%x   %s' % (pid, self.text[pid].addr, end, self.text[pid].fname))
        print('List libraries for cell %s' % self.cell_name)
        for pid in self.section_map:
            for fname in self.section_map[pid]:
                section = self.section_map[pid][fname]
                if filter is None or filter in section.fname:
                    if section.load_addr is None:
                        print('pid:%s  no load address  %s' % (section.pid, section.fname))
 
                    elif section.size is not None:
                        end = section.load_addr + section.size -1
                        print('pid:%s  0x%x - 0x%x   %s' % (section.pid, section.load_addr, end, section.fname))
                    else:
                        print('pid:%s  0x%x - ???  %s' % (section.pid, section.load_addr, section.fname))

    def isMainText(self, address):
        retval = False
        dumb, comm, tid = self.task_utils.curThread() 
        pid = self.pidFromTID(tid)
        if pid in self.text:
            end = self.text[pid].load_addr + self.text[pid].size - 1
            if address >= self.text[pid].load_addr and address <= end:
                retval = True
        return retval

    def isAboveLibc(self, address):
        # TBD fix for windows
        retval = False
        if self.isMainText(address):
            retval = True
        else:
            so_file = self.getSOFile(address)
            if so_file is not None and not resimUtils.isClib(so_file):
                fun = self.fun_mgr.getFunName(address)
                if fun is not None:
                    retval = True 
        return retval           

    def isLibc(self, address):
        retval = False
        so_file = self.getSOFile(address)
        if so_file is not None and resimUtils.isClib(so_file):
            retval = True
        return retval

    def isFunNotLibc(self, address):
        ''' return False if address not in libc, or similar windows rat hole.'''
        retval = False
        if self.isMainText(address):
            retval = True
        else:
            so_file_full = self.getSOFileFull(address)
            if so_file_full is not None:
                so_file = os.path.basename(so_file_full)
                if not resimUtils.isClib(so_file, lgr=self.lgr):
                    fun = self.fun_mgr.getFunName(address)
                    if fun is not None:
                        retval = True 
                    elif resimUtils.isWindowsCore(so_file_full):
                        retval = True
        return retval           

    def getSOFile(self, addr_in):
        retval = None
        full = self.getSOFileFull(addr_in)
        if full is not None:
            retval = ntpath.basename(full)
        
        return retval

    def getSOFileFull(self, addr_in):
        retval = None
        dumb, comm, tid = self.task_utils.curThread() 
        pid = self.pidFromTID(tid)
        if addr_in is not None:
            got_unknown = False
            if pid not in self.section_map:
                self.lgr.debug('winDLL getSOFile pid %s not in section_map' % pid)
                return retval
            for fname in self.section_map[pid]:
                section = self.section_map[pid][fname]
                if section.fname != fname:
                    self.lgr.error('winDLL getSOFileFull section.fname is %s section_map fname %s' % (section.fname, fname))
                if section.load_addr is None:
                    #self.lgr.debug('getSOFile got no addr for section %s' % section.fname)
                    continue
                if section.pid == pid:
                    if section.size is not None:
                        end = section.load_addr+section.size - 1
                        if addr_in >= section.load_addr and addr_in <= end:
                            if fname != 'unknown':
                                if retval is not None:
                                    #self.lgr.debug('winDLL getSOFile got retval of %s, but now %s?' % (retval, fname))
                                    pass
                                retval = fname
                            else:
                                got_unknown = True
                    else:
                        self.lgr.debug('winDLL getSOFile section size is None for %s' % fname)
            if retval is None and got_unknown:
                retval = 'unknown'     
        return retval


    def isCode(self, addr_in, tid):
        if addr_in is None:
            self.lgr.error('winDLLMap isCode pid:%s addr_in is none '% tid)
            return False
        pid = self.pidFromTID(tid)
        retval = False
        if pid in self.min_addr:
            if addr_in >= self.min_addr[pid] and addr_in <= self.max_addr[pid]:
                #self.lgr.debug('winDLL isCode 0x%x falls in min/max' % addr_in)
                retval = True
            else:
                if pid in self.section_map:
                    for fname in self.section_map[pid]:
                        section = self.section_map[pid][fname]
                        if section.load_addr == 0 or section.size is None:
                            continue
                        if section.pid == pid:
                            end = section.load_addr+section.size - 1
                            if addr_in >= section.load_addr and addr_in <= end:
                                retval = True
                                break 
        else:
            self.lgr.debug('winDLLMap isCode pid:%s not in min/max addr dictionary' % pid)
            pass
        return retval

    def getLoadAddrSize(self, in_fname, tid=None):
        self.lgr.debug('winDLLMap loadAddr %s tid %s' % (in_fname, tid))
        retval = None
        ret_size = None
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        pid = self.pidFromTID(tid)
        if pid is None:
            self.lgr.error('winDLLMap getLoadAddr no pid for %s' % str(pid))
            return None
        if in_fname == 'unknown':
            self.lgr.debug('winDLLMap getLoadAddr in_fname is "unknown" for pid for %s' % str(pid))
            return None
        if pid in self.section_map:
            for fname in self.section_map[pid]:
                #self.lgr.debug('winDLLMap compare %s to %s' % (os.path.basename(in_fname).lower(), ntpath.basename(section.fname).lower()))
                if ntpath.basename(in_fname).lower() == ntpath.basename(fname).lower():
                    section = self.section_map[pid][fname]
                    self.lgr.debug('winDLLMap got match for %s section.load_addr 0x%x tid:%s' % (fname, section.load_addr, tid))
                    retval = section.load_addr
                    ret_size = section.size
                    break 
        return retval, ret_size

    def getLoadAddr(self, in_fname, tid=None):
        retval, ret_size = self.getLoadAddrSize(in_fname, tid=tid)
        return retval

    def getImageBaseForPid(self, in_fname, pid):
        # TBD separate staic program info from load addres and remove this.
        retval = None
        pid = self.pidFromTID(str(pid))
        self.lgr.debug('winDLL getImageBaseForPid %s pid: %d' % (in_fname, pid))
        if pid not in self.section_map:
            self.lgr.error('winDLL getImageBaseForPid, no section map for pid %d' % pid)
            return retval
        for fname in self.section_map[pid]:
            #self.lgr.debug('compare %s to %s' % (ntpath.basename(in_fname).lower(), ntpath.basename(fname).lower()))
            if ntpath.basename(in_fname).lower() == ntpath.basename(fname).lower():
                section = self.section_map[pid][fname]
                self.lgr.debug('winDLL getImageBaseForPid got %s' % in_fname)
                if section.image_base is None:
                    full_path = self.top.getFullPath(fname=fname)
                    win_prog_info = winProg.getWinProgInfo(self.cpu, self.mem_utils, None, full_path, self.lgr)
                    if win_prog_info is not None:
                        section.image_base = win_prog_info.image_base
                        section.size = win_prog_info.text_size
                    else:
                        self.lgr.error('winDLL getImageBaseForPid no image base for section %s' % section.fname)
                else:
                    self.lgr.debug('winDLL getImageBaseForPid image base for section %s is 0x%x' % (section.fname, section.image_base))
                retval = section.image_base
                break 
        return retval

    def getImageBase(self, in_fname, pid=None):
        retval = None
        if pid is None:
            for pid in self.section_map:
                retval = self.getImageBaseForPid(in_fname, pid)
                if retval is not None:
                    break
        return retval

    def getSOPidList(self, in_fname):
        # Get a list of PIDs that have the given library loaded
        retval = []
        self.lgr.debug('winDLLMap getSOPidList in_fname %s' % in_fname)
        if in_fname == 'unknown':
            self.lgr.debug('winDLLMap getSOPidList in_fname is "unknown" for pid for %s' % str(pid))
            return retval
        for pid in self.section_map:
            for fname in self.section_map[pid]:
                if ntpath.basename(in_fname).lower() == ntpath.basename(fname).lower():
                    self.lgr.debug('winDLLMap getSOPidList got match')
                    retval.append(pid)
                    break
        return retval
   
    def getSOInfo(self, addr_in):
        retval = None, None, None
        cpu, comm, tid = self.task_utils.curThread() 
        pid = self.pidFromTID(tid)
        if pid is None:
            return retval
        if pid in self.section_map:
            for fname in self.section_map[pid]:
                section = self.section_map[pid][fname]
                end = section.load_addr+section.size - 1
                #self.lgr.debug('winDLL getSOInfo section fname %s addr 0x%x end 0x%x  addr_in 0x%x map_fname %s' % (section.fname, section.load_addr, end, addr_in, fname))
                if addr_in >= section.load_addr and addr_in <= end:
                    retval = (fname, section.load_addr, end)
                    #break 
        return retval

    def getCodeSections(self, tid):
        retval = []
        pid = self.pidFromTID(tid)
        if pid in self.section_map:
            for fname in self.section_map[pid]:
                section = self.section_map[pid][fname]
                code_section = soMap.CodeSection(section.load_addr, section.size, fname)
                retval.append(code_section) 
        return retval

    def addSOWatch(self, fname, callback, name=None):
        if name is None:
            name = 'NONE'
        if fname not in self.so_watch_callback:
            self.so_watch_callback[fname] = {}
        self.so_watch_callback[fname][name] = callback

    def cancelSOWatch(self, fname, name):
        if fname in self.so_watch_callback:
            if name in self.so_watch_callback[fname]:
                del self.so_watch_callback[fname][name]

    def getAnalysisPath(self, fname):
        if len(self.fun_list_cache) == 0:
            self.fun_list_cache = resimUtils.getFunListCache(None, root_prefix=self.root_prefix)
            self.lgr.debug('winDLL getAnalysisPath loaded %d into fun cache' % len(self.fun_list_cache))
        return resimUtils.getAnalysisPath(None, fname, fun_list_cache = self.fun_list_cache, root_prefix=self.root_prefix, lgr=self.lgr)

    def setFunMgr(self, fun_mgr, tid):
        if fun_mgr is None:
            self.lgr.warning('IDA funs is none, no SOMap')
            return
        self.lgr.debug('winDLL setFunMgr tid:%s' % tid)
        self.fun_mgr = fun_mgr
        only_so = self.top.getCompDict(self.cell_name, 'ONLY_SO')
        only_so_list = []
        if only_so is not None:
            if os.path.isfile(only_so):
                with open(only_so) as fh:
                    for line in fh:
                        only_so_list.append(line.strip().lower()) 
            else:
                self.lgr.debug('No ONLY_SO files at %s' % only_so)
 
        pid = self.pidFromTID(tid)
        sort_map = {}
        if pid in self.section_map:
            for fname in self.section_map[pid]:
                section = self.section_map[pid][fname]
                if len(only_so_list) > 0 and os.path.basename(section.fname) not in only_so_list:
                    continue
                sort_map[section.load_addr] = section

            for locate in sorted(sort_map, reverse=True):
                section = sort_map[locate]
                if section.fname != 'unknown':
                    self.addSectionFunction(section, locate)
        else:
            self.lgr.debug('winDLL setFunMgr pid %d not in section_map' % pid)

    def addSectionFunction(self, section, locate):
        if self.fun_mgr is None:
            #self.lgr.error('winDLL MISSING fun_mgr *************************************')
            self.lgr.debug('winDLL MISSING fun_mgr *************************************')
            return
        self.lgr.debug('winDLL addSectionFunction section.fname %s local %s' % (section.fname, section.local_path))
        fun_path = self.getAnalysisPath(section.fname)
        if fun_path is not None:
            self.lgr.debug('winDLL addSectionFunction set addr 0x%x for %s' % (locate, fun_path))
            if section.image_base is None:
                full_path = self.top.getFullPath(fname=section.fname)
                self.lgr.debug('winDLL addSectionFunction got %s from getFullPath' % full_path)
                size, machine, image_base, text_offset = winProg.getSizeAndMachine(full_path, self.lgr)
                section.image_base = image_base
                section.text_offset = text_offset
                section.size = size
                section.local_path = full_path
          
            else:
                image_base = section.image_base
                text_offset = section.text_offset
            if text_offset is not None:
                delta = (locate - image_base) 
                offset = delta + text_offset
                self.lgr.debug('winDLL addSectionFunction xxx offset 0x%x locate: 0x%x text_offset 0x%x image_base 0x%x delta 0x%x fun_path: %s' % (offset, locate, text_offset, image_base, delta, fun_path))
            else:
                offset = 0
                text_offset = 0
                self.lgr.debug('winDLL addSectionFunction text_offset is None fun_path: %s' % (fun_path))
            self.fun_mgr.add(fun_path, locate, offset=offset, text_offset=text_offset)


    def getSO(self, tid=None, quiet=False):
        self.lgr.debug('winDLL getSO tid %s ' % tid)
        retval = {}
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        pid = self.pidFromTID(tid)
        retval['group_leader'] = str(pid)
        if pid in self.text and self.text[pid].load_addr is not None:
                retval['prog_start'] = self.text[pid].load_addr
                retval['prog_end'] = self.text[pid].load_addr + self.text[pid].size - 1
                retval['prog'] = self.top.getProgName(pid)
                retval['prog_local_path'] = self.top.getFullPath()
        else:
            self.lgr.debug('winDLL getSO pid:%s not in text sections' % pid)
        sort_map = {}
        if pid in self.section_map:
            for fname in self.section_map[pid]:
                section = self.section_map[pid][fname]
                if section.pid == pid:
                    if section.load_addr is not None:
                        sort_map[section.load_addr] = section
                    else:
                        self.lgr.error('winDLL getSO section has none for addr %s' % section.fname)
            retval['sections'] = []
            for locate in sorted(sort_map):
                section = {}
                text_seg = sort_map[locate]
                start = text_seg.load_addr
                end = locate + text_seg.size - 1
                section['locate'] = locate
                section['end'] = end
                section['offset'] = text_seg.text_offset
                section['size'] = text_seg.size
                section['file'] = text_seg.fname
                section['local_path'] = text_seg.local_path
                retval['sections'].append(section)

        ret_json = json.dumps(retval) 
        if not quiet:
            print(ret_json)
        return ret_json

    def wordSize(self, tid=None):
       # TBD clean this up
       retval = None
       if tid is None:
           retval = self.mem_utils.wordSize(self.cpu)
       else:
           retval = None
           ms = self.getMachineSize(tid)
           if ms == 32:
               retval = 4
           elif ms  == 64:
               retval = 8
           elif ms is None:
               retval = self.mem_utils.wordSize(self.cpu)
       return retval

    def findSize(self, find_comm):
        retval = None
        if find_comm in self.word_sizes:
            retval = self.word_sizes[find_comm]
        elif len(find_comm) == self.task_utils.commSize():
            for comm in self.word_sizes:
                if comm.startswith(find_comm):
                    retval = self.word_sizes[comm]
        if find_comm == 'services.exe':
            self.lgr.debug('winDLL findSize HEREEEEEE')
        if retval is None and self.exec_dict is not None:
            if find_comm in self.exec_dict:
                retval = self.exec_dict[find_comm][0]['word_size']
                self.lgr.debug('winDLLMap findSize found size in exec_dict for %s, %s' % (find_comm, retval))
            elif len(find_comm) == self.task_utils.commSize():
                for exec_base in self.exec_dict:
                    if exec_base.startswith(find_comm):
                        retval = self.exec_dict[exec_base][0]['word_size']
                        self.lgr.debug('winDLLMap findSize truncated base found size in exec_dict for %s, %s' % (find_comm, retval))
   
        return retval

    def getMachineSize(self, tid=None):
        retval = None
        if tid is None:
            return self.task_utils.getMemUtils().wordSize(self.cpu)
        pid = self.pidFromTID(tid)
        #self.lgr.debug('getMachineSize tid %s' % tid)
        if pid in self.text:
            #self.lgr.debug('getMachineSize tid %s in text' % tid)
            if hasattr(self.text[pid], 'machine'):
               machine = self.text[pid].machine
               #self.lgr.debug('getMachineSize tid %s has machine %s' % (tid, machine))
               if machine is not None:
                   if 'I386' in machine:
                       retval = 32
                   elif 'AMD64' in machine:
                       retval = 64

            else:
                self.lgr.warning('winDLL getMachineSize pid:%s missing machine field' % pid) 
        elif pid is not None:
            find_comm = self.task_utils.getCommFromTid(tid)
            #self.lgr.debug('winDLLMap getMachineSize comm %s for tid %s' % (find_comm, tid))
            num_bytes = self.findSize(find_comm) 
            if num_bytes is None:
                #self.lgr.debug('winDLL getMachineSize pid:%s has no text' % pid) 
                pass
            else:
                retval = num_bytes * 8
        else:
            self.lgr.error('winDLL getMachineSize with pid of None')
       
        #if retval is not None: 
        #    self.lgr.debug('winDLL getMachineSize of %d for pid:%s' % (retval, pid))
        
        return retval

    def addPendingProc(self, prog_path):
        if len(prog_path.strip()) > 0:
            self.pending_procs.append(prog_path)
            self.lgr.debug('winDLL addPendingProc %s' % prog_path)

    def handleExit(self, tid, killed=False):
        ''' when a thread leader exits, clone the so map structures to each child, TBD determine new thread leader? '''
        pid = self.pidFromTID(tid)
        if pid not in self.so_addr_map and pid not in self.prog_start:
            self.lgr.debug('SOMap handleExit pid:%s not in so_addr map' % pid)
            return
        ''' TBD for windows'''
        self.lgr.debug('DLLmap handleExit pid:%s  TBD for windows' % pid)
        return

    def swapTid(self, old, new):
       ''' TBD ??? '''
       return False

    def getProg(self, tid):
        retval = None
        pid = self.pidFromTID(tid)
        if pid in self.text:
            dll_info = self.text[pid]
            retval = dll_info.fname
        return retval

    def getLocalPath(self, tid):
        retval = None
        pid = self.pidFromTID(tid)
        if pid in self.text:
            dll_info = self.text[pid]
            retval = dll_info.local_path
        return retval

    def getFullPath(self, comm):
        retval = None
        for pid in self.text:
            base = ntpath.basename(self.text[pid].fname)
            if base.startswith(comm):
                retval = self.text[pid].fname
        return retval

    def getLoadInfo(self):
        load_info = None
        cpu, comm, tid = self.task_utils.curThread() 
        pid = self.pidFromTID(tid)
        if pid in self.text:
            dll_info = self.text[pid]
            if dll_info.load_addr is None:
                eproc = self.task_utils.getCurThreadRec()
                text_load_addr = winProg.getLoadAddress(self.cpu, self.mem_utils, eproc, comm, self.lgr)
                dll_info.load_addr = text_load_addr
                if dll_info.load_addr is None:
                    self.lgr.debug('winDLL getLoadInfo load_addr None for text[%s] %s' % (pid, dll_info.fname))
                else:
                    self.lgr.debug('winDLL getLoadInfo load_addr was None for text[%s] %s, loaded with 0x%x' % (pid, dll_info.fname, text_load_addr))
            if dll_info.load_addr is not None:
                load_info = soMap.LoadInfo(dll_info.load_addr, dll_info.size)
        else:
            self.lgr.debug('winDLL getLoadInfo pid %s not in self.text' % pid)
        return load_info

    def getLoadOffset(self, in_fname, tid=None):
        retval = None
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        pid = self.pidFromTID(tid)
        if pid in self.section_map:
            for fname in self.section_map[pid]:
                if ntpath.basename(in_fname).lower() == ntpath.basename(fname).lower():
                    section = self.section_map[pid][fname]
                    if section.load_addr is None:
                        self.lgr.error('winDLL getLoadOffset section for pid %s %s has not load addr' % (pid, fname))
                    elif section.image_base is not None:
                        retval = section.load_addr - section.image_base
                    else:
                        self.lgr.debug('winDLL getLoadOffset %s tid %s no image base, just use load_addr 0x%x' % (in_fname, tid, section.load_addr))
                        retval = section.load_addr 
                    break
        else:
            self.lgr.debug('winDLL getLoadOffset tid %s not in section_map' % pid)
        return retval


    def getSOTid(self, tid):
        # compatability 
        return tid

    def getProgSize(self, prog_in):
        self.lgr.error('winDLL getProgSize not done yet')
        return None

    def loadWordSizes(self):
        fname = self.top.getCompDict(self.cell_name, 'WORD_SIZES')
        if fname is not None:
            if os.path.isfile(fname):
                with open(fname) as fh:
                    for line in fh:
                        line = line.strip()
                        if line.startswith('#') or len(line)==0:
                            continue
                        parts = line.split()
                        comm = parts[0]
                        size = parts[1]
                        self.word_sizes[comm] = int(size)
                        self.lgr.debug('winDLLMap loadWordSizes added %s %d' % (comm, self.word_sizes[comm]))
                      
            else:
                self.lgr.error('winDLLMap failed to find word sizes file at %s' % fname)

    def findPendingProg(self, comm):
        retval = None
        for pp in self.pending_procs:
            proc_base = ntpath.basename(pp)
            self.lgr.debug('winDLL findPendingProg does %s start with %s' % (proc_base, comm))
            if proc_base.startswith(comm):
                retval = pp
        return retval

    def checkClibAnalysis(self, tid):
        if '-' in tid:
            tid = tid.split('-')[0]
        sofile = 'logs/somap-%s.somap' % tid
        self.lgr.debug('winDLL checkClibAnalysis tid:%s sofile %s' % (tid, sofile))
        retval = False
        if not os.path.isfile(sofile):
            self.lgr.debug('winDLL checkClibAnalysis tid:%s no file at %s' % (tid, sofile))
            self.showSO(tid, save=True)
            retval = missingDLLAnalysis.checkMissingDLLs(None, sofile, self.lgr, root_prefix=self.root_prefix, generate=False)
            self.lgr.debug('winDLL checkClibAnalysis tid:%s created sofile, result is %r' % (tid, retval))
        else:
            retval = True
        return retval
