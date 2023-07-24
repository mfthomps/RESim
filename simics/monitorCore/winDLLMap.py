import os
import glob
import pickle
import json
import ntpath
import soMap
import winProg
import resimUtils
class Text():
    ''' compat with old linux elfText code without importing... '''
    def __init__(self, address, size, image_base):
        self.address = address
        self.size = size 
        self.image_base = image_base 

class DLLInfo():
    def __init__(self, pid, fname, fd):
        self.fname = fname
        self.fd = fd
        self.pid = pid
        self.section_handle = None
        ''' load address '''
        self.addr = None
        ''' offset of text relative to load address '''
        self.text_offset = 0
        ''' size of text '''
        self.size = None
        self.machine = None
        self.image_base = None

    @classmethod
    def copy(cls, info):
        new = cls(info.pid, info.fname, info.fd)
        new.addr = info.addr
        new.size = info.size
        new.machine = info.machine
        new.image_base = info.image_base
        return new

    def addSectionHandle(self, section_handle):
        self.section_handle = section_handle
    def addLoadAddress(self, addr, size):
        self.addr = addr 
        self.size = size 
    def addMachine(self, machine):
        self.machine = machine
    def addImageBase(self, image_base):
        self.image_base = image_base

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
        self.so_watch_callback = {}
        self.text = {}
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)
        self.pending_procs = []
        self.fun_list_cache = []

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
                        self.min_addr[section.pid] = section.addr + section.text_offset
                    if section.size is None:
                        self.lgr.error('winDLL loadPickle no size for %s, addr 0x%x pid:%d' % (section.fname, section.addr, section.pid))
                        continue
                    ma = section.addr + section.text_offset + section.size
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
                    self.lgr.debug('winDLL TBD is this a windows path? %s if so fix this' % prog)
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

    def addText(self, fname, pid, addr, size, machine, image_base, text_offset):
        dll_info = DLLInfo(pid, fname, None)
        dll_info.addr = addr
        dll_info.text_offset = text_offset
        dll_info.size = size
        dll_info.machine = machine
        dll_info.image_base = image_base
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
                            #self.lgr.debug('winDLL mapSection does %s start with %s' % (proc_base, comm))
                            if proc_base.startswith(comm):
                                eproc = self.task_utils.getCurTaskRec()
                                full_path = self.top.getFullPath(fname=pp)
                                win_prog_info = winProg.getWinProgInfo(self.cpu, self.mem_utils, eproc, full_path, self.lgr)
                                self.addText(pp, pid, win_prog_info.load_addr, win_prog_info.text_size, win_prog_info.machine, 
                                            win_prog_info.image_base, win_prog_info.text_offset)
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
        basename = ntpath.basename(section.fname)
        if basename in self.so_watch_callback:
            self.lgr.debug('winDLL checkSOWatch do callback for %s' % basename)
            self.so_watch_callback[basename](section)

    def showSO(self, pid, filter=None):
        if pid is None: 
            cpu, comm, pid = self.task_utils.curProc() 
        
        sort_map = {}
        for section in self.section_list:
            if section.pid == pid:
                sort_map[section.addr] = section

        self.lgr.debug('WinDLLMap showSO %d sections' % (len(sort_map)))
        for section_addr in sorted(sort_map):
            section = sort_map[section_addr]
            if filter is None or filter in section.fname:
                end = section.addr+section.size
                print('pid:%d 0x%x - 0x%x %s' % (section.pid, section.addr, end, section.fname)) 
                self.lgr.debug('winDLLMap showSO pid:%d 0x%x - 0x%x %s' % (section.pid, section.addr, end, section.fname)) 


    def isMainText(self, address):
        retval = False
        cpu, comm, pid = self.task_utils.curProc() 
        if pid in self.text:
            end = self.text[pid].addr + self.text[pid].size
            if address >= self.text[pid].addr and address <= end:
                retval = True
        return retval

    def getSOFile(self, addr_in):
        retval = None
        cpu, comm, pid = self.task_utils.curProc() 
        if addr_in is not None:
            for section in self.section_list:
                if section.pid == pid:
                    if section.size is not None:
                        end = section.addr+section.size
                        if addr_in >= section.addr and addr_in <= end:
                            retval = ntpath.basename(section.fname)
                            break 
        return retval

    def isCode(self, addr_in, pid):
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
            self.text_start = address
            self.locate = locate
            self.offset = offset
            self.size = size
            self.text_size = size

    def getSOAddr(self, in_fname, pid=None):
        self.lgr.debug('winDLLMap getSOAddr %s' % in_fname)
        retval = None
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
        pid = self.getSOPid(pid)
        if pid is None:
            self.lgr.debug('winDLLMap getSOAddr no pid for %s' % str(pid))
            return None
        if in_fname == 'unknown':
            self.lgr.debug('winDLLMap getSOAddr in_fname is "unknown" for pid for %s' % str(pid))
            return
        for section in self.section_list:
            if section.pid == pid:
                #self.lgr.debug('winDLLMap compare %s to %s' % (os.path.basename(in_fname).lower(), ntpath.basename(section.fname).lower()))
                if os.path.basename(in_fname).lower() == ntpath.basename(section.fname).lower():
                    if section.image_base is None:
                        self.lgr.debug('winDLLMap no image base defined for %s, get it' % section.fname)
                        full_path = self.top.getFullPath(fname=section.fname)
                        self.lgr.debug('winDLL getSOAddr got %s from getFullPath' % full_path)
                        size, machine, image_base, text_offset = winProg.getSizeAndMachine(full_path, self.lgr)
                        section.image_base = image_base
                    if section.image_base is not None:
                        delta = (section.addr - section.image_base) 
                        offset = delta + section.text_offset
                        retval = self.HackCompat(section.addr, section.image_base, offset, section.size)
                    else:
                        self.lgr.error('winDLLMap no image base defined for %s' % section.fname)
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
        self.so_watch_callback[fname] = callback

    def getText(self, pid):
        ''' poor name.  actually used to get the load address to compute an offset from the header's image base'''
        retval = None
        self.lgr.debug('winDLL getText pid:%s' % pid) 
        if pid in self.text:
            retval = Text(self.text[pid].addr, self.text[pid].size, self.text[pid].image_base)
        else:
            cpu, comm, cur_pid = self.task_utils.curProc() 
            if pid == cur_pid:
                prog_name = self.top.getProgName(pid)
                full_path = self.top.getFullPath(fname=prog_name)
                self.lgr.debug('winDLL getText, no text yet for %s, try reading it from winProg' % prog_name)
                eproc = self.task_utils.getCurTaskRec()
                win_prog_info = winProg.getWinProgInfo(self.cpu, self.mem_utils, eproc, full_path, self.lgr)
                self.top.setFullPath(full_path)
                self.addText(prog_name, pid, win_prog_info.load_addr, win_prog_info.text_size, win_prog_info.machine, win_prog_info.image_base, win_prog.text_offset)
                retval = Text(win_prog_info.load_addr, win_prog_info.text_size, win_prog_info.image_base)
        return retval
            
    def getAnalysisPath(self, fname):
        retval = None
        #self.lgr.debug('winDLL getAnalyisPath find %s' % fname)
        analysis_path = os.getenv('IDA_ANALYIS')
        if analysis_path is None:
            analysis_path = '/mnt/resim_archive/analysis'
            if len(self.fun_list_cache) == 0:
                self.lgr.warning('winDLL getAnalysis path IDA_ANALYSIS not defined')
         
        root_prefix = self.top.getCompDict(self.cell_name, 'RESIM_ROOT_PREFIX')
        root_dir = os.path.basename(root_prefix)
        top_dir = os.path.join(analysis_path, root_dir)
        if len(self.fun_list_cache) == 0:
            self.fun_list_cache = resimUtils.findListFrom('*.funs', top_dir)
            #self.lgr.debug('winDLLMap getAnalysisPath loaded %d fun files into cache' % (len(self.fun_list_cache)))

        fname = fname.replace('\\', '/')
        if fname.startswith('/??/C:/'):
                fname = fname[7:]

        base = ntpath.basename(fname)+'.funs'
        if base.upper() in map(str.upper, self.fun_list_cache):
            with_funs = fname+'.funs'
            #self.lgr.debug('windDLLMap getAnalsysisPath look for path for %s top_dir %s' % (with_funs, top_dir))
            retval = resimUtils.getfileInsensitive(with_funs, top_dir, self.lgr)
            if retval is not None:
                #self.lgr.debug('windDLLMap getAnalsysisPath got %s from %s' % (retval, with_funs))
                retval = retval[:-5]
        else:
            #self.lgr.debug('winDLL getAnalysisPath %s not in cache' % base)
            pass

        return retval
            

    def setFunMgr(self, fun_mgr, pid):
        if fun_mgr is None:
            self.lgr.warning('IDA funs is none, no SOMap')
            return
        self.fun_mgr = fun_mgr

        sort_map = {}
        for section in self.section_list:
            if section.pid == pid:
                sort_map[section.addr] = section

        for locate in sorted(sort_map, reverse=True):
            section = sort_map[locate]
            if section.fname != 'unknown':
                #fpath = section.fname
                #full_path = self.top.getFullPath(fpath)
                fun_path = self.getAnalysisPath(section.fname)
                if fun_path is not None:
                    self.lgr.debug('winDLL setIdaFuns set addr 0x%x for %s' % (locate, fun_path))
                    if section.image_base is None:
                        full_path = self.top.getFullPath(fname=section.fname)
                        self.lgr.debug('winDLL setIdaFuns got %s from getFullPath' % full_path)
                        size, machine, image_base, text_offset = winProg.getSizeAndMachine(full_path, self.lgr)
                        section.image_base = image_base
                    else:
                        image_base = section.image_base
                        text_offset = section.text_offset
                    if text_offset is not None:
                        delta = (locate - image_base) 
                        offset = delta + text_offset
                        self.lgr.debug('winDLL setIdaFuns xxx offset 0x%x locate: 0x%x text_offset 0x%x image_base 0x%x delta 0x%x ' % (offset, locate, text_offset, image_base, delta))
                    else:
                        self.lgr.debug('winDLL setIdaFuns offset 0x%x locate: 0x%x text_offset is None ' % (offset, locate))
                        offset = 0
                        text_offset = 0
                    self.fun_mgr.add(fun_path, locate, offset=offset, text_offset=text_offset)

    def getSO(self, pid=None, quiet=False):
        self.lgr.debug('winDLL getSO pid %s ' % pid)
        retval = {}
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
        pid = self.getSOPid(pid)
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
        retval['group_leader'] = pid
        if pid in self.text and self.text[pid].addr is not None:
                retval['prog_start'] = self.text[pid].addr
                retval['prog_end'] = self.text[pid].addr + self.text[pid].size - 1
                retval['prog'] = self.top.getProgName(pid)
        else:
            self.lgr.debug('winDLL getSO pid %d not in text sections' % pid)
        sort_map = {}
        for section in self.section_list:
            if section.pid == pid:
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
                self.lgr.warning('winDLL getMachineSize pid:%d missing machine field' % pid) 
        else: 
            self.lgr.debug('winDLL getMachineSize pid:%d has no text' % pid) 
            pass
       
        #if retval is not None: 
        #    self.lgr.debug('winDLL getMachineSize of %d for pid %d' % (retval, pid))
        
        return retval

    def addPendingProc(self, prog_path):
        self.pending_procs.append(prog_path)
        self.lgr.debug('winDLL addPendingProc %s' % prog_path)

    def handleExit(self, pid, killed=False):
        ''' when a thread leader exits, clone the so map structures to each child, TBD determine new thread leader? '''
        if pid not in self.so_addr_map and pid not in self.prog_start:
            self.lgr.debug('SOMap handleExit pid %d not in so_addr map' % pid)
            return
        ''' TBD for windows'''
        self.lgr.debug('DLLmap handleExit pid %d  TBD for windows' % pid)
        return
        if not killed:
            pid_list = self.context_manager.getThreadPids()
            if pid in pid_list:
                self.lgr.debug('SOMap handleExit pid %d in pidlist' % pid)
                for tpid in pid_list:
                    if tpid != pid:
                        self.lgr.debug('SOMap handleExit new pid %d added to SOmap' % tpid)
                        if pid in self.so_addr_map:
                            self.so_addr_map[tpid] = self.so_addr_map[pid]
                            self.so_file_map[tpid] = self.so_file_map[pid]
                        if pid in self.prog_start and self.prog_start[pid] is not None:
                            self.prog_start[tpid] = self.prog_start[pid]
                            self.prog_end[tpid] = self.prog_end[pid]
                            self.text_prog[tpid] = self.text_prog[pid]
                        else:
                            self.lgr.debug('SOMap handle exit, missing text_start entry pid: %d tpid %d' % (pid, tpid))
        
            else:
                self.lgr.debug('SOMap handleExit pid %d NOT in pidlist' % pid)
        if pid in self.so_addr_map:
            del self.so_addr_map[pid]
            del self.so_file_map[pid]
        if pid in self.prog_start:
           del self.prog_start[pid]
           del self.prog_end[pid]
           del self.text_prog[pid]

    def swapPid(self, old, new):
       ''' TBD ??? '''
       return False
