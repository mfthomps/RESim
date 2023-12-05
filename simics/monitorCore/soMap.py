from simics import *
import os
import pickle
import elfText
import resimUtils
import json

from resimHaps import *
'''
Manage maps of shared object libraries
Also track text segment.
NOTE: does not catch introduction of new code other than so libraries
'''
class CodeSection():
    def __init__(self, addr, size):
        self.addr = addr
        self.size = size
    
class SOMap():
    def __init__(self, top, cell_name, cell, cpu, context_manager, task_utils, targetFS, run_from_snap, lgr):
        self.context_manager = context_manager
        self.task_utils = task_utils
        self.targetFS = targetFS
        self.cell_name = cell_name
        self.so_addr_map = {}
        self.so_file_map = {}
        self.lgr = lgr
        self.top = top
        self.cell = cell
        self.cpu = cpu
        self.prog_start = {}
        self.prog_end = {}
        self.text_prog = {}
        self.prog_text_start = {}
        self.prog_text_end = {}
        self.prog_text_offset = {}
        self.hap_list = []
        self.stop_hap = None
        self.fun_mgr = None
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)
        self.cheesy_tid = 0
        self.cheesy_mapped = 0
        self.fun_list_cache = []

    def loadPickle(self, name):
        somap_file = os.path.join('./', name, self.cell_name, 'soMap.pickle')
        if os.path.isfile(somap_file):
            self.lgr.debug('SOMap pickle from %s' % somap_file)
            so_pickle = pickle.load( open(somap_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            self.so_addr_map = so_pickle['so_addr_map']
            self.so_file_map = so_pickle['so_file_map']
            self.text_prog = so_pickle['text_prog']
            ''' backward compatability '''
            if 'prog_start' in so_pickle:
                self.prog_start = so_pickle['prog_start']
                self.prog_end = so_pickle['prog_end']
            else:
                self.lgr.debug('soMap loadPickle old format, find text info')
                self.prog_start = so_pickle['text_start']
                self.prog_end = so_pickle['text_end']
                for tid in self.so_file_map:
                    if tid in self.text_prog:
                        full_path = self.targetFS.getFull(self.text_prog[tid], lgr=self.lgr)
                        self.lgr.debug('soMap loadPickle tid in text_prog %s full is %s' % (tid, full_path))
                        elf_info = elfText.getText(full_path, self.lgr)
                        if elf_info.text_start is not None:
                            self.prog_text_start[tid] = elf_info.text_start        
                            self.prog_text_end[tid] = elf_info.text_start + elf_info.text_size 
                            self.prog_text_offset[tid] = elf_info.text_offset        
                            break
            ''' really old backward compatibility '''
            if self.prog_start is None:
                self.lgr.debug('soMap loadPickle text_start is none')
                self.prog_start = {}
                self.prog_end = {}
                self.text_prog = {}

            ''' pid to tid compatability'''
            add_so_addr_map = {}
            for pid in self.so_addr_map:
                if type(pid) is int:
                    add_so_addr_map[str(pid)] = self.so_addr_map[pid]
            for tid in add_so_addr_map:
                self.so_addr_map[tid] = add_so_addr_map[tid]

            add_so_file_map = {}
            for pid in self.so_file_map:
                if type(pid) is int:
                    add_so_file_map[str(pid)] = self.so_file_map[pid]

            for tid in add_so_file_map:
                self.so_file_map[tid] = add_so_file_map[tid]

            add_text_prog = {}
            for pid in self.text_prog:
                if type(pid) is int:
                    add_text_prog[str(pid)] = self.text_prog[pid]
            for tid in add_text_prog:
                self.text_prog[tid] = add_text_prog[tid]
            add_prog_start = {}
            for pid in self.prog_start:
                if type(pid) is int:
                    add_prog_start[str(pid)] = self.prog_start[pid]
            for tid in add_prog_start:
                self.prog_start[tid] = add_prog_start[tid]
            add_prog_end = {}
            for pid in self.prog_end:
                if type(pid) is int:
                    add_prog_end[str(pid)] = self.prog_end[pid]
            for tid in add_prog_end:
                self.prog_end[tid] = add_prog_end[tid]
            
            #self.lgr.debug('SOMap  loadPickle text 0x%x 0x%x' % (self.prog_start, self.prog_end))

    def pickleit(self, name):
        somap_file = os.path.join('./', name, self.cell_name, 'soMap.pickle')
        so_pickle = {}
        so_pickle['so_addr_map'] = self.so_addr_map
        so_pickle['so_file_map'] = self.so_file_map
        so_pickle['prog_start'] = self.prog_start
        so_pickle['prog_end'] = self.prog_end
        so_pickle['text_prog'] = self.text_prog
        fd = open( somap_file, "wb") 
        pickle.dump( so_pickle, fd)
        self.lgr.debug('SOMap pickleit to %s ' % (somap_file))

    def isCode(self, address, tid):
        ''' is the given address within the text segment or those of SO libraries? '''
        #self.lgr.debug('compare 0x%x to 0x%x - 0x%x' % (address, self.prog_start, self.prog_end))
        tid = self.getSOTid(tid)
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
            #self.lgr.debug('SOMap isCode, regot tid after getSOTid failed, tid:%s missing from so_file_map' % tid)
            return False
        if tid in self.prog_start and self.prog_start[tid] is not None and address >= self.prog_start[tid] and address <= self.prog_end[tid]:
            return True
        if tid not in self.so_file_map:
            tid = self.task_utils.getCurrentThreadLeaderTid()
        if tid not in self.so_file_map:
            #self.lgr.debug('SOMap isCode, tid:%s missing from so_file_map' % tid)
            return False
        for text_seg in self.so_file_map[tid]:
            start = text_seg.locate 
            end = start + text_seg.size
            if address >= start and address <= end:
                return True
        return False

    def isAboveLibc(self, address):
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

    def isMainText(self, address):
        cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid is None:
            return False
        if tid in self.prog_start and self.prog_start[tid] is not None:
            if address >= self.prog_start[tid] and address <= self.prog_end[tid]:
                return True
            else: 
                return False
        else: 
            return False

    def swapTid(self, old, new):
        ''' intended for when original process exits following a fork '''
        ''' TBD, half-assed logic for deciding if procs were all really deleted '''
        retval = True
        if old in self.prog_start:
            self.prog_start[new] = self.prog_start[old]
            self.prog_end[new] = self.prog_end[old]
            self.text_prog[new] = self.text_prog[old]
            if old in self.so_addr_map:
                self.so_addr_map[new] = self.so_addr_map[old]
                self.so_file_map[new] = self.so_file_map[old]
            else:
                self.lgr.debug('soMap swaptid tid:%s not in so_addr_map' % old)
        else:
            self.lgr.debug('soMap swaptid tid:%s not in text_start' % old)
            retval = False
        return retval

    def setElfInfo(self, tid, elf_info, prog):
        self.prog_start[tid] = elf_info.address
        self.prog_end[tid] = elf_info.address+elf_info.size
        if elf_info.text_start is not None:
            self.prog_text_start[tid] = elf_info.text_start
            self.prog_text_end[tid] = elf_info.text_start + elf_info.text_size
            self.prog_text_offset[tid] = elf_info.text_offset
        self.text_prog[tid] = prog
        if tid not in self.so_addr_map:
            self.so_addr_map[tid] = {}
            self.so_file_map[tid] = {}

    def addText(self, path, prog, tid_in):
        elf_info = elfText.getText(path, self.lgr)
        ''' First check that SO not already loaded from a snapshot '''
        tid = self.getThreadTid(tid_in, quiet=True)
        if tid is None:
            tid = tid_in
        if elf_info is not None and tid in self.prog_start:
            self.lgr.debug('soMap addText tid:%s already in map len of so_addr_map %d' % (tid, len(self.so_file_map)))
            if '/' in prog and prog != self.text_prog[tid]:
                self.lgr.debug('soMap addText tid:%s old prog %s does not match new %s' % (tid, self.text_prog[tid], prog))
                if tid_in != tid:
                    self.lgr.debug('soMap addText, tid_in not same as tid, setting elf info for tid_in %s' % tid_in)
                    self.setElfInfo(tid_in, elf_info, prog)
                else:
                    self.lgr.debug('soMap addText, tid_in is the tid TBD reassign TID if multiple threads?  for now, pave it over')
                    self.text_prog[tid] = {}
                    self.so_addr_map[tid] = {}
                    self.so_file_map[tid] = {}
                    self.setElfInfo(tid, elf_info, prog)

        elif elf_info is not None:
            self.lgr.debug('soMap addText, prog %s tid:%s' % (prog, tid))
            self.setElfInfo(tid, elf_info, prog)
        return elf_info

    def noText(self, prog, tid):
        self.lgr.debug('soMap noText, prog %s tid:%s' % (prog, tid))
        self.text_prog[tid] = prog
        self.prog_start[tid] = None
        self.prog_end[tid] = None

    def setContext(self, tid_list):
        self.lgr.debug('so_file map now %s' % (str(self.so_file_map)))
        tid = None
        for in_tid in tid_list:
            if in_tid in self.so_file_map:
                tid = in_tid
        if tid is None:
            self.lgr.error('soMap setContext found for any input tids %s' % (str(tid_list)))
            self.lgr.error('%s' % (str(self.so_file_map)))
        elif tid in self.prog_start and self.prog_start[tid] is not None:
            self.context_manager.recordText(self.prog_start[tid], self.prog_end[tid])
        else:
            self.lgr.error('soMap setContext, no context for tid:%s' % tid)
      
    def getAnalysisPath(self, fname):
        root_prefix = self.top.getCompDict(self.cell_name, 'RESIM_ROOT_PREFIX')
        return resimUtils.getAnalysisPath(None, fname, fun_list_cache = self.fun_list_cache, root_prefix=root_prefix, lgr=self.lgr)
            
    def setFunMgr(self, fun_mgr, tid_in):
        if fun_mgr is None:
            self.lgr.warning('soMap setFunMgr input fun_mgr is none')
            return
        self.fun_mgr = fun_mgr
        tid = self.getThreadTid(tid_in, quiet=True)
        if tid is None:
            self.lgr.error('soMap setFunMgr failed to getThreadTid, tid_in was %s' % tid_in)
            return
        sort_map = {}
        for text_seg in self.so_file_map[tid]:
            sort_map[text_seg.locate] = text_seg

        for locate in sorted(sort_map, reverse=True):
            text_seg = sort_map[locate]
            fpath = self.so_file_map[tid][text_seg]
            full_path = self.getAnalysisPath(fpath)
            # TBD can we finally get rid of old style paths?
            #if full_path is None:
            #    full_path = self.targetFS.getFull(fpath, lgr=self.lgr)
            if full_path is not None:
                full_path = full_path+'.funs'
                self.fun_mgr.add(full_path, locate)
            
 
    def addSO(self, tid_in, fpath, addr, count):
        tid = self.getThreadTid(tid_in, quiet=True)
        if tid is None:
            tid = tid_in
        if tid in self.so_addr_map and fpath in self.so_addr_map[tid]:
            ''' multiple mmap calls for one so file.  assume continguous and adjust
                address to lowest '''
            if self.so_addr_map[tid][fpath].address > addr:
                self.so_addr_map[tid][fpath].address = addr
                # TBD?
                #if self.ida_funs is not None:
                #    self.ida_funs.adjust(full_path, addr))
        else:
            if tid not in self.so_addr_map:
                self.so_addr_map[tid] = {}
                self.so_file_map[tid] = {}

            full_path = self.targetFS.getFull(fpath, lgr=self.lgr)
            text_seg = elfText.getText(full_path, self.lgr)
            if text_seg is None:
                self.lgr.debug('SOMap addSO, no file at %s' % full_path)
                text_seg = elfText.Text(addr, 0, 0)
       
            text_seg.locate = addr
            #text_seg.size = count

            self.so_addr_map[tid][fpath] = text_seg
            self.so_file_map[tid][text_seg] = fpath
            self.lgr.debug('soMap addSO tid:%s, full: %s size: 0x%x given count: 0x%x, locate: 0x%x addr: 0x%x off 0x%x  len so_map %d' % (tid, 
                   full_path, text_seg.size, count, addr, text_seg.address, text_seg.offset, len(self.so_addr_map[tid])))

            start = text_seg.locate
            if self.fun_mgr is not None:
                self.fun_mgr.add(full_path, start)

    def listSO(self):
        for tid in self.so_file_map:
            if tid in self.prog_start and self.prog_start[tid] is not None:
                print('tid:%s  0x%x - 0x%x   %s' % (tid, self.prog_start[tid], self.prog_end[tid], self.text_prog[tid]))
            else:
                print('tid:%s  no text found' % tid)
    
          
    def showSO(self, tid=None, filter=None):
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
            print('no so map for %s' % tid)
        print('SO Map for threads led by group leader tid: %s' % tid)
        if tid in self.so_file_map:
            if tid in self.prog_start and self.prog_start[tid] is not None:
                print('0x%x - 0x%x   %s' % (self.prog_start[tid], self.prog_end[tid], self.text_prog[tid]))
            else:
                print('tid:%s not in text sections' % tid)
                self.lgr.debug('tid:%s not in text sections' % tid)
            sort_map = {}
            for text_seg in self.so_file_map[tid]:
                sort_map[text_seg.locate] = text_seg
                
            for locate in sorted(sort_map):
                text_seg = sort_map[locate]
                if filter is None or filter in self.so_file_map[tid][text_seg]:
                    start = text_seg.locate+text_seg.offset
                    end = locate + text_seg.size
                    print('0x%x - 0x%x 0x%x 0x%x  %s' % (locate, end, text_seg.offset, text_seg.size, self.so_file_map[tid][text_seg])) 
        else:
            print('no so map for %s' % tid)
            
    def getSO(self, tid=None, quiet=False):
        retval = {}
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        retval['group_leader'] = tid
        if tid in self.so_file_map:
            if tid in self.prog_start and self.prog_start[tid] is not None:
                retval['prog_start'] = self.prog_start[tid]
                retval['prog_end'] = self.prog_end[tid]
                retval['prog'] = self.text_prog[tid]
            else:
                self.lgr.debug('tid:%s not in text sections' % tid)
            sort_map = {}
            for text_seg in self.so_file_map[tid]:
                sort_map[text_seg.locate] = text_seg
            retval['sections'] = []
            for locate in sorted(sort_map):
                section = {}
                text_seg = sort_map[locate]
                start = text_seg.locate+text_seg.offset
                end = locate + text_seg.size
                section['locate'] = locate
                section['end'] = end
                section['offset'] = text_seg.offset
                section['size'] = text_seg.size
                section['file'] = self.so_file_map[tid][text_seg]
                retval['sections'].append(section)
        else:
            self.lgr.debug('no so map for %s' % tid)
        ret_json = json.dumps(retval) 
        if not quiet:
            print(ret_json)
        return ret_json
 
    def handleExit(self, tid, killed=False):
        ''' when a thread leader exits, clone the so map structures to each child, TBD determine new thread leader? '''
        if tid not in self.so_addr_map and tid not in self.prog_start:
            self.lgr.debug('SOMap handleExit tid:%s not in so_addr map' % tid)
            return
        self.lgr.debug('SOMap handleExit tid:%s' % tid)
        if not killed:
            tid_list = self.context_manager.getThreadTids()
            if tid in tid_list:
                self.lgr.debug('SOMap handleExit tid:%s in tidlist' % tid)
                for ttid in tid_list:
                    if ttid != tid:
                        self.lgr.debug('SOMap handleExit new tid:%s added to SOmap' % ttid)
                        if tid in self.so_addr_map:
                            self.so_addr_map[ttid] = self.so_addr_map[tid]
                            self.so_file_map[ttid] = self.so_file_map[tid]
                        if tid in self.prog_start and self.prog_start[tid] is not None:
                            self.prog_start[ttid] = self.prog_start[tid]
                            self.prog_end[ttid] = self.prog_end[tid]
                            self.text_prog[ttid] = self.text_prog[tid]
                        else:
                            self.lgr.debug('SOMap handle exit, missing text_start entry tid: %s ttid:%s' % (tid, ttid))
        
            else:
                self.lgr.debug('SOMap handleExit tid:%s NOT in tidlist' % tid)
        if tid in self.so_addr_map:
            del self.so_addr_map[tid]
            del self.so_file_map[tid]
        if tid in self.prog_start:
           del self.prog_start[tid]
           del self.prog_end[tid]
           del self.text_prog[tid]


    def getThreadTid(self, tid, quiet=False):
        if tid in self.so_file_map:
            return tid
        else:
            tid_list = self.context_manager.getThreadTids()
            if tid not in tid_list:
                #self.lgr.debug('SOMap getThreadTid requested unknown tid:%s %s  -- not debugging?' % (tid, str(tid_list)))
                return None
            else:
                for p in tid_list:
                    if p in self.so_file_map:
                        return p
        if not quiet:
            self.lgr.error('SOMap getThreadTid requested unknown tid:%s' % tid)
        #else:
        #    self.lgr.debug('SOMap getThreadTid requested unknown tid:%s' % tid)
        return None
 
    def getSOTid(self, tid):
        retval = tid
        if tid not in self.so_file_map:
            if tid == self.cheesy_tid:
                return self.cheesy_mapped
            ptid = self.task_utils.getGroupLeaderTid(tid)
            #self.lgr.debug('SOMap getSOTid getCurrnetTaskLeader got %s for current tid:%s' % (ptid, tid))
            if ptid != tid:
                #self.lgr.debug('SOMap getSOTid use group leader')
                retval = ptid
            else:
                ptid = self.task_utils.getTidParent(tid)
                if ptid != tid:
                    #self.lgr.debug('SOMap getSOTid use parent %d' % ptid)
                    retval = ptid
                else:
                    #self.lgr.debug('getSOTid no so map after get parent for %d' % tid)
                    retval = None
            self.cheesy_tid = tid
            self.cheesy_mapped = retval
        return retval

    def getSOFile(self, addr_in):
        #if addr_in is not None:
        #    self.lgr.debug('getSOFile addr_in 0x%x' % addr_in)
        #else:
        #    self.lgr.debug('getSOFile addr_in is None')
        if addr_in is None:
            #self.lgr.debug('getSOFile called with None')
            return None
        retval = None
        #tid = self.getThreadTid(tid_in)
        #if tid is None:
        #    self.lgr.error('getSOFile, no such tid in threads %d' % tid_in)
        #    return
        #self.lgr.debug('getSOFile for tid:%s addr 0x%x' % (tid, addr_in))
        cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid is None:
            return None
        if tid in self.so_file_map:
            if tid not in self.prog_start or self.prog_start[tid] is None:
                self.lgr.warning('SOMap getSOFile tid:%s in so_file map but not prog_start' % tid)
                return None
            if self.prog_end[tid] is None:
                self.lgr.warning('SOMap getSOFile tid:%s in so_file map but None for prog_end' % tid)
                return None
            if addr_in >= self.prog_start[tid] and addr_in <= self.prog_end[tid]:
                retval = self.text_prog[tid]
            else:
                #for text_seg in sorted(self.so_file_map[tid]):
                for text_seg in self.so_file_map[tid]:
                    start = text_seg.locate 
                    end = start + text_seg.size
                    if start <= addr_in and addr_in <= end:
                        retval = self.so_file_map[tid][text_seg]
                        break
            
        else:
            self.lgr.debug('getSOFile no so map for %s' % tid)
        #self.lgr.debug('getSOFile returning %s' % retval)
        return retval

    def getProg(self, tid):
        retval = None
        tid = self.getSOTid(tid)
        if tid in self.text_prog:
            retval = self.text_prog[tid]
        return retval

    def getSOInfo(self, addr_in):
        retval = None, None, None
        cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid is None:
            return retval
        if tid in self.so_file_map:
            if tid in self.prog_start and self.prog_start[tid] is not None and addr_in >= self.prog_start[tid] and addr_in <= self.prog_end[tid]:
                retval = self.text_prog[tid], self.prog_start[tid], self.prog_end[tid]
            else:
                #for text_seg in sorted(self.so_file_map[tid]):
                for text_seg in self.so_file_map[tid]:
                    #start = text_seg.locate + text_seg.offset
                    start = text_seg.locate 
                    end = start + text_seg.size
                    if start <= addr_in and addr_in <= end:
                        retval = self.so_file_map[tid][text_seg], start, end
                        break
            
        else:
            self.lgr.debug('getSOInfo no so map for %s' % tid)
        return retval

    def getSOAddr(self, in_fname, tid=None):
        retval = None
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid is None:
            return None
        #self.lgr.debug('getSOAddr look for addr for tid:%s in_fname %s' % (tid, in_fname))
        ''' TBD fix this? '''
        #if tid in self.text_prog:
        #    self.lgr.debug('getSOAddr YES tid:%s is in text_prog as %s' % (tid, self.text_prog[tid]))
        #if tid in self.text_prog and (in_fname.endswith(self.text_prog[tid]) or self.text_prog[tid].endswith(in_fname)):
        if tid in self.text_prog and (os.path.basename(in_fname) == os.path.basename(self.text_prog[tid])):
            size = self.prog_end[tid] - self.prog_start[tid]
            retval = elfText.Text(self.prog_start[tid], 0, size)
            if tid in self.prog_text_start:
                text_start = self.prog_text_start[tid]
                text_size = self.prog_text_end[tid] - self.prog_text_start[tid]
                text_offset = self.prog_text_offset[tid]
                retval.setText(text_start, text_size, text_offset)
        elif tid in self.so_file_map:
            for fpath in self.so_addr_map[tid]:
                #self.lgr.debug('getSOAddr fpath %s' % fpath)
                base = os.path.basename(fpath)
                other_base = None
                full = os.path.join(self.targetFS.getRootPrefix(), fpath[1:])
                if os.path.islink(full):
                    other_base =  os.readlink(full)
                in_base = os.path.basename(in_fname)
                #self.lgr.debug('compare <%s> or <%s> to <%s>' % (base, other_base, in_base))
                if base == in_base or other_base == in_base:
                    retval = self.so_addr_map[tid][fpath]
                    #self.lgr.debug('compare found match fpath %s retval is 0x%x' % (fpath, retval.address))
                    break
            if retval is None:
                for fpath in self.so_addr_map[tid]:
                    #self.lgr.debug('getSOAddr fpath2 %s' % fpath)
                    base = os.path.basename(fpath)
                    other_base = None
                    full = os.path.join(self.targetFS.getRootPrefix(), fpath[1:])
                    if os.path.islink(full):
                        other_base =  os.readlink(full)
                    in_base = os.path.basename(in_fname)
                    #self.lgr.debug('compare %s or %s to %s' % (base, other_base, in_base))
                    if in_base.startswith(base) or (other_base is not None and in_base.startswith(other_base)):
                        retval = self.so_addr_map[tid][fpath]
                        #self.lgr.debug('compare found startswith match')
                        break

            if retval is None:
                self.lgr.debug('SOMap getSOAddr could not find so map for %s <%s>' % (tid, in_fname))
                self.lgr.debug('text_prog is <%s>' % self.text_prog[tid])
                
        else:
            self.lgr.debug('SOMap getSOAddr no so map for %s %s' % (tid, in_fname))
            if tid in self.text_prog:
                self.lgr.debug('text_prog is <%s>' % self.text_prog[tid])
        return retval
    

    def stopHap(self, cpu, one, exception, error_string):
        if self.stop_hap is not None:
            eip = self.top.getEIP(cpu)
            self.lgr.debug('soMap stopHap ip: 0x%x' % eip)
            self.top.skipAndMail()
            RES_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None

    def stopAlone(self, cpu):
        if len(self.hap_list) > 0:
            self.stop_hap = RES_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, cpu)
            self.lgr.debug('soMap stopAlone')
            for hap in self.hap_list:
                self.context_manager.genDeleteHap(hap)
            del self.hap_list[:]

            SIM_break_simulation('soMap')

    def knownHap(self, tid, third, forth, memory):
        if len(self.hap_list) > 0:
            cpu, comm, cur_tid = self.task_utils.curThread() 
            if tid == cur_tid: 
                value = memory.logical_address
                fname, start, end = self.getSOInfo(value)
                if fname is not None and start is not None:
                    self.lgr.debug('soMap knownHap tid:%s memory 0x%x %s start:0x%x end:0x%x' % (tid, value, fname, start, end))
                else:
                    self.lgr.debug('soMap knownHap tid:%s memory 0x%x NO mapping file %s' % (tid, value, fname))

                SIM_run_alone(self.stopAlone, cpu)                
            #else:
            #    self.lgr.debug('soMap knownHap wrong tid, wanted %d got %d' % (tid, cur_tid))
        
    def runToKnown(self, skip=None):        
       cpu, comm, cur_tid = self.task_utils.curThread() 
       map_tid = self.getSOTid(cur_tid)
       if map_tid in self.prog_start: 
           start =  self.prog_start[map_tid] 
           length = self.prog_end[map_tid] - self.prog_start[map_tid] 
           proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, start, length, 0)
           self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.knownHap, cur_tid, proc_break, 'runToKnown'))
           #self.lgr.debug('soMap runToKnow text 0x%x 0x%x' % (start, length))
       else:
           self.lgr.debug('soMap runToKnown no text for %s' % map_tid)
       if map_tid in self.so_file_map:
            for text_seg in self.so_file_map[map_tid]:
                start = text_seg.locate+text_seg.offset
                length = text_seg.size
                end = start+length
                if skip is None or not (skip >= start and skip <= end):
                    proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, start, length, 0)
                    self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.knownHap, cur_tid, proc_break, 'runToKnown'))
                else:
                    self.lgr.debug('soMap runToKnow, skip %s' % (self.so_file_map[map_tid][text_seg]))
                #self.lgr.debug('soMap runToKnow lib %s 0x%x 0x%x' % (self.so_file_map[map_tid][text_seg], start, length))
       else:
           self.lgr.debug('soMap runToKnown no so_file_map for %s' % map_tid)
       if len(self.hap_list) > 0:  
           return True
       else:
           return False

    def wordSize(self, tid):
       # TBD why take tid as param?
       return self.task_utils.getMemUtils().wordSize(self.cpu)

    def getMachineSize(self, tid):
       ws = self.task_utils.getMemUtils().wordSize(self.cpu)
       if ws == 4:
           return 32
       else:
           return 64

    def getFullPath(self, comm):
        retval = None
        for pid in self.text_prog:
            base = os.path.basename(self.text_prog[pid])
            if base.startswith(comm):
                retval = self.text_prog[pid]
        return retval
