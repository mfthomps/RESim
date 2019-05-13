import os
import pickle
import elfText
'''
Manage maps of shared object libraries
Also track text segment.
NOTE: does not catch introduction of new code other than so libraries
'''
class SOMap():
    def __init__(self, cell_name, context_manager, task_utils, targetFS, run_from_snap, lgr):
        self.context_manager = context_manager
        self.task_utils = task_utils
        self.targetFS = targetFS
        self.cell_name = cell_name
        self.so_addr_map = {}
        self.so_file_map = {}
        self.lgr = lgr
        self.text_start = {}
        self.text_end = {}
        self.text_prog = {}
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)

    def loadPickle(self, name):
        somap_file = os.path.join('./', name, self.cell_name, 'soMap.pickle')
        if os.path.isfile(somap_file):
            self.lgr.debug('SOMap pickle from %s' % somap_file)
            so_pickle = pickle.load( open(somap_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            self.so_addr_map = so_pickle['so_addr_map']
            self.so_file_map = so_pickle['so_file_map']
            self.text_start = so_pickle['text_start']
            self.text_end = so_pickle['text_end']
            self.text_prog = so_pickle['text_prog']
            ''' backward compatibility '''
            if self.text_start is None:
                self.text_start = {}
                self.text_end = {}
                self.text_prog = {}
            
            #self.lgr.debug('SOMap  loadPickle text 0x%x 0x%x' % (self.text_start, self.text_end))

    def pickleit(self, name):
        somap_file = os.path.join('./', name, self.cell_name, 'soMap.pickle')
        so_pickle = {}
        so_pickle['so_addr_map'] = self.so_addr_map
        so_pickle['so_file_map'] = self.so_file_map
        so_pickle['text_start'] = self.text_start
        so_pickle['text_end'] = self.text_end
        so_pickle['text_prog'] = self.text_prog
        fd = open( somap_file, "wb") 
        pickle.dump( so_pickle, fd)
        self.lgr.debug('SOMap pickleit to %s ' % (somap_file))

    def isCode(self, address):
        ''' is the given address within the text segment or those of SO libraries? '''
        #self.lgr.debug('compare 0x%x to 0x%x - 0x%x' % (address, self.text_start, self.text_end))
        cpu, comm, pid = self.task_utils.curProc() 
        pid = self.getSOPid(pid)
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
            self.lgr.debug('SOMap isCode, pid:%d missing from so_file_map' % pid)
            return False
        if pid in self.text_start and address >= self.text_start[pid] and address <= self.text_end[pid]:
            return True
        if pid not in self.so_file_map:
            pid = self.task_utils.getCurrentThreadLeaderPid()
        if pid not in self.so_file_map:
            self.lgr.debug('SOMap isCode, pid:%d missing from so_file_map' % pid)
            return False
        for text_seg in self.so_file_map[pid]:
            start = text_seg.locate + text_seg.offset
            end = start + text_seg.size
            if address >= start and address <= end:
                return True
        return False

    def isMainText(self, address):
        cpu, comm, pid = self.task_utils.curProc() 
        pid = self.getSOPid(pid)
        if pid is None:
            return False
        if pid in self.text_start:
            if address >= self.text_start[pid] and address <= self.text_end[pid]:
                return True
            else: 
                return False
        else: 
            return False

    def addText(self, start, size, prog, pid):
        self.lgr.debug('soMap addText, prog %s pid:%d' % (prog, pid))
        self.text_start[pid] = start
        self.text_end[pid] = start+size
        self.text_prog[pid] = prog
       
    def addSO(self, pid_in, fpath, addr, count):
        pid = self.getThreadPid(pid_in, quiet=True)
        if pid is None:
            pid = pid_in
        if pid not in self.so_addr_map:
            self.so_addr_map[pid] = {}
            self.so_file_map[pid] = {}

        full_path = self.targetFS.getFull(fpath, lgr=self.lgr)
        text_seg = elfText.getText(full_path)
        if text_seg is None:
            self.lgr.debug('SOMap addSO, no file at %s' % full_path)
            return
       
        text_seg.locate = addr
        #text_seg.size = count

        self.so_addr_map[pid][fpath] = text_seg
        self.so_file_map[pid][text_seg] = fpath
        self.lgr.debug('soMap addSO pid:%d, full: %s size: 0x%x given count: 0x%x, locate: 0x%x addr: 0x%x off 0x%x  len so_map %d' % (pid, 
               full_path, text_seg.size, count, addr, text_seg.address, text_seg.offset, len(self.so_addr_map[pid])))

    def showSO(self):
        cpu, comm, pid = self.task_utils.curProc() 
        pid = self.getSOPid(pid)
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
            print('no so map for %d' % pid)
        print('SO Map for pid: %d' % pid)
        if pid in self.so_file_map:
            if pid in self.text_start:
                print('0x%x - 0x%x   %s' % (self.text_start[pid], self.text_end[pid], self.text_prog[pid]))
            else:
                print('pid %d not in text sections' % pid)
                self.lgr.debug('pid %d not in text sections' % pid)
            sort_map = {}
            for text_seg in self.so_file_map[pid]:
                sort_map[text_seg.locate] = text_seg
                
            for locate in sorted(sort_map):
                text_seg = sort_map[locate]
                start = text_seg.locate+text_seg.offset
                end = locate + text_seg.size
                print('0x%x - 0x%x 0x%x 0x%x  %s' % (locate, end, text_seg.offset, text_seg.size, self.so_file_map[pid][text_seg])) 
        else:
            print('no so map for %d' % pid)
 
    def handleExit(self, pid):
        ''' when a thread leader exits, clone the so map structures to each child, TBD determine new thread leader? '''
        if pid not in self.so_addr_map:
            self.lgr.debug('SOMap handleExit pid %d not in so_addr map' % pid)
            return
        self.lgr.debug('SOMap handleExit pid %d' % pid)
        pid_list = self.context_manager.getThreadPids()
        if pid in pid_list:
            self.lgr.debug('SOMap handleExit pid %d in pidlist' % pid)
            for tpid in pid_list:
                if tpid != pid:
                    self.lgr.debug('SOMap handleExit new pid %d added to SOmap' % tpid)
                    self.so_addr_map[tpid] = self.so_addr_map[pid]
                    self.so_file_map[tpid] = self.so_file_map[pid]
                    #if tpid in self.text_start and pid in self.text_start:
                    if pid in self.text_start:
                        self.text_start[tpid] = self.text_start[pid]
                        self.text_end[tpid] = self.text_end[pid]
                        self.text_prog[tpid] = self.text_prog[pid]
                    else:
                        self.lgr.debug('SOMap handle exit, missing text_start entry pid: %d tpid %d' % (pid, tpid))
        else:
            self.lgr.debug('SOMap handleExit pid %d NOT in pidlist' % pid)
        del self.so_addr_map[pid]
        del self.so_file_map[pid]
        if pid in self.text_start:
           del self.text_start[pid]
           del self.text_end[pid]
           del self.text_prog[pid]


    def getThreadPid(self, pid, quiet=False):
        if pid in self.so_file_map:
            return pid
        else:
            pid_list = self.context_manager.getThreadPids()
            if pid not in pid_list:
                self.lgr.error('SOMap getThreadPid requested unknown pid %d %s' % (pid, str(pid_list)))
                return None
            else:
                for p in pid_list:
                    if p in self.so_file_map:
                        return p
        if not quiet:
            self.lgr.error('SOMap getThreadPid requested unknown pid %d' % pid)
        else:
            self.lgr.debug('SOMap getThreadPid requested unknown pid %d' % pid)
        return None
 
    def getSOPid(self, pid):
        retval = pid
        if pid not in self.so_file_map:
            ppid = self.task_utils.getCurrentThreadLeaderPid()
            #self.lgr.debug('SOMap getSOPid getCurrnetTaskLeader got %s for current pid %d' % (ppid, pid))
            if ppid != pid:
                #self.lgr.debug('SOMap getSOPid use group leader')
                retval = ppid
            else:
                ppid = self.task_utils.getCurrentThreadParent()
                if ppid != pid:
                    #self.lgr.debug('SOMap getSOPid use parent %d' % ppid)
                    retval = ppid
                else:
                    #self.lgr.debug('getSOPid no so map after get parent for %d' % pid)
                    retval = None
        return retval

    def getSOFile(self, addr_in):
        retval = None
        #pid = self.getThreadPid(pid_in)
        #if pid is None:
        #    self.lgr.error('getSOFile, no such pid in threads %d' % pid_in)
        #    return
        #self.lgr.debug('getSOFile for pid %d addr 0x%x' % (pid, addr_in))
        cpu, comm, pid = self.task_utils.curProc() 
        pid = self.getSOPid(pid)
        if pid is None:
            return None
        if pid in self.so_file_map:
            if pid not in self.text_start:
                self.lgr.warning('SOMap getSOFile pid %d in so_file map but not text_start' % pid)
                return None
            if addr_in >= self.text_start[pid] and addr_in <= self.text_end[pid]:
                retval = self.text_prog[pid]
            else:
                for text_seg in sorted(self.so_file_map[pid]):
                    start = text_seg.locate + text_seg.offset
                    end = start + text_seg.size
                    if start <= addr_in and addr_in <= end:
                        retval = self.so_file_map[pid][text_seg]
                        break
            
        else:
            self.lgr.debug('getSOFile no so map for %d' % pid)
        return retval

    def getSOInfo(self, addr_in):
        retval = None, None, None
        cpu, comm, pid = self.task_utils.curProc() 
        pid = self.getSOPid(pid)
        if pid is None:
            return None
        if pid in self.so_file_map:
            if addr_in >= self.text_start[pid] and addr_in <= self.text_end[pid]:
                retval = self.text_prog[pid], self.text_start[pid], self.text_end[pid]
            else:
                for text_seg in sorted(self.so_file_map[pid]):
                    start = text_seg.locate + text_seg.offset
                    end = start + text_seg.size
                    if start <= addr_in and addr_in <= end:
                        retval = self.so_file_map[pid][text_seg], start, end
                        break
            
        else:
            self.lgr.debug('getSOInfo no so map for %d' % pid)
        return retval

    def getSOAddr(self, in_fname):
        retval = None
        cpu, comm, pid = self.task_utils.curProc() 
        pid = self.getSOPid(pid)
        if pid is None:
            return None
        self.lgr.debug('getSOAddr look for addr for pid %d in_fname %s' % (pid, in_fname))
        if in_fname == self.text_prog[pid]:
            size = self.text_end[pid] - self.text_start[pid]
            retval = elfText.Text(self.text_start[pid], 0, size)
        elif pid in self.so_file_map:
            for fpath in self.so_addr_map[pid]:
                base = os.path.basename(fpath)
                in_base = os.path.basename(in_fname)
                self.lgr.debug('compare %s to %s' % (base, in_base))
                if base == in_base:
                    if retval is not None:
                        self.lgr.debug('SOMap getSOAddr multiple so files with fname %s' % in_fname)
                        break
                    else:
                        retval = self.so_addr_map[pid][fpath]
                        break
            if retval is None:
                self.lgr.debug('SOMap getSOAddr could not find so map for %d <%s>' % (pid, in_fname))
                self.lgr.debug('text_prog is <%s>' % self.text_prog[pid])
                
        else:
            self.lgr.debug('SOMap getSOAddr no so map for %d %s' % (pid, in_fname))
            self.lgr.debug('text_prog is <%s>' % self.text_prog[pid])
        return retval
    

        
