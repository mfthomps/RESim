import os
import pickle
import elfText
'''
Manage maps of shared object libraries
Also track text segment.
NOTE: does not catch introduction of new code other than so libraries
'''
class SOMap():
    def __init__(self, context_manager, task_utils, root_prefix, run_from_snap, lgr):
        self.context_manager = context_manager
        self.task_utils = task_utils
        self.root_prefix = root_prefix
        self.so_addr_map = {}
        self.so_file_map = {}
        self.lgr = lgr
        self.text_start = {}
        self.text_end = {}
        self.text_prog = {}
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)

    def loadPickle(self, name):
        somap_file = os.path.join('./', name, 'soMap.pickle')
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
        somap_file = os.path.join('./', name, 'soMap.pickle')
        so_pickle = {}
        so_pickle['so_addr_map'] = self.so_addr_map
        so_pickle['so_file_map'] = self.so_file_map
        so_pickle['text_start'] = self.text_start
        so_pickle['text_end'] = self.text_end
        so_pickle['text_prog'] = self.text_prog
        pickle.dump( so_pickle, open( somap_file, "wb" ) )
        self.lgr.debug('SOMap pickleit to %s ' % (somap_file))

    def isCode(self, address):
        ''' is the given address within the text segment or those of SO libraries? '''
        #self.lgr.debug('compare 0x%x to 0x%x - 0x%x' % (address, self.text_start, self.text_end))
        cpu, comm, pid = self.task_utils.curProc() 
        if pid in self.text_start and address >= self.text_start[pid] and address <= self.text_end[pid]:
            return True
        if pid not in self.so_file_map:
            pid = self.task_utils.getCurrentThreadLeaderPid()
        if pid not in self.so_file_map:
            self.lgr.debug('SOMap isCode, pid:%d missing from so_file_map' % pid)
            return False
        for text_seg in self.so_file_map[pid]:
            end = text_seg.start + text_seg.offset + text_seg.size
            #print('so compare 0x%x to 0x%x - 0x%x' % (address, text_seg.start, end))
            if address >= text_seg.start and address <= end:
                return True
        return False

    def isMainText(self, address):
        cpu, comm, pid = self.task_utils.curProc() 
        if pid in self.text_start:
            if address >= self.text_start[pid] and address <= self.text_end[pid]:
                return True
            else: 
                return False
        else: 
            return False

    def addText(self, start, size, prog, pid):
        self.text_start[pid] = start
        self.text_end[pid] = start+size
        self.text_prog[pid] = prog
       
    def addSO(self, pid, fpath, addr, count):
        if pid not in self.so_addr_map:
            self.so_addr_map[pid] = {}
            self.so_file_map[pid] = {}

        full_path = os.path.join(self.root_prefix, fpath[1:])
        self.lgr.debug('addSO, prefix is %s fpath is %s  full: %s' % (self.root_prefix, fpath, full_path))
        text_seg = elfText.getText(full_path)
        if text_seg is None:
            self.lgr.debug('SOMap addSO, no file at %s' % full_path)
            return
        text_seg.start = addr
        text_seg.size = count

        self.so_addr_map[pid][fpath] = text_seg
        self.so_file_map[pid][text_seg] = fpath

    def showSO(self):
        cpu, comm, pid = self.task_utils.curProc() 
        if pid not in self.so_file_map:
            pid = self.task_utils.getCurrentThreadLeaderPid()
        if pid in self.so_file_map:
            print('0x%x - 0x%x   %s' % (self.text_start[pid], self.text_end[pid], self.text_prog[pid]))
            sort_map = {}
            for text_seg in self.so_file_map[pid]:
                sort_map[text_seg.start] = text_seg
                
            for addr in sorted(sort_map):
                text_seg = sort_map[addr]
                #end = text_seg.start + text_seg.offset + text_seg.size
                end = text_seg.start + text_seg.size
                print('0x%x - 0x%x 0x%x 0x%x  %s' % (text_seg.start, end, text_seg.offset, text_seg.size, self.so_file_map[pid][text_seg])) 
        else:
            print('no so map for %d' % pid)

    def getThreadPid(self, pid):
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
        self.lgr.error('SOMap getThreadPid requested unknown pid %d' % pid)
        return None

    def getSOFile(self, addr_in):
        retval = None
        #pid = self.getThreadPid(pid_in)
        #if pid is None:
        #    self.lgr.error('getSOFile, no such pid in threads %d' % pid_in)
        #    return
        #self.lgr.debug('getSOFile for pid %d addr 0x%x' % (pid, addr_in))
        cpu, comm, pid = self.task_utils.curProc() 
        if pid not in self.so_file_map:
            pid = self.task_utils.getCurrentThreadLeaderPid()
        if pid in self.so_file_map:
            if addr_in >= self.text_start[pid] and addr_in <= self.text_end[pid]:
                retval = self.text_prog[pid]
            else:
                for text_seg in sorted(self.so_file_map[pid]):
                    end = text_seg.start + text_seg.size
                    #self.lgr.debug('compare 0x%x to range 0x%x - 0x%x' % (addr_in, text_seg.start, end))
                    if text_seg.start <= addr_in and addr_in <= end:
                        retval = self.so_file_map[pid][text_seg]
                        break
            
        else:
            self.lgr.debug('getSOFile no so map for %d' % pid)
        return retval

    def getSOInfo(self, addr_in):
        retval = None, None, None
        cpu, comm, pid = self.task_utils.curProc() 
        if pid not in self.so_file_map:
            pid = self.task_utils.getCurrentThreadLeaderPid()
        if pid in self.so_file_map:
            if addr_in >= self.text_start[pid] and addr_in <= self.text_end[pid]:
                retval = self.text_prog[pid], self.text_start[pid], self.text_end[pid]
            else:
                for text_seg in sorted(self.so_file_map[pid]):
                    end = text_seg.start + text_seg.size
                    #self.lgr.debug('compare 0x%x to range 0x%x - 0x%x' % (addr_in, text_seg.start, end))
                    if text_seg.start <= addr_in and addr_in <= end:
                        retval = self.so_file_map[pid][text_seg], text_seg.start, end
                        break
            
        else:
            self.lgr.debug('getSOFile no so map for %d' % pid)
        return retval

    def getSOAddr(self, in_fname):
        retval = None
        cpu, comm, pid = self.task_utils.curProc() 
        if pid not in self.so_file_map:
            pid = self.task_utils.getCurrentThreadLeaderPid()
        self.lgr.debug('look for addr for pid %d in_fname %s' % (pid, in_fname))
        if in_fname == self.text_prog:
            size = self.text_end - self.text_start
            retval = elfText.Text(self.text_start, 0, size)
        elif pid in self.so_file_map:
            for fpath in self.so_addr_map[pid]:
                base = os.path.basename(fpath)
                in_base = os.path.basename(in_fname)
                #self.lgr.debug('compare %s to %s' % (base, in_base))
                if base == in_base:
                    if retval is not None:
                        self.lgr.debug('SOMap getSOAddr multiple so files with fname %s' % in_fname)
                        break
                    else:
                        retval = self.so_addr_map[pid][fpath]
                        break
        else:
            self.lgr.debug('SOMap getSOAddr no so map for %d' % pid)
        return retval
    

        
