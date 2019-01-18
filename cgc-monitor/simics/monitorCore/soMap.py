import os
import elfText
'''
Manage maps of shared object libraries
Also track text segment.
NOTE: does not catch introduction of new code other than so libraries
'''
class SOMap():
    def __init__(self, context_manager, root_prefix, lgr):
        self.context_manager = context_manager
        self.root_prefix = root_prefix
        self.so_addr_map = {}
        self.so_file_map = {}
        self.lgr = lgr
        self.text_start = None
        self.text_end = None
        self.text_prog = None

    def isCode(self, in_pid, address):
        ''' is the given address within the text segment or those of SO libraries? '''
        pid = self.getThreadPid(in_pid)
        #print('compare 0x%x to 0x%x - 0x%x' % (address, self.text_start, self.text_end))
        if address >= self.text_start and address <= self.text_end:
            return True
        for text_seg in self.so_file_map[pid]:
            end = text_seg.start + text_seg.offset + text_seg.size
            #print('so compare 0x%x to 0x%x - 0x%x' % (address, text_seg.start, end))
            if address >= text_seg.start and address <= end:
                return True
        return False

    def addText(self, start, size, prog):
        self.text_start = start
        self.text_end = start+size
        self.text_prog = prog
       
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

    def showSO(self, in_pid):
        pid = self.getThreadPid(in_pid)
        if pid in self.so_file_map:
            print('0x%x - 0x%x   %s' % (self.text_start, self.text_end, self.text_prog))
            sort_map = {}
            for text_seg in self.so_file_map[pid]:
                sort_map[text_seg.start] = text_seg
                
            for addr in sorted(sort_map):
                text_seg = sort_map[addr]
                #end = text_seg.start + text_seg.offset + text_seg.size
                end = text_seg.start + text_seg.size
                print('0x%x - 0x%x 0x%x 0x%x  %s' % (text_seg.start, end, text_seg.offset, text_seg.size, self.so_file_map[pid][text_seg])) 
        else:
            print('no so map for %d' % in_pid)

    def getThreadPid(self, pid):
        if pid in self.so_file_map:
            return pid
        else:
            pid_list = self.context_manager.getThreadPids()
            if pid not in pid_list:
                self.lgr.debug('SOMap getThreadPid requested unknown pid %d' % pid)
                return None
            else:
                for p in pid_list:
                    if p in self.so_file_map:
                        return p
        self.lgr.debug('SOMap getThreadPid requested unknown pid %d' % pid)
        return None

    def getSOFile(self, pid, addr_in):
        retval = None
        pid = self.getThreadPid(pid)
        if pid is None:
            self.lgr.debug('getSOFile, no such pid in threads %d' % pid)
            return
        #self.lgr.debug('getSOFile for pid %d addr 0x%x' % (pid, addr_in))
        if pid in self.so_file_map:
            if addr_in >= self.text_start and addr_in <= self.text_end:
                retval = self.text_prog
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

    def getSOAddr(self, pid, in_fname):
        retval = None
        pid = self.getThreadPid(pid)
        self.lgr.debug('look for addr for pid %d in_fname %s' % (pid, in_fname))
        if in_fname == self.text_prog:
            retval = elfText(self.text_start, 0, self.text_start-self.text_end)
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
    

        
