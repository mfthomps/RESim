from simics import *
import os
import pickle
import elfText
'''
Manage maps of shared object libraries
Also track text segment.
NOTE: does not catch introduction of new code other than so libraries
'''
class SOMap():
    def __init__(self, top, cell_name, cell, context_manager, task_utils, targetFS, run_from_snap, lgr):
        self.context_manager = context_manager
        self.task_utils = task_utils
        self.targetFS = targetFS
        self.cell_name = cell_name
        self.so_addr_map = {}
        self.so_file_map = {}
        self.lgr = lgr
        self.top = top
        self.cell = cell
        self.text_start = {}
        self.text_end = {}
        self.text_prog = {}
        self.hap_list = []
        self.stop_hap = None
        self.ida_funs = None
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)
        self.cheesy_pid = 0
        self.cheesy_mapped = 0

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
                self.lgr.debug('soMap loadPickle text_start is none')
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

    def isCode(self, address, pid):
        ''' is the given address within the text segment or those of SO libraries? '''
        #self.lgr.debug('compare 0x%x to 0x%x - 0x%x' % (address, self.text_start, self.text_end))
        pid = self.getSOPid(pid)
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
            self.lgr.debug('SOMap isCode, regot pid after getSOPid failed, pid:%d missing from so_file_map' % pid)
            return False
        if pid in self.text_start and address >= self.text_start[pid] and address <= self.text_end[pid]:
            return True
        if pid not in self.so_file_map:
            pid = self.task_utils.getCurrentThreadLeaderPid()
        if pid not in self.so_file_map:
            self.lgr.debug('SOMap isCode, pid:%d missing from so_file_map' % pid)
            return False
        for text_seg in self.so_file_map[pid]:
            start = text_seg.locate 
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

    def swapPid(self, old, new):
        ''' intended for when original process exits following a fork '''
        ''' TBD, half-assed logic for deciding if procs were all really deleted '''
        retval = True
        if old in self.text_start:
            self.text_start[new] = self.text_start[old]
            self.text_end[new] = self.text_end[old]
            self.text_prog[new] = self.text_prog[old]
            self.so_addr_map[new] = self.so_addr_map[old]
            self.so_file_map[new] = self.so_file_map[old]
        else:
            self.lgr.debug('soMap swappid pid %d not in text_start' % old)
            retval = False
        return retval

    def addText(self, start, size, prog, pid_in):
        ''' First check that SO not already loaded from a snapshot '''
        pid = self.getThreadPid(pid_in, quiet=True)
        if pid is None:
            pid = pid_in
        if pid in self.text_start:
            self.lgr.debug('soMap addText pid %d already in map len of so_addr_map %d' % (pid, len(self.so_file_map)))
        else:
            self.lgr.debug('soMap addText, prog %s pid:%d' % (prog, pid))
            self.text_start[pid] = start
            self.text_end[pid] = start+size
            self.text_prog[pid] = prog
            if pid not in self.so_addr_map:
                self.so_addr_map[pid] = {}
                self.so_file_map[pid] = {}

    def noText(self, prog, pid):
        self.lgr.debug('soMap noText, prog %s pid:%d' % (prog, pid))
        self.text_prog[pid] = prog
        self.text_start[pid] = None
        self.text_end[pid] = None

    def setContext(self, pid_list):
        pid = None
        for in_pid in pid_list:
            if in_pid in self.so_file_map:
                pid = in_pid
        if pid is None:
            self.lgr.error('soMap setContext found for any input pids %s' % (str(pid_list)))
        elif pid in self.text_start:
            self.context_manager.recordText(self.text_start[pid], self.text_end[pid])
        else:
            self.lgr.error('soMap setContext, no context for pid %d' % pid)
      
    def setIdaFuns(self, ida_funs):
        if ida_funs is None:
            self.lgr.warning('IDA funs is none, no SOMap')
            return
        self.ida_funs = ida_funs
        for pid in self.so_file_map:
            sort_map = {}
            for text_seg in self.so_file_map[pid]:
                sort_map[text_seg.locate] = text_seg

            for locate in sorted(sort_map, reverse=True):
                text_seg = sort_map[locate]
                fpath = self.so_file_map[pid][text_seg]
                full_path = self.targetFS.getFull(fpath, lgr=self.lgr)
                self.ida_funs.add(full_path, locate)
            
 
    def addSO(self, pid_in, fpath, addr, count):
        pid = self.getThreadPid(pid_in, quiet=True)
        if pid is None:
            pid = pid_in
        if pid in self.so_addr_map and fpath in self.so_addr_map[pid]:
            ''' multiple mmap calls for one so file.  assume continguous and adjust
                address to lowest '''
            if self.so_addr_map[pid][fpath].address > addr:
                self.so_addr_map[pid][fpath].address = addr
                # TBD?
                #if self.ida_funs is not None:
                #    self.ida_funs.adjust(full_path, addr))
        else:
            if pid not in self.so_addr_map:
                self.so_addr_map[pid] = {}
                self.so_file_map[pid] = {}

            full_path = self.targetFS.getFull(fpath, lgr=self.lgr)
            text_seg = elfText.getText(full_path, self.lgr)
            if text_seg is None:
                self.lgr.debug('SOMap addSO, no file at %s' % full_path)
                return
       
            text_seg.locate = addr
            #text_seg.size = count

            self.so_addr_map[pid][fpath] = text_seg
            self.so_file_map[pid][text_seg] = fpath
            self.lgr.debug('soMap addSO pid:%d, full: %s size: 0x%x given count: 0x%x, locate: 0x%x addr: 0x%x off 0x%x  len so_map %d' % (pid, 
                   full_path, text_seg.size, count, addr, text_seg.address, text_seg.offset, len(self.so_addr_map[pid])))

            start = text_seg.locate
            if self.ida_funs is not None:
                self.ida_funs.add(full_path, start)

    def showSO(self, pid=None):
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
        pid = self.getSOPid(pid)
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
            print('no so map for %d' % pid)
        print('SO Map for threads led by group leader pid: %d' % pid)
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
 
    def handleExit(self, pid, killed=False):
        ''' when a thread leader exits, clone the so map structures to each child, TBD determine new thread leader? '''
        if pid not in self.so_addr_map and pid not in self.text_start:
            self.lgr.debug('SOMap handleExit pid %d not in so_addr map' % pid)
            return
        self.lgr.debug('SOMap handleExit pid %d' % pid)
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
                        if pid in self.text_start:
                            self.text_start[tpid] = self.text_start[pid]
                            self.text_end[tpid] = self.text_end[pid]
                            self.text_prog[tpid] = self.text_prog[pid]
                        else:
                            self.lgr.debug('SOMap handle exit, missing text_start entry pid: %d tpid %d' % (pid, tpid))
        
            else:
                self.lgr.debug('SOMap handleExit pid %d NOT in pidlist' % pid)
        if pid in self.so_addr_map:
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
                self.lgr.debug('SOMap getThreadPid requested unknown pid %d %s  -- not debugging?' % (pid, str(pid_list)))
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
            if pid == self.cheesy_pid:
                return self.cheesy_mapped
            ppid = self.task_utils.getGroupLeaderPid(pid)
            #self.lgr.debug('SOMap getSOPid getCurrnetTaskLeader got %s for current pid %d' % (ppid, pid))
            if ppid != pid:
                #self.lgr.debug('SOMap getSOPid use group leader')
                retval = ppid
            else:
                ppid = self.task_utils.getPidParent(pid)
                if ppid != pid:
                    #self.lgr.debug('SOMap getSOPid use parent %d' % ppid)
                    retval = ppid
                else:
                    #self.lgr.debug('getSOPid no so map after get parent for %d' % pid)
                    retval = None
            self.cheesy_pid = pid
            self.cheesy_mapped = retval
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
                #for text_seg in sorted(self.so_file_map[pid]):
                for text_seg in self.so_file_map[pid]:
                    start = text_seg.locate 
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
                #for text_seg in sorted(self.so_file_map[pid]):
                for text_seg in self.so_file_map[pid]:
                    #start = text_seg.locate + text_seg.offset
                    start = text_seg.locate 
                    end = start + text_seg.size
                    if start <= addr_in and addr_in <= end:
                        retval = self.so_file_map[pid][text_seg], start, end
                        break
            
        else:
            self.lgr.debug('getSOInfo no so map for %d' % pid)
        return retval

    def getSOAddr(self, in_fname, pid=None):
        retval = None
        if pid is None:
            cpu, comm, pid = self.task_utils.curProc() 
        pid = self.getSOPid(pid)
        if pid is None:
            return None
        self.lgr.debug('getSOAddr look for addr for pid %d in_fname %s' % (pid, in_fname))
        ''' TBD fix this? '''
        #if pid in self.text_prog:
        #    self.lgr.debug('getSOAddr YES pid %d is in text_prog as %s' % (pid, self.text_prog[pid]))
        #if pid in self.text_prog and (in_fname.endswith(self.text_prog[pid]) or self.text_prog[pid].endswith(in_fname)):
        if pid in self.text_prog and (os.path.basename(in_fname) == os.path.basename(self.text_prog[pid])):
            size = self.text_end[pid] - self.text_start[pid]
            retval = elfText.Text(self.text_start[pid], 0, size)
        elif pid in self.so_file_map:
            for fpath in self.so_addr_map[pid]:
                self.lgr.debug('getSOAddr fpath %s' % fpath)
                base = os.path.basename(fpath)
                other_base = None
                full = os.path.join(self.targetFS.getRootPrefix(), fpath[1:])
                if os.path.islink(full):
                    other_base =  os.readlink(full)
                in_base = os.path.basename(in_fname)
                self.lgr.debug('compare <%s> or <%s> to <%s>' % (base, other_base, in_base))
                if base == in_base or other_base == in_base:
                    retval = self.so_addr_map[pid][fpath]
                    self.lgr.debug('compare found match fpath %s retval is 0x%x' % (fpath, retval.address))
                    break
            if retval is None:
                for fpath in self.so_addr_map[pid]:
                    self.lgr.debug('getSOAddr fpath2 %s' % fpath)
                    base = os.path.basename(fpath)
                    other_base = None
                    full = os.path.join(self.targetFS.getRootPrefix(), fpath[1:])
                    if os.path.islink(full):
                        other_base =  os.readlink(full)
                    in_base = os.path.basename(in_fname)
                    self.lgr.debug('compare %s or %s to %s' % (base, other_base, in_base))
                    if in_base.startswith(base) or (other_base is not None and in_base.startswith(other_base)):
                        retval = self.so_addr_map[pid][fpath]
                        self.lgr.debug('compare found startswith match')
                        break

            if retval is None:
                self.lgr.debug('SOMap getSOAddr could not find so map for %d <%s>' % (pid, in_fname))
                self.lgr.debug('text_prog is <%s>' % self.text_prog[pid])
                
        else:
            self.lgr.debug('SOMap getSOAddr no so map for %d %s' % (pid, in_fname))
            if pid in self.text_prog:
                self.lgr.debug('text_prog is <%s>' % self.text_prog[pid])
        return retval
    

    def stopHap(self, cpu, one, exception, error_string):
        if self.stop_hap is not None:
            eip = self.top.getEIP(cpu)
            self.lgr.debug('soMap stopHap ip: 0x%x' % eip)
            self.top.skipAndMail()
            SIM_hap_delete_callback_id("Core_Simulation_Stopped", self.stop_hap)
            self.stop_hap = None

    def stopAlone(self, cpu):
        if len(self.hap_list) > 0:
            self.stop_hap = SIM_hap_add_callback("Core_Simulation_Stopped", 
            	     self.stopHap, cpu)
            self.lgr.debug('soMap stopAlone')
            for hap in self.hap_list:
                self.context_manager.genDeleteHap(hap)
            del self.hap_list[:]

            SIM_break_simulation('soMap')

    def knownHap(self, pid, third, forth, memory):
        if len(self.hap_list) > 0:
            cpu, comm, cur_pid = self.task_utils.curProc() 
            if pid == cur_pid: 
                value = memory.logical_address
                fname, start, end = self.getSOInfo(value)
                if fname is not None and start is not None:
                    self.lgr.debug('soMap knownHap pid:%d memory 0x%x %s start:0x%x end:0x%x' % (pid, value, fname, start, end))
                else:
                    self.lgr.debug('soMap knownHap pid:%d memory 0x%x NO mapping file %s' % (pid, value, fname))

                SIM_run_alone(self.stopAlone, cpu)                
            #else:
            #    self.lgr.debug('soMap knownHap wrong pid, wanted %d got %d' % (pid, cur_pid))
        
    def runToKnown(self, skip=None):        
       cpu, comm, cur_pid = self.task_utils.curProc() 
       map_pid = self.getSOPid(cur_pid)
       if map_pid in self.text_start: 
           start =  self.text_start[map_pid] 
           length = self.text_end[map_pid] - self.text_start[map_pid] 
           proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, start, length, 0)
           self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.knownHap, cur_pid, proc_break, 'runToKnown'))
           #self.lgr.debug('soMap runToKnow text 0x%x 0x%x' % (start, length))
       else:
           self.lgr.debug('soMap runToKnown no text for %d' % map_pid)
       if map_pid in self.so_file_map:
            for text_seg in self.so_file_map[map_pid]:
                start = text_seg.locate+text_seg.offset
                length = text_seg.size
                end = start+length
                if skip is None or not (skip >= start and skip <= end):
                    proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, start, length, 0)
                    self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.knownHap, cur_pid, proc_break, 'runToKnown'))
                else:
                    self.lgr.debug('soMap runToKnow, skip %s' % (self.so_file_map[map_pid][text_seg]))
                #self.lgr.debug('soMap runToKnow lib %s 0x%x 0x%x' % (self.so_file_map[map_pid][text_seg], start, length))
       else:
           self.lgr.debug('soMap runToKnown no so_file_map for %d' % map_pid)
       if len(self.hap_list) > 0:  
           return True
       else:
           return False
                
