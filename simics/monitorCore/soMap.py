'''
 * This software was created by United States Government employees
 * and may not be copyrighted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
'''
from simics import *
import os
import sys
import pickle
import elfText
import resimUtils
import doInUser
import json
from pathlib import Path
from resimHaps import *
resim_dir = os.getenv('RESIM_DIR')
sys.path.append(os.path.join(resim_dir, 'simics', 'bin'))
import missingDLLAnalysis
'''
Manage maps of shared object libraries
Also track text segment.
NOTE: does not catch introduction of new code other than so libraries
'''
class CodeSection():
    def __init__(self, addr, size, fname):
        self.addr = addr
        self.size = size
        self.fname = fname

class ProgInfo():
    def __init__(self, text_start, text_size, text_offset, plt_addr, plt_offset, plt_size, local_path, interp=None):
        self.text_start = text_start
        self.text_size = text_size
        self.text_end = None
        self.dynamic = False
        self.interp = interp
        if self.text_start is not None and text_size is not None:
           self.text_end = text_start + text_size
        self.text_offset = text_offset
        if plt_offset is None:
            self.plt_addr = 0
            self.plt_offset = 0
            self.plt_size = 0
        else:
            self.plt_addr = plt_addr
            self.plt_offset = plt_offset
            self.plt_size = plt_size
        self.local_path = local_path
    def setDynamic(self):
        self.dynamic = True

    def toString(self):
        if self.text_start is not None and self.plt_size is not None:
            return('text_start 0x%x text_size 0x%x text_offset 0x%x plt_addr 0x%x plt_offset 0x%x plt_size 0x%x' % (self.text_start, self.text_size,
                self.text_offset, self.plt_addr, self.plt_offset, self.plt_size))
        elif self.text_offset is not None:
            if self.text_size is not None:
                return('relocatable text_offset 0x%x size: 0x%x interp: %s' % (self.text_offset, self.text_size, self.interp))
            else:
                return('relocatable text_offset 0x%x size is none interp: %s' % (self.text_offset, self.interp))
                
        else:
            return('Not a binary')


class LoadInfo():
    def __init__(self, addr, size, interp=None):
        self.addr = addr
        self.size = size
        self.interp = interp
        if addr is not None:
            self.end = addr+size
    
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

        # static data from elf headers
        self.prog_info = {}

        self.prog_start = {}
        self.prog_end = {}
        self.text_prog = {}
        self.prog_text_start = {}
        self.prog_text_end = {}
        self.prog_text_offset = {}
        self.prog_local_path = {}
        self.hap_list = []
        self.stop_hap = None
        self.fun_mgr = None
        # optimization?
        self.cheesy_tid = 0
        self.cheesy_mapped = 0
        self.fun_list_cache = []
        self.so_watch_callback = {}

        self.prog_base_map = {}
        self.root_prefix = self.top.getCompDict(self.cell_name, 'RESIM_ROOT_PREFIX')

        # Used to check for SO watches after execve program is loaded
        self.pending_execve = {}

        # NO declarations below here
        if run_from_snap is not None:
            self.loadPickle(run_from_snap)

    def loadPickle(self, name):
        somap_file = os.path.join('./', name, self.cell_name, 'soMap.pickle')
        if os.path.isfile(somap_file):
            self.lgr.debug('SOMap loadPickle pickle from %s' % somap_file)
            so_pickle = pickle.load( open(somap_file, 'rb') ) 
            #print('start %s' % str(so_pickle['text_start']))
            self.text_prog = so_pickle['text_prog']
            self.prog_start = so_pickle['prog_start']
            self.prog_end = so_pickle['prog_end']
            self.prog_local_path = so_pickle['prog_local_path']
            version = self.top.getSnapVersion() 
            if 'prog_base_map' in so_pickle:
                self.prog_base_map = so_pickle['prog_base_map']
                self.lgr.debug('SOMap loadPickle prog_base_map keys %s' % str(self.prog_base_map.keys()))
                # TBD hack remove after snapshots cycle out.  was mapping path basename vice prog basename, symlinks!
                base_name_list = list(self.prog_base_map.keys())
                for base_name in base_name_list:
                    prog_base = os.path.basename(self.prog_base_map[base_name])
                    if prog_base not in self.prog_base_map:
                        self.prog_base_map[prog_base] = self.prog_base_map[base_name]

            else:
                for tid in self.text_prog:
                    base = os.path.basename(self.text_prog[tid])
                    self.prog_base_map[base] = self.text_prog[tid]
                
            if 'prog_info' in so_pickle:
                self.so_addr_map = so_pickle['so_addr_map']
                self.so_file_map = so_pickle['so_file_map']
                if version < 23:
                    self.lgr.debug('soMap loadPickle version %d less than 23, hack backward compat' % version)
                    old_prog_info = so_pickle['prog_info']
                    for prog in old_prog_info: 
                         if prog.startswith('/'):
                             use_prog = prog[1:]
                         else:
                             use_prog = prog
                         prog_path = os.path.join(self.root_prefix, use_prog)
                         elf_info = elfText.getText(prog_path, self.lgr)
                         if elf_info is not None:
                             self.prog_info[prog] = ProgInfo(elf_info.text_start, elf_info.text_size, elf_info.text_offset, elf_info.plt_addr, 
                                  elf_info.plt_offset, elf_info.plt_size, prog, interp=elf_info.interp)
                             self.lgr.debug('soMap loadPickle prog %s info %s' % (prog, self.prog_info[prog].toString()))
                             prog_basename = os.path.basename(prog)
                             self.prog_base_map[prog_basename] = prog
                         else:
                             self.lgr.debug('soMap loadPickle no elf info for %s' % prog)
                             pass
                else:
                    self.prog_info = so_pickle['prog_info']
                    self.lgr.debug('soMap loadPickle version %d has proper elf info, load %d prog_info from pickle' % (version, len(self.prog_info)))
                if version < 24:
                    self.lgr.debug('version less than 24')
                    for prog in self.prog_info:
                        base = os.path.basename(prog)
                        self.lgr.debug('soMap loadPickle base %s prog %s' % (base, prog))
                        self.prog_base_map[base] = prog
                else:
                    for prog in self.prog_info:
                        if self.prog_info[prog].plt_offset is None:
                            self.prog_info[prog].plt_offset = 0
                            self.prog_info[prog].plt_size = 0
                if version < 25:
                    for prog in self.prog_info:
                        #self.lgr.debug('soMap loadPickle prog %s start 0x%x size 0x%x' % (prog, self.prog_info[prog].text_offset, self.prog_info[prog].text_size))
                        full_path = self.top.getFullPath(prog)
                        real_path = resimUtils.realPath(full_path)
                        #self.lgr.debug('soMap loadPickle add prog info for real path %s' % (real_path))
                        self.addProgInfo(prog, real_path)
                        for tid in self.text_prog:
                            if self.text_prog[tid] == prog:
                                self.prog_end[tid] = self.prog_start[tid] + self.prog_info[prog].text_size
                                #self.lgr.debug('soMap loadPickle self.prog_start[%s] is 0x%x end changed to 0x%x' % (tid, self.prog_start[tid], self.prog_end[tid]))
                                break
                if version < 26:
                    self.lgr.debug('Got version %d' % version)
                    for tid in self.so_file_map:
                        for load_info in self.so_file_map[tid]:
                            prog = self.so_file_map[tid][load_info]
                            self.lgr.debug('wtf prog is %s' % prog)
                            if 'libubox.so' in prog:
                                self.lgr.debug('Got bad libubox.so')
                                load_info.addr = load_info.addr - 0x3000
            else:
                # backward compatability, but only most recent
                # TBD remove all this
                for tid in self.text_prog:
                    prog = self.text_prog[tid]
                    if self.prog_start[tid] is not None:
                        size = self.prog_end[tid] - self.prog_start[tid]
                        if tid in self.prog_local_path:
                            self.prog_info[prog] = ProgInfo(self.prog_start[tid], size, 0, 0, 0, self.prog_local_path[tid])
                        else:
                            self.prog_info[prog] = ProgInfo(self.prog_start[tid], size, 0, 0, 0, None)
                    else:
                        self.prog_info[prog] = None
                old_so_file_map = so_pickle['so_file_map']
                for tid in old_so_file_map:
                    for text_seg in old_so_file_map[tid]:
                        prog = old_so_file_map[tid][text_seg]
                        if prog not in self.prog_info:
                            end = text_seg.text_start + text_seg.text_size - 1
                            self.prog_info[prog] = ProgInfo(text_seg.text_start, end, text_seg.text_offset, 0, 0, None)
                        load_info = LoadInfo(text_seg.address, text_seg.size)
                        if tid not in self.so_file_map:
                            self.so_file_map[tid] = {}
                            self.so_addr_map[tid] = {}
                        self.so_file_map[tid][load_info] = prog
                        self.so_addr_map[tid][prog] = load_info.addr            

            self.lgr.debug('SOMap  loadPickle %d text_progs' % (len(self.text_prog)))

    def pickleit(self, name):
        somap_file = os.path.join('./', name, self.cell_name, 'soMap.pickle')
        so_pickle = {}
        so_pickle['so_addr_map'] = self.so_addr_map
        so_pickle['so_file_map'] = self.so_file_map
        so_pickle['prog_start'] = self.prog_start
        so_pickle['prog_end'] = self.prog_end
        so_pickle['text_prog'] = self.text_prog
        so_pickle['prog_local_path'] = self.prog_local_path
        so_pickle['prog_info'] = self.prog_info
        so_pickle['prog_base_map'] = self.prog_base_map
        fd = open( somap_file, "wb") 
        pickle.dump( so_pickle, fd)
        self.lgr.debug('SOMap pickleit to %s saved %d text_progs and %d prog_info' % (somap_file, len(self.text_prog), len(self.prog_info)))

    def isCode(self, address, tid):
        ''' is the given address within the text segment or those of SO libraries? '''
        #self.lgr.debug('compare 0x%x to 0x%x - 0x%x' % (address, self.prog_start, self.prog_end))
        tid = self.getSOTid(tid)
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
            self.lgr.debug('SOMap isCode, regot tid after getSOTid failed, tid:%s missing from so_file_map' % tid)
            return False
        if tid in self.prog_start and self.prog_start[tid] is not None and address >= self.prog_start[tid] and address <= self.prog_end[tid]:
            prog = self.text_prog[tid]
            prog_info = self.prog_info[prog]
            #self.lgr.debug('soMap isCode prog %s info %s' % (prog, prog_info.toString()))
            code_start = None
            # TBD this is messed up.  Just use entry point address
            if self.cpu.architecture == 'ppc32':
                code_start = self.prog_start[tid] 
            else:
                code_start = self.prog_start[tid] + prog_info.plt_offset    
            #self.lgr.debug('soMap isCode addr 0x%x code_start 0x%x' % (address, code_start))
            if address > code_start:
                return True
            else:
                return False
        if tid not in self.so_file_map:
            tid = self.task_utils.getCurrentThreadLeaderTid()
        if tid not in self.so_file_map:
            self.lgr.debug('SOMap isCode, tid:%s missing from so_file_map' % tid)
            return False
        for load_info in self.so_file_map[tid]:
            start = load_info.addr 
            end = load_info.end
            if address >= start and address <= end:
                return True
        return False

    def isFunNotLibc(self, address):
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

    def isMainText(self, address):
        if address is None:
            self.lgr.error('soMap isMainText called with None')
            return False
        cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        #self.lgr.debug('soMap isMainText address 0x%x tid %s' % (address, tid))
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

    def addText(self, path, prog, tid_in):
        # Add information about a newly loaded program, returning load info
        if path is None:
            self.lgr.error('soMap addText called with path of None prog %s' % prog) 
            return
        if tid_in in self.text_prog and self.text_prog[tid_in] == prog:
            self.lgr.debug('soMap addText prog %s already in text_prog as that tid (%s), bail' % (prog, tid_in))
            retval = self.getLoadInfo(tid=tid_in)
            return retval
        tid_already = self.getSOTid(tid_in)
        self.lgr.debug('soMap addText tid_in %s tid_already %s' % (tid_in, tid_already))
        if tid_already is not None:
            if tid_already != tid_in:
                self.lgr.debug('soMap addText tid_in %s is thread of existing leader %s' % (tid_in, tid_already))
                retval = self.getLoadInfo(tid=tid_already)
                return retval
            else:
                tid = tid_already
        else:
            tid = tid_in
        self.lgr.debug('soMap addText tid_in %s path %s tid now %s' % (tid_in, path, tid))
        retval = None
        prog_basename = os.path.basename(prog)
        #if prog_basename == 'busybox':
        #    self.lgr.debug('soMap ignore busybox')
        #    return None
        if prog_basename not in self.prog_base_map:
            self.prog_base_map[prog_basename] = prog
            self.lgr.debug('soMap addText prog_base_map for %s set to %s' % (prog_basename, prog))
        else:
            if self.prog_base_map[prog_basename] != prog:
                self.lgr.warning('soMap addText collision on program base name %s adding %s, replace old with new' % (prog_basename, prog))
                self.prog_base_map[prog_basename] = prog
        eip = None
        interp = None 
        skip_this = False
        if prog not in self.prog_info:
            self.addProgInfo(prog, path)
        else:
            self.lgr.debug('soMap addText prog already in prog_info: %s' % prog)
        if not skip_this:
            if tid not in self.so_addr_map:    
                self.so_addr_map[tid] = {}
                self.so_file_map[tid] = {}
                self.lgr.debug('soMap addText tid:%s added to so_file_map' % tid)
            else:
                self.lgr.debug('soMap addText tid:%s already in map len of so_addr_map %d' % (tid, len(self.so_file_map)))
            if tid in self.prog_start:
                self.lgr.debug('soMap addText tid:%s already in prog_start as %s, overwrite' % (tid, self.text_prog[tid]))
            
            if prog in self.prog_info:    
                if self.prog_info[prog].text_start is not None:
                    if self.prog_info[prog].dynamic:
                        load_addr = None
                        self.prog_end[tid] = None
                    else:
                        load_addr = self.prog_info[prog].text_start - self.prog_info[prog].text_offset
                        self.lgr.debug('soMap addText text_offset 0x%x' % self.prog_info[prog].text_offset)
                        self.prog_end[tid] = self.prog_info[prog].text_end
                    self.prog_start[tid] = load_addr
                    if load_addr is not None:
                        self.lgr.debug('soMap addText setting prog_start to 0x%x for prog %s' % (load_addr, prog))
                    else:
                        self.lgr.debug('soMap addText load_addr is none for prog %s' % (prog))
                    self.text_prog[tid] = prog
                    # do not check so watch here, the program is not yet loaded.
                    #self.checkSOWatch(load_addr, prog)
                    self.pending_execve[prog] = load_addr
                    mem_utils = self.task_utils.getMemUtils()
                    doInUser.DoInUser(self.top, self.cpu, self.pendingExecve, prog, self.task_utils, mem_utils, self.context_manager, self.lgr, tid=tid)
                    size = self.prog_info[prog].text_size + self.prog_info[prog].text_offset
                    retval = LoadInfo(load_addr, size, interp=interp)
                else:
                    self.lgr.debug('soMap addText prog %s has no text start' % prog)
            else:
                self.lgr.debug('soMap addText prog %s not in prog_info' % prog)
        else:
            self.lgr.debug('soMap addText told to skip %s, maybe not an elf' % prog) 
        return retval

    def pendingExecve(self, prog):
        if prog not in self.pending_execve:
            self.lgr.error('soMap pendingExecve prog %s not found' % prog)
        else:
            self.lgr.debug('soMap pendingExecve for prog %s' % prog)
            self.checkSOWatch(self.pending_execve[prog], prog)
            del self.pending_execve[prog]
            

    def addProgInfo(self, prog, path):
        elf_info = elfText.getText(path, self.lgr)
        if elf_info is not None:
            self.prog_info[prog] = ProgInfo(elf_info.text_start, elf_info.text_size, elf_info.text_offset, elf_info.plt_addr, 
                   elf_info.plt_offset, elf_info.plt_size, path, interp=elf_info.interp)
            interp = elf_info.interp
            self.lgr.debug('soMap addProgInfo prog info %s %s' % (prog, self.prog_info[prog].toString()))
            if self.prog_info[prog].text_start is None:
                if self.prog_info[prog].text_size is not None:
                    eip = self.top.getEIP(self.cpu)
                    mem_utils = self.task_utils.getMemUtils()
                    if mem_utils.isKernel(eip):
                        eip = mem_utils.getKReturnAddr(self.cpu)
                        if eip is None:
                            self.lgr.error('soMap addProgInfo no text start, assume dynamic but eip is in kernel and getting return addr is TBD')
                            return
                        self.lgr.debug('soMap addProgInfo no text start, assume dynamic eip based on kernel return addr is 0x%x' % eip)
                    else:
                        self.lgr.debug('soMap addProgInfo no text start, assume dynamic eip is 0x%x' % eip)
                    self.prog_info[prog].text_start = 0
                    self.prog_info[prog].text_end = self.prog_info[prog].text_size - 1
                    self.prog_info[prog].setDynamic()
                else:
                    self.lgr.debug('soMap addProgInfo no text start or text size, for %s' % prog)

    def noText(self, prog, tid):
        self.lgr.debug('soMap noText, prog %s tid:%s' % (prog, tid))
        self.text_prog[tid] = prog
        self.prog_start[tid] = None
        self.prog_end[tid] = None

    def getAnalysisPath(self, fname):
        return resimUtils.getAnalysisPath(None, fname, fun_list_cache = self.fun_list_cache, root_prefix=self.root_prefix, lgr=self.lgr)
            
    def setFunMgr(self, fun_mgr, tid_in):
        if fun_mgr is None:
            self.lgr.warning('soMap setFunMgr input fun_mgr is none')
            return
        self.fun_mgr = fun_mgr
        #tid = self.getThreadTid(tid_in, quiet=True)
        tid = self.getSOTid(tid_in)
        if tid is None:
            self.lgr.error('soMap setFunMgr failed to getSOTid, tid_in was %s' % tid_in)
            return
        self.lgr.debug('soMap setFunMgr %s' % tid_in)
        sort_map = {}
        for load_info in self.so_file_map[tid]:
            sort_map[load_info.addr] = load_info

        for locate in sorted(sort_map, reverse=True):
            load_info = sort_map[locate]
            fpath = self.so_file_map[tid][load_info]
            full_path = self.getAnalysisPath(fpath)
            self.lgr.debug('soMap setFunMgr path %s' % fpath)
            # TBD can we finally get rid of old style paths?
            #if full_path is None:
            #    full_path = self.targetFS.getFull(fpath, lgr=self.lgr)
            if full_path is not None:
                full_path = full_path+'.funs'
                self.fun_mgr.add(full_path, locate)
    
    def addLoader(self, tid_in, prog, addr):
        load_info = None

        tid = self.getSOTid(tid_in)
        self.lgr.debug('soMap addLoader tid:%s prog %s addr 0x%x' % (tid, prog, addr))
        full_path = self.targetFS.getFull(prog, lgr=self.lgr)
        if full_path is not None:
            if tid is None:
                tid = tid_in
            if tid not in self.so_addr_map:
                self.so_addr_map[tid] = {}
                self.so_file_map[tid] = {}

            elf_info = elfText.getText(full_path, self.lgr)
            if elf_info is not None:
                self.lgr.debug('soMap addLoader tid:%s prog %s  text_offset 0x%x' % (tid, prog, elf_info.text_offset))
                self.prog_info[prog] = ProgInfo(elf_info.text_start, elf_info.text_size, elf_info.text_offset, elf_info.plt_addr, 
                     elf_info.plt_offset, elf_info.plt_size, prog)
            else:
                self.lgr.error('soMap addLoader no elf info from %s' % prog)
                return
            load_addr = addr -  elf_info.text_offset
            self.lgr.debug('soMap addLoader tid:%s prog %s load_addr 0x%x size 0x%x' % (tid, prog, load_addr, elf_info.text_size))
            load_size = elf_info.text_size + elf_info.text_offset
            load_info = LoadInfo(load_addr, load_size)

            self.so_addr_map[tid][prog] = load_info
            self.so_file_map[tid][load_info] = prog
            self.lgr.debug('soMap addLoader tid: %s prog %s addr: 0x%x' % (tid, prog, addr))
        
        return load_info
        
    def addSO(self, tid_in, prog, addr, count):
        self.lgr.debug('soMap addSO')
        if '..' in prog:
            prog = str(Path(prog).resolve())
        prog_basename = os.path.basename(prog)
        if prog_basename not in self.prog_base_map:
            self.prog_base_map[prog_basename] = prog
            self.lgr.debug('soMap addSO prog_base_map for %s set to %s' % (prog_basename, prog))
        else:
            if self.prog_base_map[prog_basename] != prog:
                self.lgr.warning('soMap addeSO collision on program base name %s adding %s.  Replace old with new.' % (prog_basename, prog))
                self.prog_base_map[prog_basename] = prog
        #tid = self.getThreadTid(tid_in, quiet=True)
        tid = self.getSOTid(tid_in)
        if tid is None:
            tid = tid_in
        if tid in self.so_addr_map and prog in self.so_addr_map[tid]:
            self.lgr.debug('soMap addSO tid %s already in map' % tid)
            ''' multiple mmap calls for one so file.  assume continguous and adjust
                address to lowest '''
            if self.so_addr_map[tid][prog].addr> addr:
                self.so_addr_map[tid][prog].addr = addr
                # TBD?
                #if self.ida_funs is not None:
                #    self.ida_funs.adjust(full_path, addr))
        else:
            if tid not in self.so_addr_map:
                self.so_addr_map[tid] = {}
                self.so_file_map[tid] = {}

            full_path = self.targetFS.getFull(prog, lgr=self.lgr)
            self.lgr.debug('soMap addSO tid %s prog %s full %s' % (tid, prog, full_path))
            if full_path is not None and prog not in self.prog_info:
                elf_info = elfText.getText(full_path, self.lgr)
                if elf_info is not None:
                    self.prog_info[prog] = ProgInfo(elf_info.text_start, elf_info.text_size, elf_info.text_offset, elf_info.plt_addr, 
                         elf_info.plt_offset, elf_info.plt_size, full_path, interp=elf_info.interp)
                    self.lgr.debug('soMap addSo added prog_info for prog %s' % prog)
                else:
                    self.lgr.debug('soMap addSo no elf info from %s' % prog)

            load_info = LoadInfo(addr, count)

            self.so_addr_map[tid][prog] = load_info
            self.so_file_map[tid][load_info] = prog
            self.lgr.debug('soMap addSO tid: %s prog %s addr: 0x%x' % (tid, prog, addr))

            if self.fun_mgr is not None:
                self.fun_mgr.add(full_path, addr)

            self.checkSOWatch(addr, prog)

    def listSO(self, filter=None):
        for tid in self.so_file_map:
            self.lgr.debug('soMap listSO tid %s in so_file_map' % tid)
            for load_info in self.so_file_map[tid]:
                prog = self.so_file_map[tid][load_info]
                if filter is None or filter in prog:
                    print('tid:%s  0x%x - 0x%x   %s' % (tid, load_info.addr, load_info.end, prog))
        for tid in self.text_prog:
            if filter is None or filter in self.text_prog[tid]:
                if tid in self.prog_start and self.prog_start[tid] is not None:
                    print('tid:%s  0x%x - 0x%x   %s' % (tid, self.prog_start[tid], self.prog_end[tid], self.text_prog[tid]))
                else:
                    #print('tid:%s  no text found' % tid)
                    pass
         
    def findSOPath(self, starts, tid=None):
        retval = None
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
            print('no so map for %s' % tid)
            self.lgr.debug('soMap findSOPath no so map for %s' % tid)
            return None
        if tid in self.so_file_map:
            sort_map = {}
            for load_info in self.so_file_map[tid]:
                prog = self.so_file_map[tid][load_info]
                self.lgr.debug('soMap findSOPath try %s' % prog)
                if  os.path.basename(prog).startswith(starts):
                    retval = prog
                    break
        else:
            self.lgr.debug('soMap findSOPath tid:%s not in so_file_map' % tid)
        return retval

    def showSO(self, tid=None, filter=None, save=False):
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
            print('no so map for %s' % tid)
            self.lgr.debug('soMap showSO no so map for %s' % tid)
        print('SO Map for threads led by group leader tid: %s' % tid)
        if tid in self.so_file_map:
            if save:
                ofile = 'logs/somap-%s.somap' % tid
                ofile_fh = open(ofile, 'w')
            if tid in self.prog_start and self.prog_start[tid] is not None:
                print('0x%x - 0x%x   %s' % (self.prog_start[tid], self.prog_end[tid], self.text_prog[tid]))
            else:
                print('tid:%s not in text sections' % tid)
                self.lgr.debug('showSO tid:%s not in text sections' % tid)
            sort_map = {}
            for load_info in self.so_file_map[tid]:
                prog = self.so_file_map[tid][load_info]
                load_addr = load_info.addr
                sort_map[load_addr] = load_info
                
            for locate in sorted(sort_map):
                load_info = sort_map[locate]
                prog = self.so_file_map[tid][load_info]
                if filter is None or filter in prog:
                    if prog in self.prog_info: 
                        if self.prog_info[prog].text_offset is not None:
                            if save:
                                ofile_fh.write('0x%x - 0x%x 0x%x 0x%x  %s\n' % (locate, load_info.end, self.prog_info[prog].text_offset, self.prog_info[prog].text_size, prog))
                            else:
                                print('0x%x - 0x%x 0x%x 0x%x  %s' % (locate, load_info.end, self.prog_info[prog].text_offset, self.prog_info[prog].text_size, prog))
                        else:
                            if save:
                                ofile_fh.write('0x%x - 0x%x ???? ????  %s\n' % (locate, load_info.end, prog))
                            else:
                                print('0x%x - 0x%x ???? ????  %s' % (locate, load_info.end, prog))
                    else:
                        if save:
                            ofile_fh.write('0x%x - 0x%x ???  ???   %s\n' % (locate, load_info.end, prog))
                        else:
                            print('0x%x - 0x%x ???  ???   %s' % (locate, load_info.end, prog))
            if save:
                ofile_fh.close()
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
        self.lgr.debug('getSO tid:%s' % tid)
        if tid in self.so_file_map:
            if tid in self.prog_start and self.prog_start[tid] is not None:
                prog = self.text_prog[tid]
                if prog in self.prog_info:
                    retval['offset'] = self.prog_info[prog].text_offset
                    if self.prog_info[prog].text_start == 0:
                        retval['relocate'] = 'True'
                        self.lgr.debug('getSO tid:%s is relocate' % tid)
                    else:
                        self.lgr.debug('getSO tid:%s text_start is 0x%x' % (tid, self.prog_info[prog].text_start))
                else:
                    retval['offset'] = 0
                    self.lgr.debug('getSO tid:%s prog %s not in prog_info' % prog)
                retval['prog_start'] = self.prog_start[tid]
                retval['prog_end'] = self.prog_end[tid]
                retval['prog'] = self.text_prog[tid]
                if tid in self.prog_local_path:
                    retval['prog_local_path'] = self.prog_local_path[tid]
                else:
                    retval['prog_local_path'] = self.top.getFullPath()
            else:
                self.lgr.debug('getSO tid:%s not in text sections' % tid)
            sort_map = {}
            for load_info in self.so_file_map[tid]:
                sort_map[load_info.addr] = load_info
            retval['sections'] = []
            for locate in sorted(sort_map):
                section = {}
                load_info = sort_map[locate]
                prog = self.so_file_map[tid][load_info]
                section['locate'] = locate
                section['end'] = load_info.end
                if prog in self.prog_info:
                    section['offset'] = self.prog_info[prog].text_offset
                    section['size'] = self.prog_info[prog].text_size
                else:
                    section['offset'] = 0
                    section['size'] = 0
                section['file'] = prog
                retval['sections'].append(section)
        else:
            self.lgr.debug('getSO no so map for %s' % tid)
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

    def hasSOInfo(self, tid_in):
        tid = self.getSOTid(tid_in)
        if tid in self.prog_start:
            return True
        else:
            return False

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
        # all threads in a family share one record for what we think is the parent tid (group leader)
        #self.lgr.debug('SOMap getSOTid for %s' % tid)
        retval = None
        if tid is None:
            self.lgr.error('soMap getSOTid called with None for tid')
            return None
        retval = tid
        if tid not in self.so_file_map:
            #self.lgr.debug('SOMap getSOTid for %s Not in so_file_map' % tid)
            if tid == self.cheesy_tid:
                return self.cheesy_mapped
            ptid = self.task_utils.getGroupLeaderTid(tid)
            #self.lgr.debug('SOMap getSOTid getCurrentTaskLeader got %s for current tid:%s' % (ptid, tid))
            if ptid != tid:
                self.lgr.debug('SOMap getSOTid try group leader %s' % ptid)
                if ptid in self.so_file_map:
                    retval = ptid
                else:
                    comm = self.task_utils.getCommFromTid(tid)
                    tid_list = self.task_utils.getTidsForComm(comm)
                    self.lgr.debug('SOMap getSOTid try thread tids, len %d' % (len(tid_list)))
                    for try_tid in tid_list:
                        if try_tid in self.so_file_map:
                            retval = try_tid
                            break
                    if retval is None:
                        self.lgr.debug('SOMap getSOTid giving up, using failed group leader')
                        retval = ptid
            #else:
            #    ptid = self.task_utils.getTidParent(tid)
            #    if ptid != tid:
            #        self.lgr.debug('SOMap getSOTid use parent %s' % ptid)
            #        retval = ptid
            #    else:
            #        self.lgr.debug('getSOTid no so map after get parent for %s' % tid)
            #        retval = None
            self.cheesy_tid = tid
            self.cheesy_mapped = retval
        return retval

    def getSOFileFull(self, addr_in):
        return self.getSOFile(addr_in)

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
                #return None
            elif tid not in self.prog_end or self.prog_end[tid] is None:
                self.lgr.warning('SOMap getSOFile tid:%s in so_file map but None for prog_end' % tid)
                #return None
            if tid in self.prog_start and tid in self.prog_end and addr_in >= self.prog_start[tid] and addr_in <= self.prog_end[tid]:
                retval = self.text_prog[tid]
            else:
                #for text_seg in sorted(self.so_file_map[tid]):
                for load_addr in self.so_file_map[tid]:
                    start = load_addr.addr 
                    end = load_addr.end
                    if start <= addr_in and addr_in <= end:
                        retval = self.so_file_map[tid][load_addr]
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
        # return file name, start and end for the binary file whose load range includes the given address.
        # start and end are the load addresses
        retval = None, None, None
        cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid is None:
            return retval
        if tid in self.so_file_map:
            if tid in self.prog_start and self.prog_start[tid] is not None and addr_in >= self.prog_start[tid] and addr_in <= self.prog_end[tid]:
                retval = self.text_prog[tid], self.prog_start[tid], self.prog_end[tid]
            else:
                for load_addr in self.so_file_map[tid]:
                    #start = text_seg.locate + text_seg.offset
                    start = load_addr.addr 
                    end = load_addr.end
                    if start <= addr_in and addr_in <= end:
                        retval = self.so_file_map[tid][load_addr], start, end
                        break
            
        else:
            self.lgr.debug('getSOInfo no so map for %s' % tid)
        return retval


    def stopHap(self, cpu, one, exception, error_string):
        if self.stop_hap is not None:
            eip = self.top.getEIP(cpu)
            self.lgr.debug('soMap stopHap ip: 0x%x' % eip)
            self.top.skipAndMail()
            self.top.RES_delete_stop_hap(self.stop_hap)
            self.stop_hap = None

    def stopAlone(self, cpu):
        if len(self.hap_list) > 0:
            self.stop_hap = self.top.RES_add_stop_callback(self.stopHap, cpu)
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
            else:
                self.lgr.debug('soMap knownHap wrong tid, wanted %s got %s' % (tid, cur_tid))
        
    def runToKnown(self, skip=None, threads=None):        
       # TBD why this and the one in runTo???  threads is not used here
       cpu, comm, cur_tid = self.task_utils.curThread() 
       map_tid = self.getSOTid(cur_tid)
       if map_tid in self.prog_start: 
           start =  self.prog_start[map_tid] 
           length = self.prog_end[map_tid] - self.prog_start[map_tid] 
           proc_break = self.context_manager.genBreakpoint(None, Sim_Break_Linear, Sim_Access_Execute, start, length, 0)
           self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.knownHap, cur_tid, proc_break, 'runToKnown'))
           self.lgr.debug('soMap runToKnow text 0x%x 0x%x' % (start, length))
       else:
           self.lgr.debug('soMap runToKnown no text for %s' % map_tid)
       if map_tid in self.so_file_map:
            for load_info in self.so_file_map[map_tid]:
                start = load_info.addr
                length = load_info.size
                end = load_info.end
                if skip is None or not (skip >= start and skip <= end):
                    proc_break = self.context_manager.genBreakpoint(self.cell, Sim_Break_Linear, Sim_Access_Execute, start, length, 0)
                    self.hap_list.append(self.context_manager.genHapIndex("Core_Breakpoint_Memop", self.knownHap, cur_tid, proc_break, 'runToKnown'))
                else:
                    self.lgr.debug('soMap runToKnow, skip %s' % (self.so_file_map[map_tid][load_info]))
                #self.lgr.debug('soMap runToKnow lib %s 0x%x 0x%x' % (self.so_file_map[map_tid][text_seg], start, length))
       else:
           self.lgr.debug('soMap runToKnown no so_file_map for %s' % map_tid)
       if len(self.hap_list) > 0:  
           return True
       else:
           return False

    def wordSize(self, tid=None):
       # TBD why take tid as param?  Because may be multiple processes/objects of different sizes
       # should pass in address, or leave as None to indicate current scheduled thread
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

    def getLocalPath(self, tid):
        tid = self.getSOTid(tid)
        retval = None
        if tid in self.prog_local_path:
            retval = self.prog_local_path[tid]
        return retval

    def getLoadAddr(self, in_fname, tid=None):
        retval, ret_size = self.getLoadAddrSize(in_fname, tid=tid)
        return retval

    def getLoadAddrSize(self, in_fname, tid=None):
        #self.lgr.debug('soMap getLoadAddr loadAddr %s tid %s' % (in_fname, tid))
        retval = None
        ret_size = None
        prog = self.fullProg(in_fname)
        if prog is None:
            self.lgr.error('soMap getLoadAddr got no prog for %s' % in_fname)
            return None, None
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        map_tid = self.getSOTid(tid)
        if map_tid not in self.so_file_map:
            self.lgr.debug('soMap getLoadAddr tid %s not in so_file_map, perhaps a prog' % map_tid)
        else:
            #self.lgr.debug('soMap getLoadAddr prog %s tid:%s file_map size %d' % (prog, tid, len(self.so_file_map[map_tid])))
            for load_info in self.so_file_map[map_tid]:
                #self.lgr.debug('soMap getLoadAddr compare %s to %s' % (self.so_file_map[map_tid][load_info], os.path.basename(prog)))
                if os.path.basename(self.so_file_map[map_tid][load_info]) == os.path.basename(prog):
                    retval = load_info.addr
                    ret_size = load_info.size
                    self.lgr.debug('soMap got match for %s address 0x%x tid:%s' % (prog, retval, tid))
                    break 

        if retval is None and map_tid in self.text_prog:
            if os.path.basename(self.text_prog[map_tid]) == os.path.basename(prog):
                self.lgr.debug('soMap just using prog_start for map_tid %s' % (map_tid))
                retval = self.prog_start[map_tid]
                ret_size = self.prog_end[map_tid] - self.prog_start[map_tid] + 1
        return retval, ret_size

    def isDynamic(self, in_fname):
        retval = False
        if in_fname in self.prog_info:
            try:
                retval = self.prog_info[in_fname].dynamic
            except AttributeError:
                pass
        else:
            prog = self.fullProg(in_fname)
            if prog in self.prog_info:
                retval = self.prog_info[prog].dynamic
            else:
                self.lgr.debug('soMap isDynamic in_fname %s not found in prog_info' % in_fname)
        return retval

    def getImageBase(self, in_fname):
        prog = self.fullProg(in_fname)
        retval = None
        if prog in self.prog_info:
            tid_list = self.task_utils.getTidsForComm(in_fname)
            if len(tid_list) == 0:
                self.lgr.debug('soMap gteImageBase has prog %s in prog_info, but no program running.  Do not mislead' %prog)
            else:
                if self.prog_info[prog].text_start == 0:
                    retval = 0
                elif self.prog_info[prog].text_start is not None:
                   retval = self.prog_info[prog].text_start - self.prog_info[prog].text_offset
                else:
                    retval = self.prog_info[prog].text_offset
        else:
            self.lgr.debug('soMap getImageBase not in prog_info: %s' % prog)

        return retval

    def getSOPidList(self, in_fname):
        # Get a list of PIDs that have the given library loaded
        retval = []
        prog = self.fullProg(in_fname)
        self.lgr.debug('soMap getSOPidList prog %s' % prog)
        for tid in self.so_file_map:
            for load_addr in self.so_file_map[tid]:
                if os.path.basename(self.so_file_map[tid][load_addr]) == os.path.basename(prog):
                    retval.append(tid) 
        for tid in self.text_prog: 
            if os.path.basename(self.text_prog[tid]) == os.path.basename(prog):
                retval.append(tid) 
        return retval

    def hasSOWatch(self, fpath):
        retval = False
        use_name = fpath
        base_name = os.path.basename(fpath)
        if use_name not in self.so_watch_callback and base_name in self.so_watch_callback:
            use_name = base_name
        self.lgr.debug('soMap hasSOWatch check if <%s> in so_watch_callbck %s' % (use_name, str(self.so_watch_callback.keys())))
        if use_name in self.so_watch_callback:
            retval = True
        return retval

    def addSOWatch(self, fname, callback, name=None):
        if name is None:
            name = 'NONE'
        prog = self.fullProg(fname)
        if prog is None:
            prog = fname
        if prog not in self.so_watch_callback:
            self.so_watch_callback[prog] = {}
        self.lgr.debug('soMap addSOWatch adding prog %s name %s to so_watch_callback' % (prog, name))
        self.so_watch_callback[prog][name] = callback

    def cancelSOWatch(self, fname, name):
        prog = self.fullProg(in_fname)
        if prog is None:
            prog = fname
        self.lgr.debug('soMap cancelSOWatch prog %s name %s to so_watch_callback' % (prog, name))
        if prog in self.so_watch_callback:
            if name in self.so_watch_callback[prog]:
                del self.so_watch_callback[prog][name]

    def checkSOWatch(self, load_addr, fpath):
        use_name = fpath
        base_name = os.path.basename(fpath)
        if use_name not in self.so_watch_callback and base_name in self.so_watch_callback:
            use_name = base_name
         
        self.lgr.debug('soMap checkSOWatch check if <%s> in so_watch_callbck %s' % (use_name, str(self.so_watch_callback.keys())))
        if use_name in self.so_watch_callback:
            self.lgr.debug('soMap checkSOWatch found %s, len %d' % (use_name, len(self.so_watch_callback[use_name])))
            for name in self.so_watch_callback[use_name]:
                if name == 'NONE':
                    self.lgr.debug('soMap checkSOWatch do callback for %s but name is NONE????' % use_name)
                    self.so_watch_callback[use_name][name](load_addr)
                else:
                    # pass the load address to the callback
                    self.lgr.debug('soMap checkSOWatch do callback for %s, name %s' % (use_name, name))
                    self.so_watch_callback[use_name][name](load_addr, name)

    def setProgStart(self, dumb=None):
        cpu, comm, tid = self.task_utils.curThread() 
        text_entry = self.top.getEIP()
        if tid in self.prog_start and self.prog_start[tid] is not None:
            self.lgr.debug('soMap setProgStart tid %s already in prog_start' % tid)
        else:
            prog = self.text_prog[tid]
            text_start = text_entry - self.prog_info[prog].text_offset
            self.prog_start[tid] = text_start
            self.prog_end[tid] = self.prog_info[prog].text_end + text_start
            self.lgr.debug('soMap setProgStart tid %s set prog_start 0x%x end 0x%x' % (tid, self.prog_start[tid], self.prog_end[tid]))

    def getLoadInfo(self, tid=None):
        # get load information for a tid program.
        # TBD assumes not ASLR
        load_info = None
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        #if tid in self.prog_start and self.prog_start[tid] is not None:
        if tid in self.text_prog:
            prog = self.text_prog[tid]
            if tid in self.prog_start and self.prog_start[tid] is not None:
                size = self.prog_end[tid] - self.prog_start[tid] + 1 
                load_info = LoadInfo(self.prog_start[tid], size, interp=self.prog_info[prog].interp)
            elif prog in self.prog_info:
                size = self.prog_info[prog].text_size
                load_info = LoadInfo(None, size, interp=self.prog_info[prog].interp)
           
        return load_info

    def fullProg(self, prog_in):
        # if the given prog_in is a basename, use a prog_base_map to return the full path
        prog = None
        if prog_in is not None and '/' not in prog_in:
            if prog_in in self.prog_base_map:
                prog = self.prog_base_map[prog_in] 
            
            else:
                # may be call from readReplace or jumper
                self.lgr.debug('soMap fullProg called for %s, but not in prog_base_map' % prog_in)
        else:
            prog = prog_in
        return prog

    def getLoadOffset(self, prog_in, tid=None):
        retval = None
        prog = self.fullProg(prog_in)
        if prog is None:
            self.lgr.error('soMap getLoadOffset got None from fullProg for %s' % prog_in)
            return None
        if tid is None:
            cpu, comm, tid = self.task_utils.curThread() 
        tid = self.getSOTid(tid)
        if tid in self.text_prog:
            self.lgr.debug('soMap getLoadOffset tid is %s len prog_start %d prog_in %s prog %s text_prog %s' % (tid, len(self.prog_start), prog_in, prog, self.text_prog[tid]))
        else:
            self.lgr.debug('soMap getLoadOffset tid is %s not in text_prog' % (tid))
        if tid in self.prog_start:
           self.lgr.debug('tid %s in prog_start and text_prog[tid] is %s' % (tid, self.text_prog[tid]))
           
        else:
           self.lgr.debug('tid %s not in prog_start' % tid)
        maybe_image_base = self.getImageBase(prog_in)
        maybe_load_addr = self.getLoadAddr(prog_in)
        if tid in self.text_prog and tid in self.prog_start and self.text_prog[tid] == prog_in:
            load_addr = self.prog_start[tid]
            if prog in self.prog_info:
                if self.prog_info[prog].text_start > 0:
                    image_base =  self.prog_info[prog].text_start - self.prog_info[prog].text_offset
                    retval = load_addr - image_base
                    #self.lgr.debug('soMap getLoadOffset return offset %d based on load_addr 0x%x image_base 0x%x text_start 0x%x textoffset 0x%x' % (retval, load_addr,
                    #     image_base, self.prog_info[prog].text_start, self.prog_info[prog].text_offset))
                else:
                    retval = load_addr
            else:
                self.lgr.error('soMap getLoadOffset prog %s not in prog_info' % prog)
        elif maybe_image_base is not None and maybe_load_addr is not None:
            retval = maybe_load_addr - maybe_image_base
            self.lgr.debug('soMap getLoadOffset using image_base from getImageBase got retval 0x%x' % retval)
        else:
            self.lgr.debug('soMap getLoadOffset tid %s not somewhere, use getLoadAddr? ' % (tid))
            #if tid in self.text_prog:
            #    self.lgr.debug('soMap getLoadOffset text_prog[%s] is %s and prog_in is %s' % (tid, self.text_prog[tid], prog_in))
            retval = self.getLoadAddr(prog, tid)
        return retval

    def getCodeSections(self, tid):
        retval = []
        tid = self.getSOTid(tid)
        size = self.prog_end[tid] - self.prog_start[tid] + 1
        if tid in self.prog_start:
            code_section = CodeSection(self.prog_start[tid], size, self.text_prog[tid])
            retval.append(code_section)
            if tid in self.so_file_map: 
                for load_info in self.so_file_map[tid]:
                    code_section = CodeSection(load_info.addr, load_info.size, self.so_file_map[tid][load_info])
                    retval.append(code_section) 
        return retval

    def findCodeSection(self, tid, name):
        retval = None
        tid = self.getSOTid(tid)
        name = name.lower()
        if tid in self.so_file_map: 
            for load_info in self.so_file_map[tid]:
                if self.so_file_map[tid][load_info].lower().endswith(name):
                    retval = CodeSection(load_info.addr, load_info.size, self.so_file_map[tid][load_info])
                    break 
        return retval

    def getProgSize(self, prog_in):
        prog = self.fullProg(prog_in)
        if prog in self.prog_info:
            return self.prog_info[prog].text_size + self.prog_info[prog].text_offset

    def rmTask(self, tid):
        if tid in self.so_file_map:
            del self.so_file_map[tid]
            self.lgr.debug('soMap rmTask so_file_map for tid %s' % tid)
            self.so_file_map[tid] = {}

        if tid in self.so_addr_map:
            del self.so_addr_map[tid]
            self.lgr.debug('soMap rmTask so_addr_map for tid %s' % tid)
            self.so_addr_map[tid] = {}
        self.cheesy_tid = 0

    def checkClibAnalysis(self, tid):
        sofile = 'logs/somap-%s.somap' % tid
        self.lgr.debug('soMap checkClibAnalysis tid:%s sofile %s' % (tid, sofile))
        retval = False
        if not os.path.isfile(sofile):
            self.showSO(tid, save=True)
            retval = missingDLLAnalysis.checkMissingDLLs(None, sofile, self.lgr, root_prefix=self.root_prefix, generate=False)
            self.lgr.debug('soMap checkClibAnalysis tid:%s created sofile, result is %r' % (tid, retval))
        else:
            retval = True
        return retval
