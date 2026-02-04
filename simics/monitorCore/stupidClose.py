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
'''
Detect brute force closing of all (or many) file descriptors and suspend
tracing for the TID until finished.
'''
import os
import coverage
import resimUtils
from simics import *
from resimHaps import *
class StupidClose():
    def __init__(self, top, cpu, cell_name, mem_utils, task_utils, soMap, context_manager, lgr):
        self.top = top
        self.cpu = cpu
        self.cell_name = cell_name
        self.mem_utils = mem_utils
        self.task_utils = task_utils
        self.soMap = soMap
        self.context_manager = context_manager
        self.lgr = lgr
        self.fail_count = {}
        self.last_failed_tid = {}
        self.last_failed_fd = {}
        self.coverage = None
        self.pending_escape = []
        self.hit_list = []
        self.blocks = {}
        #self.escape_hap = None
        #self.escape_bp = []
        self.escape_list = []
        self.bb = None
        self.prog_name = None
        self.prog_comm = None
        self.coverage_tid = None
        self.stupid_closers = resimUtils.getListFromComponentFile(top, cell_name, 'STUPID_CLOSERS', lgr)

    def closeFail(self, tid, comm, fd):
        if comm not in self.stupid_closers:
            return
        self.lgr.debug('stupidClose closeFail tid:%s fd:%d.' % (tid, fd))
        if self.prog_comm is not None and comm != self.prog_comm:
            self.lgr.debug('stupidClose closeFail only supports stupid closing from one program.  fix this')
            return
        if tid in self.pending_escape:
            # This tid already had enough failures and we've been collecting BB hits
            # in self.hit_list.  Call findEscape to locate the escape branch.
            self.pending_escape.remove(tid)
            self.coverage.disableAll()
            self.findEscape()
            #SIM_break_simulation('stupidClose pending escape for tid:%s' % tid)
        elif tid not in self.fail_count:
            self.fail_count[tid] = 1
            self.last_failed_fd[tid] = fd
        else:
            expected = self.last_failed_fd[tid] + 1
            if fd != expected:
                self.lgr.error('stupidClose closeFail tid:%s expected fd: %d got %d' % (tid, expected, fd))
                del self.fail_count[tid]
                del self.last_failed_fd[tid]
                return 
            self.last_failed_fd[tid] = expected
            self.fail_count[tid] = self.fail_count[tid] + 1
            if self.fail_count[tid] > 5:
                self.lgr.debug('stupidClose closeFail tid:%s fd:%d fail count %d, escape.' % (tid, fd, self.fail_count[tid]))
                if self.coverage is None: 
                    self.top.stopAndGo(self.setCoverage)
                else:
                    self.lgr.debug('stupidClose already have coverage')
                    self.coverage.enableAll()
                del self.fail_count[tid]
                del self.last_failed_fd[tid]
                self.pending_escape.append(tid)

    def setCoverage(self):
        cpu, comm, tid = self.task_utils.curThread()
        self.lgr.debug('stupidClose setCoverage tid:%s comm %s' % (tid, comm))
        self.prog_name = self.top.getProgName(tid)
        self.prog_comm = comm
        self.coverage_tid = tid
        analysis_path = self.soMap.getAnalysisPath(self.prog_name)
        ida_path = self.top.getIdaData(self.prog_name)
        if ida_path is not None: 
            analysis_path = self.soMap.getAnalysisPath(self.prog_name)
            self.lgr.debug('stupidClose setCoverage comm %s prog_name %s analysis path %s ida_path %s' % (comm, self.prog_name, analysis_path, ida_path))
            self.coverage = coverage.Coverage(self.top, self.prog_name, analysis_path, ida_path, self.context_manager, 
                           self.cell_name, self.soMap, self.mem_utils, self.cpu, None, self.lgr)
            self.lgr.debug('stupidClose setCoverage back from coverage')
            self.coverage.enableCoverage(tid)
            self.coverage.setAlternateCallback(self.bbHap)
            self.coverage.doCoverage()
            self.indexBlocks()
            SIM_run_alone(SIM_continue, 0)
        else:
            self.lgr.error('ida_path failed for prog %s' % self.prog_name)

    def indexBlocks(self):
        blocks = self.coverage.getBlocks()
        for fun in blocks:
            for bb in blocks[fun]['blocks']:
                #self.lgr.debug('bb 0x%x' % bb['start_ea'])
                self.blocks[bb['start_ea']] = bb
                #for branch in bb['succs']:

    def bbHap(self, logical):
        '''  Hit when a bb is reached.  
        '''
        cpu, comm, tid = self.task_utils.curThread()
        self.lgr.debug('stupidClose bbHap tid:%s logical 0x%x' % (tid, logical))
        if len(self.escape_list) > 0:
            # we have escaped
            self.lgr.debug('bbHap we have escaped')
            self.context_manager.rmSuspendWatch()
            self.escape_list = []
        else: 
            self.lgr.debug('bbHap addr 0x%x' % logical)
            self.hit_list.append(logical)


    def findEscape(self):
        ''' We've collected the bb's hit since the failed close and we now hit another close '''
        cpu, comm, tid = self.task_utils.curThread()
        self.lgr.debug('stupidClose findEscape tid:%s' % tid)
        # assume last hit is syscall
        self.escape_list = []
        for bb in self.hit_list[:-1]:
            if bb in self.blocks:        
                self.lgr.debug('stupidClose findEscape found block info for 0x%x' % bb)
                bb_info = self.blocks[bb]
                for branch in bb_info['succs']:
                    if branch not in self.hit_list:
                        self.lgr.debug('stupidClose findEscape branch 0x%x looks like an escape' % branch)
                        self.escape_list.append(branch) 
                    else:
                        self.lgr.debug('stupidClose findEscape branch 0x%x is in our hit list' % branch)

            else:
                self.lgr.error('stupidClose failed to find findExcape block info for 0x%x' % bb)
        if len(self.escape_list) > 0:
            self.lgr.debug('stupidClose findEscape call setEscapeBreaks')
            self.context_manager.addSuspendWatch()
            SIM_run_alone(self.setEscapeBreaks, None)
        else:
            self.lgr.debug('stupidClose no escapes!')
        self.hit_list = []

    def setEscapeBreaks(self, dumb):
        self.lgr.debug('stupidClose setEscapeBreaks')
        self.coverage.disableAll()

        for bb in self.escape_list:
            self.coverage.enableForBB(bb)
            self.lgr.debug('stupidClose setEscapeBreak for bb 0x%x' % bb) 


