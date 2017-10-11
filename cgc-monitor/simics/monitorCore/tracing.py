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

import simics
import os
import shutil
import memUtils
import decode
from simics import *
'''
Trace instructions/data of a specific process.  Uses (slow) mode Haps.
TBD remove need for mode hap and just catch entry into the kernel
TBD permit trace of multiple sessions at once
'''
class tracing():
    tracer = None
    def __init__(self, top, master_config, os_p_utils, zk, cfg, lgr, logdir):
        self.i_trace = None 
        self.trace_pid = None 
        self.szk = zk
        self.cfg = cfg
        self.lgr = lgr
        self.top = top
        self.os_p_utils = os_p_utils
        self.logdir = logdir
        self.__mode_changed = None
        # default log dir, cb tracing will alter this
        self.outfile = {}
        outfile = logdir+'/traces/trace.txt'
        if master_config.trace_target is not None or master_config.trace_cb:
            if master_config.trace_target:
                self.i_trace = master_config.trace_target
                self.lgr.debug('tracing init will trace %s' % self.i_trace)
            self.lgr = lgr
            try:
                os.mkdir(logdir+'/traces')
            except:
                pass
            cmd = 'log-setup -no-console -time-stamp -overwrite logfile = %s' % outfile
            SIM_run_command(cmd)
        #self.tracer = SIM_run_command('new-tracer')
        #cmd = '%s.stop' % self.tracer
        #SIM_run_command(cmd)

    def isTraced(self, comm, pid):
        if comm == self.i_trace or pid == self.trace_pid:
            return True
        else:
            tmp = comm.rsplit('_', 1)[0]
            if tmp == self.i_trace:
                return True
            else:
                return False

    def closeTrace(self, pid, cell_name):
        self.i_trace = None
        if self.__mode_changed is not None:
            SIM_hap_delete_callback_id("Core_Mode_Change", self.__mode_changed)
            self.__mode_changed = None

    ''' only do copy if this is a CB with a replay '''
    # TBD not currently used
    def copyTrace(self, replay):
        replay_dir = self.szk.replayPathFromName(self.cfg.cb_dir, replay)
        if replay_dir is not None:
            parent = os.path.dirname(replay_dir)
            try:
                shutil.copyfile(self.outfile, parent+'/trace.txt')
                self.lgr.debug('tracing copied trace from %s to %s' % (self.outfile, parent+'/trace.txt'))
            except IOError:
                self.lgr.error('could not copy trace file to %s/trace.txt' % parent)
            self.i_trace = None
        

    def createTracer(self, comm):
        #if self.tracer is None:
        self.tracer = SIM_run_command('new-tracer')
        SIM_run_command('untrace-exception -all')
        self.lgr.debug('created tracer %s for %s' % (self.tracer, comm))
    '''
    def getCount(self):
        cmd = '%s.get_count' % self.tracer
        return SIM_run_command(cmd)
    '''

    def modeChanged(self, cpu, one, old, new):
        if self.__mode_changed is None:
            return
        cell_name = self.top.getTopComponentName(cpu)
        cpu, cur_addr, comm, pid = self.os_p_utils[cell_name].getPinfo(cpu)
        #self.lgr.debug('modeChanged %d %s' % (pid, comm))
        if self.isTraced(comm, pid):
            # force comm, may not be updated in proc utils
            comm = self.i_trace
            cpl = memUtils.getCPL(cpu)
            if cpl == 0:
                cmd = '%s.stop' % self.tracer
                SIM_run_alone(SIM_run_command, cmd)
                self.lgr.debug('stopped tracing %s' % comm)
                if True:
                    eip = self.top.getEIP(cpu)
                    instruct = SIM_disassemble_address(cpu, eip, 1, 0)
                    if decode.getMn(instruct[1]) == 'jmp':
                        op1, op0 = decode.getOperands(instruct[1])
                        eip_str = '0x%x' % eip
                        self.lgr.debug('modeChanged jmp is %s eip_str is <%s> op0 is <%s>' % (instruct[1], eip_str, op0))
                        if op0 == eip_str:
                            self.closeTrace(cell_name, pid) 
                            self.lgr.debug('modeChanged, found ebfe, stop tracing')
                            return
            else:
                if self.tracer is None:
                    SIM_run_alone(self.createTracer, comm)
                    self.lgr.debug('created tracer for %s' % comm)
                else:
                    outfile = self.outfile[comm]
                    cmd = '%s.start file=%s' % (self.tracer, outfile)
                    SIM_run_alone(SIM_run_command, cmd)
                self.lgr.debug('start tracing %s' % comm)

    def startTrace(self, comm, pid, cpu, replay=None, use_outfile=None):
        if replay is not None:
            cb_dir = self.logdir+'/traces/'+comm
            try:
                os.makedirs(cb_dir)
            except:
                pass
            base = os.path.basename(replay)
            just_file = os.path.splitext(base)[0]
            outfile = cb_dir+'/'+just_file+'.txt'
            try:
                os.remove(outfile)
            except:
                pass
            self.lgr.debug('will start tracing %s pid:%d for replay: %s outfile is %s' % (comm, pid, replay, outfile))
            new_comm = comm.rsplit('_', 1)[0]
            if new_comm != self.i_trace:
                self.outfile = {}
                self.i_trace = comm.rsplit('_', 1)[0]
        else:
            self.i_trace = comm
            self.trace_pid = pid
            self.outfile = {}
            if use_outfile is None:
                outfile = '/tmp/trace_%s.txt' % comm
                if comm in self.outfile and outfile != self.outfile[comm]:
                    ''' hack to reset instruction counters '''
                    cmd = '%s.start file=dog_tail.log' % (self.tracer)
                    SIM_run_alone(SIM_run_command, cmd)
                    cmd = '%s.stop' % (self.tracer)
                    SIM_run_alone(SIM_run_command, cmd)
            else:
                outfile = use_outfile

            self.lgr.debug('will start tracing %s pid:%d outfile %s' % (comm, pid, outfile))
        self.outfile[comm] = outfile
        if self.__mode_changed is None:
            self.lgr.debug('set the mode hap to trace')
            #SIM_run_alone(self.createTracer, comm)
            self.__mode_changed = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0,
                    self.modeChanged, cpu)

    def getOutfile(self, comm):            
        if comm in self.outfile:
           outfile = self.outfile[comm]
           return outfile
        else:
           return None
    # not currently used 
    def returnTo(self, comm, pid):
        return
        if self.isTraced(comm, pid):
            #print 'returning to %s pid:%d' % (comm, pid)
            cmd = '%s.start file=%s' % (self.tracer, self.outfile)
            SIM_run_alone(SIM_run_command, cmd)
            #self.lgr.debug('started tracing %s' % comm)
            return True
        return False

    # not currently used 
    def intoKernel(self, comm, pid):
        return
        if self.isTraced(comm, pid):
            cmd = '%s.stop' % self.tracer
            SIM_run_alone(SIM_run_command, cmd)
            #print 'intoKernel for %s pid:%d' % (comm, pid)
