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
import cli
import resimSimicsUtils
import os
import json
'''
    Trace instructions, storing results in /tmp/$USER/fname.
    Will also record shared object map for the current process
    for post-processing filtering of low-level libs and trap handling. 
'''
class InstructTrace():
    def __init__(self, top, lgr, fname, all_proc=False, kernel=False, watch_threads=False, just_tid=None, just_kernel=False, all_cores=False, just_comm=None):
        self.top = top
        self.lgr = lgr
        if just_tid is None:
            tid = self.top.getTID()
        else:
            tid = just_tid
        self.just_comm = just_comm
        cpu = self.top.getCPU()
        cell_name = self.top.getTopComponentName(cpu)+'.cell'
        cmd = 'pselect %s' % cpu.name
        dumb, ret = cli.quiet_run_command(cmd)

        #SIM_run_command('add-module-directory path = modules/instrumentation-tracer-tool')
        self.version = resimSimicsUtils.version()
        self.lgr.debug('Simics version is %s' % self.version)
        if self.version.startswith('7'):
            self.use_new_tracer = True
        else:
            self.use_new_tracer = False
        if self.use_new_tracer:
            tracer_name = 'my_tracer'
            file = self.getOutFile(fname)
            if all_cores:
                parent_name = self.top.getTopComponentName(cpu)
                cmd = 'new-tracer-tool name=%s file=%s parent=%s' % (tracer_name, file, parent_name)
            else:
                cmd = 'new-tracer-tool name=%s file=%s processors=%s' % (tracer_name, file, cpu.name)
            SIM_run_command(cmd)
        else:
            SIM_run_command('load-module trace')
            tracer_name = SIM_run_command('new-tracer cell= %s' % cell_name)
        self.tracer = SIM_get_object(tracer_name)
        self.all_proc = all_proc
        self.kernel = kernel
        self.just_kernel = just_kernel
        self.watch_threads = watch_threads
        self.just_tid = just_tid
        print('tracer is %s' % tracer_name)
        
        if not self.use_new_tracer:
            file = self.getOutFile(fname)
            #cmd = 'output-file-start %s' % tfile
            cmd = 'start-command-line-capture %s' % tfile
            #cmd = '%s->file=%s' % (tracer_name, tfile)
            SIM_run_command(cmd)
        print('Starting cycle: 0x%x' % cpu.cycles)
        if just_kernel:
            self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, None)
        elif not kernel:
            self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, tid)
            cpl = self.top.getCPL()
            self.lgr.debug('InstructTrace cpl is %d' % cpl)
            if cpl == 0:
                self.lgr.debug('InstructTrace cpl is zero at start, stop')
                self.stop()
        self.lgr.debug('InstructTrace starting with tid:%s, watch_threads: %r' % (tid, watch_threads))

    def start(self,dumb=None):
        tid = self.top.getTID()
        print('instructTrace starting tid is %s' % tid)
        self.lgr.debug('instructTrace starting tid is %s' % tid)
        if not self.use_new_tracer:
            self.tracer.cli_cmds.start()
        else:
            self.tracer.cli_cmds.enable_instrumentation()

    def stop(self,dumb=None):
        tid = self.top.getTID()
        print('instructTrace stopping tid is %s' % tid)
        self.lgr.debug('instructTrace stopping tid is %s' % tid)
        if not self.use_new_tracer:
            self.tracer.cli_cmds.stop()
        else:
            self.tracer.cli_cmds.disable_instrumentation()

    def endTrace(self):
        if not self.use_new_tracer:
            cmd = 'output-file-stop'
            SIM_run_command(cmd)

    def modeChanged(self, want_tid, one, old, new):
        cpu, comm, this_tid = self.top.curThread() 
        self.lgr.debug('instructTrace mode changed %s' % (this_tid))
        if not self.just_kernel:
            if want_tid != this_tid:
                if self.watch_threads:
                    if not self.top.amWatching(this_tid):
                        self.lgr.debug('instructTrace mode changed wrong tid watching threads, wanted %s got %s' % (want_tid, this_tid))
                        return
                elif not self.all_proc:
                    self.lgr.debug('instructTrace mode changed wrong tid, wanted %s got %s' % (want_tid, this_tid))
                    return
        if self.just_comm is not None:
            if comm != self.just_comm:
                self.lgr.debug('instructTrace modeChanged, comm %s does not match %s' % (comm, self.just_comm))
                self.tracer.disable-instrumentation()
                return
        cpl = self.top.getCPL()
        if not self.just_kernel:
            if new == Sim_CPU_Mode_Supervisor:
                print('into kernel cycle: 0x%x' % cpu.cycles)
                self.lgr.debug('instructTrace into kernel, stop trace')
                SIM_run_alone(self.stop, None)
            else:
                print('return from kernel cycles: 0x%x tid:%s' % (cpu.cycles, this_tid))
                self.lgr.debug('instructTrace out of  kernel, start trace cycles: 0x%x tid:%s' % (cpu.cycles, this_tid))
                SIM_run_alone(self.start, None)

        else:
            if new == Sim_CPU_Mode_Supervisor:
                self.lgr.debug('instructTrace into kernel, start trace')
                SIM_run_alone(self.start, None)
            else:
                self.lgr.debug('instructTrace out of  kernel, stop trace')
                SIM_run_alone(self.stop, None)

    def getOutFile(self, fname):
        user = os.getenv('USER')
        tmpdir = os.path.join('/tmp', user, 'instruct_traces', fname)
        try:
            os.makedirs(tmpdir)
        except: 
            pass

        outfile = os.path.join(tmpdir, fname+'.intrace')
        print('trace will be written to %s' % outfile)
        so_json = self.top.getSOMap(quiet=True)
        out_json = os.path.join(tmpdir, 'somap.json')
        with open(out_json, 'w') as fh:
            fh.write(so_json)

        return outfile
