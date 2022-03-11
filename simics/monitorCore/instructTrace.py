from simics import *
import cli
class InstructTrace():
    def __init__(self, top, lgr, fname, all_proc=False, kernel=False, watch_threads=False):
        self.top = top
        self.lgr = lgr
        pid = self.top.getPID()
        cpu = self.top.getCPU()
        cell_name = self.top.getTopComponentName(cpu)+'.cell'
        cmd = 'pselect %s' % cpu.name
        dumb, ret = cli.quiet_run_command(cmd)

        SIM_run_command('load-module trace')
        tracer_name = SIM_run_command('new-tracer cell= %s' % cell_name)
        self.tracer = SIM_get_object(tracer_name)
        self.all_proc = all_proc
        self.kernel = kernel
        self.watch_threads = watch_threads
        print('tracer is %s' % tracer_name)
        tfile = '/tmp/%s' % fname
        #cmd = 'output-file-start %s' % tfile
        cmd = 'start-command-line-capture %s' % tfile
        #cmd = '%s->file=%s' % (tracer_name, tfile)
        SIM_run_command(cmd)
        print('begin, or what?')
        if not kernel:
            self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, pid)
        self.lgr.debug('InstructTrace starting with pid:%d, watch_threads: %r' % (pid, watch_threads))

    def start(self,dumb=None):
        pid = self.top.getPID()
        print('instructTrace starting pid is %d' % pid)
        self.lgr.debug('instructTrace starting pid is %d' % pid)
        self.tracer.cli_cmds.start()

    def stop(self,dumb=None):
        pid = self.top.getPID()
        print('instructTrace stopping pid is %d' % pid)
        self.lgr.debug('instructTrace stopping pid is %d' % pid)
        self.tracer.cli_cmds.stop()

    def endTrace(self):
        cmd = 'output-file-stop'
        SIM_run_command(cmd)

    def modeChanged(self, want_pid, one, old, new):
        this_pid = self.top.getPID()
        self.lgr.debug('mode changed %d' % (this_pid))
        if want_pid != this_pid:
            if self.watch_threads:
                if not self.top.amWatching(this_pid):
                    self.lgr.debug('mode changed wrong pid watching threads, wanted %d got %d' % (want_pid, this_pid))
                    return
            elif not self.all_proc:
                self.lgr.debug('mode changed wrong pid, wanted %d got %d' % (want_pid, this_pid))
                return
        cpl = self.top.getCPL()
        if new == Sim_CPU_Mode_Supervisor:
            self.lgr.debug('instructTrace into kernel, stop trace')
            SIM_run_alone(self.stop, None)
        else:
            self.lgr.debug('instructTrace out of  kernel, start trace')
            SIM_run_alone(self.start, None)
