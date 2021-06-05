from simics import *
class InstructTrace():
    def __init__(self, top, lgr, fname):
        self.top = top
        self.lgr = lgr
        SIM_run_command('load-module trace')
        tracer_name = SIM_run_command('new-tracer')
        self.tracer = SIM_get_object(tracer_name)
        tfile = '/tmp/%s' % fname
        #cmd = 'output-file-start %s' % tfile
        cmd = 'start-command-line-capture %s' % tfile
        SIM_run_command(cmd)
        pid = self.top.getPID()
        cpu = self.top.getCPU()
        self.mode_hap = SIM_hap_add_callback_obj("Core_Mode_Change", cpu, 0, self.modeChanged, pid)

    def start(self,dumb=None):
        pid = self.top.getPID()
        self.lgr.debug('starting pid is %d' % pid)
        self.tracer.cli_cmds.start()

    def stop(self,dumb=None):
        pid = self.top.getPID()
        self.lgr.debug('stopping pid is %d' % pid)
        self.tracer.cli_cmds.stop()

    def endTrace(self):
        cmd = 'output-file-stop'
        SIM_run_command(cmd)

    def modeChanged(self, want_pid, one, old, new):
        this_pid = self.top.getPID()
        if want_pid != this_pid:
            #self.lgr.debug('mode changed wrong pid, wanted %d got %d' % (want_pid, this_pid))
            return
        cpl = self.top.getCPL()
        if new == Sim_CPU_Mode_Supervisor:
            SIM_run_alone(self.stop, None)
        else:
            SIM_run_alone(self.start, None)
