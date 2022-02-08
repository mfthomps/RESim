import os
import time
import logging
import subprocess
try:
    import cli
    from simics import *
except:
    ''' Not always called from simics context '''
    pass
def getLogger(name, logdir, level=None):
    os.umask(000)
    try:
        os.makedirs(logdir)
    except:
        pass
    lgr = logging.getLogger(name)
    #lhStdout = lgr.handlers[0]
    lgr.setLevel(logging.DEBUG)
    fh = logging.FileHandler(logdir+'/%s.log' % name)
    fh.setLevel(logging.DEBUG)
    frmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(frmt)
    lgr.addHandler(fh)
    #lgr.removeHandler(lhStdout)
    lgr.info('Start of log from %s.py' % name)
    ch = logging.StreamHandler()
    ch.setLevel(logging.ERROR)
    ch.setFormatter(frmt)
    lgr.addHandler(ch)
    #lgr.propogate = False
    return lgr

def rprint(string):
    rl = SIM_get_object('RESim_log')
    SIM_log_info(1, rl, 0, string)

def skipToTest(cpu, cycle, lgr):
        while SIM_simics_is_running():
            lgr.error('skipToTest but simics running')
            time.sleep(1)
        retval = True
        cli.quiet_run_command('pselect %s' % cpu.name)
        cmd = 'skip-to cycle = %d ' % cycle
        cli.quiet_run_command(cmd)
        now = cpu.cycles
        if now != cycle:
            lgr.error('skipToTest failed wanted 0x%x got 0x%x' % (cycle, now))
            time.sleep(1)
            cli.quiet_run_command(cmd)
            now = cpu.cycles
            if now != cycle:
                lgr.error('skipToTest failed again wanted 0x%x got 0x%x' % (cycle, now))
                retval = False
        return retval

def getFree():
    cmd = "free"
    ps = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = ps.communicate()
    use_available = False
    for line in output[0].decode("utf-8").splitlines():
         if 'available' in line:
             use_available = True
         if line.startswith('Mem:'):
             parts = line.split()
             tot = int(parts[1])
             if use_available:
                 free = int(parts[6])
             else:
                 free = int(parts[3])
             #print('tot %s   free %s' % (tot, free))             
             percent = (free / tot) * 100
             return int(percent)
    return None
