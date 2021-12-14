import os
import logging
from simics import *
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
