import os
import sys
import time
import logging
import subprocess
import imp 
import elfText
import json
try:
    import cli
    from simics import *
except:
    ''' Not always called from simics context '''
    pass
try:
    import importlib
except:
    ''' must be py 2.7 '''
    pass

def getLogger(name, logdir, level=None):
    os.umask(000)
    try:
        os.makedirs(logdir)
    except:
        pass

    log_level = logging.DEBUG
    log_level_env = os.getenv('RESIM_LOG_LEVEL')
    if log_level_env is not None and log_level_env.lower() == 'info':
        log_level = logging.INFO
        
    lgr = logging.getLogger(name)
    #lhStdout = lgr.handlers[0]
    lgr.setLevel(log_level)
    fh = logging.FileHandler(logdir+'/%s.log' % name)
    fh.setLevel(log_level)
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

def reverseEnabled():
        cmd = 'sim.status'
        #cmd = 'sim.info.status'
        dumb, ret = cli.quiet_run_command(cmd)
        rev = ret.find('Reverse Execution')
        after = ret[rev:]
        parts = after.split(':', 1)
        if parts[1].strip().startswith('Enabled'):
            return True
        else:
            return False

def skipToTest(cpu, cycle, lgr):
        limit=100
        count = 0
        while SIM_simics_is_running() and count<limit:
            lgr.error('skipToTest but simics running')
            time.sleep(1)
            count = count+1
                
        if count >= limit:
            return False
        if not reverseEnabled():
            lgr.error('Reverse execution is disabled.')
            return False
        retval = True
        cli.quiet_run_command('pselect %s' % cpu.name)
        cli.quiet_run_command('disable-vmp')
        cmd = 'skip-to cycle = %d ' % cycle
        cli.quiet_run_command(cmd)
        #cli.quiet_run_command('si')
        #cli.quiet_run_command(cmd)
        
        now = cpu.cycles
        if now != cycle:
            lgr.error('skipToTest failed wanted 0x%x got 0x%x' % (cycle, now))
            time.sleep(1)
            cli.quiet_run_command(cmd)
            now = cpu.cycles
            if now != cycle:
                lgr.error('skipToTest failed again wanted 0x%x got 0x%x' % (cycle, now))
                retval = False
        cli.quiet_run_command('enable-vmp')
        return retval

def getFree():
    cmd = "free"
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as ps:
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

def isParallel():
    ''' Determine if the current workspace is a parallel clone '''
    here = os.getcwd()
    ws = os.path.basename(here)
    if ws.startswith('resim_') and os.path.exists('resim_ctl.fifo'):
        return True
    else:
        return False

def getIdaData(full_path):
    retval = None
    resim_ida_data = os.getenv('RESIM_IDA_DATA')
    if resim_ida_data is None:
        print('ERROR: RESIM_IDA_DATA not defined')
    else: 
        base = os.path.basename(full_path)
        retval = os.path.join(resim_ida_data, base, base)
    return retval

def getProgPath(prog):
    ''' read the .prog file to get the path of the analyzed program, i.e., the program
        whose basic blocks were watched.'''
    ida_path = getIdaData(prog)
    data_path = ida_path+'.prog'
    prog_file = None
    if not os.path.isfile(data_path):
        print('failed to find prog file at %s' % data_path)
    else:
        with open(data_path) as fh:
            lines = fh.read().strip().splitlines()
            prog_file = lines[0].strip()
    return prog_file

def doLoad(packet_filter, path):
    #print('version is %d %d' % (sys.version_info[0], sys.version_info[1]))
    if sys.version_info[0] == 3:
        spec = importlib.util.spec_from_file_location(packet_filter, path)
        retval = importlib.util.module_from_spec(spec)
        sys.modules[packet_filter] = retval
        spec.loader.exec_module(retval)
    else: 
        retval = imp.load_source(packet_filter, path)
    return retval

def getPacketFilter(packet_filter, lgr):
    retval = None
    if packet_filter is not None:
        file_path = './%s.py' % packet_filter
        abs_path = os.path.abspath(file_path)
        if os.path.isfile(abs_path):
            retval = doLoad(packet_filter, abs_path)
            lgr.debug('afl using AFL_PACKET_FILTER %s' % packet_filter)
        else:
            file_path = './%s' % packet_filter
            abs_path = os.path.abspath(file_path)
            if os.path.isfile(abs_path):
                retval = doLoad(packet_filter, abs_path)
                lgr.debug('afl using AFL_PACKET_FILTER %s' % packet_filter)
            else:
                lgr.error('failed to find filter at %s' % packet_filter)
                raise Exception('failed to find filter at %s' % packet_filter)
    return retval

def getBasicBlocks(prog):
    blocks = None
    prog_file = getProgPath(prog)
    prog_elf = None
    if prog_file is not None:
        prog_elf = elfText.getTextOfText(prog_file)
        print('prog addr 0x%x size %d' % (prog_elf.address, prog_elf.size))
        block_file = prog_file+'.blocks'
        print('block file is %s' % block_file)
        if not os.path.isfile(block_file):
            print('block file not found %s' % block_file)
            return
        with open(block_file) as fh:
            blocks = json.load(fh)
    return blocks, prog_elf

def getOneBasicBlock(prog, addr):
    blocks, dumb = getBasicBlocks(prog)
    retval = None
    for fun in blocks:
        for bb in blocks[fun]['blocks']:
            if bb['start_ea'] == addr:
                retval = bb
                break
        if retval is not None:
            break    
    return retval
