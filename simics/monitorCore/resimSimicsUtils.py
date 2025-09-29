import memUtils
import cli
from simics import *
import time
import subprocess
import shlex
def fdString(fd):
    if memUtils.isNull(fd):
        return 'NULL'
    elif fd == 0xffffff9c:
        return 'AT_FD_CWD'
    elif fd == 0xffffffffffffff9c:
        return 'AT_FD_CWD'
    else:
        return '%d' % fd

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

def skipToTest(cpu, cycle, lgr, disable_vmp=False):
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
        already_disabled = False
        retval = True
        if disable_vmp:
            cli.quiet_run_command('pselect %s' % cpu.name)
            result=cli.quiet_run_command('disable-vmp')
            lgr.debug('skipToTest disable-vmp result %s' % str(result))
            already_disabled = False
            if 'VMP already disabled' in result[1]:
                already_disabled = True
        
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

        if disable_vmp:
            if not already_disabled:
                try:
                    cli.quiet_run_command('enable-vmp')
                #except cli_impl.CliError:
                except:
                    pass

        return retval

def disconnectServiceNode(name):
        cmd = '%s.status' % name
        try:
            dumb,result = cli.quiet_run_command(cmd)
        except:
            #print('resimSimicsUtils disconnectService node failed on cmd %s' % cmd)
            return
       
        ok = False 
        for line in result.splitlines():
            if 'connector_link0' in line:
                parts = line.split(':')
                node_connect = parts[0].strip()
                switch = parts[1].strip()
                cmd = '%s.status' % switch
                dumb,result = cli.quiet_run_command(cmd)
                for line in result.splitlines():
                    if name in line:
                        switch_device = line.split(':')[0].strip()
                        cmd = 'disconnect %s.%s %s.%s' % (name, node_connect, switch, switch_device)
                        dumb,result = cli.quiet_run_command(cmd)
                        cmd = '%s.disable-service -all' % name
                        dumb,result = cli.quiet_run_command(cmd)
                        ok = True
                        break
                break
        #cmd = '%s.delete' % name
        #print('did disconnect, now delete')
        #dumb,result = cli.quiet_run_command(cmd)
        #print('did delete')


def serviceNodeConnected(name, lgr=None):
        retval = False
        cmd = '%s.status' % name
        #if lgr is not None:
        #    lgr.debug('resimSimicsUtils serviceNodeConnected cmd: %s' % cmd)
        try:
            dumb,result = cli.quiet_run_command(cmd)
        except:
            #print('resimSimicsUtils disconnectService node failed on cmd %s' % cmd)
            return False
       
        #lgr.debug('resimSimicsUtils serviceNodeConnected result: %s' % result)
        ok = False 
        for line in result.splitlines():
            if 'connector_link0' in line:
                parts = line.split(':')
                node_connect = parts[0].strip()
                switch = parts[1].strip()
                cmd = '%s.status' % switch
                dumb,result = cli.quiet_run_command(cmd)
                for line in result.splitlines():
                    if name in line:
                        #lgr.debug('resimSimicsUtils serviceNodeConnected found name %s' % name)
                        retval = True
                        break
                break
        return retval

def cutRealWorld():
    driver_service_node = 'driver_service_node'
    dhcp_service_node = 'dhcp_service_node'
    cmd = 'disconnect-real-network'
    SIM_run_command(cmd)
    cmd = 'switch0.disconnect-real-network'
    SIM_run_command(cmd)
    cmd = 'switch1.disconnect-real-network'
    SIM_run_command(cmd)
    disconnectServiceNode(driver_service_node)
    try:
        disconnectServiceNode(dhcp_service_node)
    except:
        pass

def getFrequencyc(cpu):
    name = cpu.name
    cmd = '%s.status' % name
    result = cli.quiet_run_command(cmd)[1]
    pparts = result.split(':')
    freq_s = pparts[1].split()[0]
    #print('freq: %s' % freq_s)
    freq = float(freq_s) 
    #print('freq is %f.2 mhz' % freq)
    return freq

def getMemoryUsed():
    pid = cli.quiet_run_command('pid')[0]
    
    retval = None
    cmd = 'cat /proc/%s/statm' % pid
    with subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as ps:
        output = ps.communicate()[0]
        out_string = output.split()[0]
        retval = int(out_string) * 4096 

    return retval


def timer(cpu, cycles):
    mem_start = getMemoryUsed()
    print('mem_start  %s' % f"{mem_start:,}")

    frequency = getFrequencyc(cpu)
    parts = cli.quiet_run_command('date -t')
    start_time = parts[0]
    start_cycle = cpu.cycles
    SIM_continue(cycles)
    parts = cli.quiet_run_command('date -t')
    end_time = parts[0]
    end_cycle = cpu.cycles
    delta_time = end_time - start_time
    #print('timer ran 0x%x cycles in %f.2 seconds' % (cycles, delta))
    delta_sim_time = cycles / (frequency * 1000000)
    mem_end = getMemoryUsed()
    ram_use = mem_end - mem_start
    print('sim time is %f' % delta_sim_time)
    return delta_time, delta_sim_time, ram_use

def version():
    parts = cli.quiet_run_command('version')
    version = parts[0][0][2]
    return version
            
def setBreakpointPrefix(conf, bp, prefix):
    retval = False
    index = 0
    for item in conf.sim.breakpoints:
        if item[0] == bp:
            retval = True
            conf.sim.attr.breakpoints[index][7] = prefix
            break
        index = index + 1
    return retval

def setBreakpointSubstring(conf, bp, substring):
    retval = False
    index = 0
    for item in conf.sim.breakpoints:
        if item[0] == bp:
            retval = True
            conf.sim.attr.breakpoints[index][8] = substring
            break
        index = index + 1
    return retval

def transType(op_type):
    retval = 'unknown'
    if op_type == Sim_Trans_Load:
        retval = 'load'
    elif op_type == Sim_Trans_Store:
        retval = 'store'
    elif op_type == Sim_Trans_Instr_Fetch:
        retval = 'instr_fetch'
    elif op_type == Sim_Trans_Pefetch:
        retval = 'instr_prefetch'
    elif op_type == Sim_Trans_Cache:
        retval = 'instr_cache'
    return retval
