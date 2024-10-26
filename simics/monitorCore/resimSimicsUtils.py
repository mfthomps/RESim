import memUtils
import cli
from simics import *
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
            print('resimUtils disconnectService node failed')
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

