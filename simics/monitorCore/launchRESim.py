import os
try:
    import ConfigParser
except:
    import configparser as ConfigParser
RESIM_REPO = os.getenv('RESIM_DIR')
CORE = os.path.join(RESIM_REPO, 'simics/monitorCore')
if CORE not in sys.path:
    #print("using CORE of %s" % CORE)
    sys.path.append(CORE)
import genMonitor
import getKernelParams
import resimUtils
import resimSimicsUtils
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
Intended to be invoked by from a Simics workspace, e.g., via a bash script.
The workspace must contain a configuration file named $RESIM_INI.ini
That ini file must include and ENV section and a section for each
component in the simulation.  
'''

global cgc, gkp, cfg_file
class LinkObject():
    def __init__(self, name):
        self.name = name
        cmd = '%s' % name
        self.obj = SIM_run_command(cmd)
        #print('self.name is %s self.obj is %s' % (self.name, self.obj))

def doEthLink(target, eth, lgr):
    name = '$%s_%s' % (target, eth)
    cmd = '%s = $%s' % (name, eth)
    lgr.debug('doEthLink cmd %s' % cmd)
    run_command(cmd)
    link_object = LinkObject(name)
    if link_object.obj == 'None':
        lgr.debug('doEthLink object None for name %s' % name)
        return None
    return link_object
    
def doSwitch(target, switch, device, lgr):
    ''' TBD test on Simics 4 '''
    #return None
    name = '$%s_%s' % (target, switch)
    #cmd = '%s = $%s_con' % (name, switch)
    cmd = '%s = %s' % (name, device)
    lgr.debug('doswitch cmd %s' % cmd)
    run_command(cmd)
    link_object = LinkObject(name)
    return link_object
    
def assignLinkNames(target, comp_dict, lgr):
    class LinkInfo():
        def __init__(self, index):
            self.eth = 'eth%d' % index
            self.sw = 'switch%d' % index
            self.mac = '$mac_address_%d' % index
    links = []
    for i in range(4):
         links.append(LinkInfo(i))
   
    link_names = {}
    for link in links:
        if link.mac not in comp_dict:
            lgr.debug('*************** assingLinkNames link.mac %s not in comp_dict' % link.mac)
            continue
        if comp_dict[link.mac] != 'None':
            obj = doEthLink(target, link.eth, lgr)
            if obj is not None: 
                link_names[link.eth] = obj
            else:
                lgr.debug('*******assingLinkNames got None object from doEthLink for %s' % str(link.eth))
        else:
            lgr.debug('*******assingLinkNames link.mac is None for %s' % str(link))
    return link_names

def addSwitchLinkNames(target, comp_dict, link_names, switch_map, lgr):
    class LinkInfo():
        def __init__(self, index):
            self.eth = 'eth%d' % index
            self.sw = 'switch%d' % index
            self.mac = '$mac_address_%d' % index
    links = []
    for i in range(4):
         links.append(LinkInfo(i))
    index = 0 
    for link in links:
        if link.mac in comp_dict and link.sw in switch_map:
            obj = doSwitch(target, link.sw, switch_map[link.sw], lgr)
            if obj is not None: 
                link_names[link.sw] = obj
        else:
            if link.mac not in comp_dict:
                lgr.debug('Link mac %s not in comp dict *******************' % link.mac)
    return link_names

def doConnect(switch, eth, switch_map, index, lgr):
    lgr.debug('do connect switch %s eth %s' % (switch, eth))
    #cmd = '$%s' % eth
    #dog = run_command(cmd)
    #print('dog is %s' % dog)
    if switch.startswith('v'):
        switch, group = switch.split('-')
        no_vlan = False
        if group.startswith('nv'):
            no_vlan = True
            group = group[2:]
        group = int(group)
        if not no_vlan:
            cmd = '%s.get-free-trunk-connector %d' % (switch, group)
        else:
            cmd = '%s.get-free-connector %d' % (switch, group)
    else:
        cmd = '%s.get-free-connector' % switch
    lgr.debug('doConect cmd is %s' % cmd)
    con  = run_command(cmd)
    eth_name = run_command('$%s' % eth)
    lgr.debug('eth name %s' % eth_name)
    if 'i82546bg' in eth_name:
        eth_name = eth_name+'[0]'
    cmd = 'connect $%s cnt1 = %s' % (eth, con)
    cmd = 'connect %s cnt1 = %s' % (eth_name, con)
    lgr.debug('doConnect cmd: %s' % cmd)
    run_command(cmd)
    switch_n = 'switch%d' % index
    lgr.debug('adding %s to map as %s' % (switch_n, con))
    switch_map[switch_n] = con

def linkSwitches(target, comp_dict, link_names, lgr):
    lgr.debug('linkSwitches link_names are %s' % str(link_names))
    switch_map = {} 
    if comp_dict['ETH0_SWITCH'] != 'NONE' and 'eth0' in link_names:
        doConnect(comp_dict['ETH0_SWITCH'], 'eth0', switch_map, 0, lgr)
    if comp_dict['ETH1_SWITCH'] != 'NONE' and 'eth1' in link_names:
        doConnect(comp_dict['ETH1_SWITCH'], 'eth1', switch_map, 1, lgr)
    if comp_dict['ETH2_SWITCH'] != 'NONE' and 'eth2' in link_names:
        doConnect(comp_dict['ETH2_SWITCH'], 'eth2', switch_map, 2, lgr)
    if comp_dict['ETH3_SWITCH'] != 'NONE' and 'eth3' in link_names:
        doConnect(comp_dict['ETH3_SWITCH'], 'eth3', switch_map, 3, lgr)
    return switch_map

def expandValue(value): 
    if value.startswith('$'):
        if os.path.sep in value:
            env_var, rest = value.split(os.path.sep,1)
            expanded = os.getenv(env_var[1:])
            if expanded is None:
                print('ERROR***** Could not expand %s' % value)
                return None
            value = os.path.join(expanded, rest)
        else:
            value = os.getenv(value[1:])
    return value
   
def createDict(config, not_a_target, lgr): 
    comp_dict = {}
    if config.has_section('driver'):
        comp_dict['driver'] = {}
        for name, value in config.items('driver'):
            comp_dict['driver'][name] = value
    for section in config.sections():
        if section in not_a_target and section != 'driver':
            continue
        comp_dict[section] = {}
        #print('assign %s CLI variables' % section)
        lgr.debug('assign %s CLI variables' % section)
        ''' hack defaults, Simics CLI has no undefine operation '''
        comp_dict[section]['ETH0_SWITCH'] = 'switch0'
        comp_dict[section]['ETH1_SWITCH'] = 'switch1'
        comp_dict[section]['ETH2_SWITCH'] = 'switch2'
        comp_dict[section]['ETH3_SWITCH'] = 'switch3'
        for name, value in config.items(section):
            #lgr.debug('name %s value %s' % (name, value))
            value = expandValue(value)
            if value is None:
                continue
            comp_dict[section][name] = value
    return comp_dict

def checkVLAN(config):
    did_these = []
    for name, value in config.items('ENV'):
        if name.startswith('VLAN_'):
            print('GOT VLAN %s' % name)
            num = int(name.split('_')[1])
            if num not in did_these:
                cmd = 'create-ethernet-vlan-switch vswitch%d' % num
                print('checkVLAN cmd: %s' % cmd)
                run_command(cmd)
                did_these.append(num)
            value = int(value)
            cmd = 'vswitch%d.add-vlan %d' % (num, value)
            run_command(cmd)

class LaunchRESim():
    def __init__(self):
        global cgc, gkp, cfg_file
        print('Launch RESim')
        lgr = resimUtils.getLogger('launchResim', './logs', level=None)
        SIMICS_WORKSPACE = os.getenv('SIMICS_WORKSPACE')
        lgr.debug('Start of log from LaunchRESim workspace %s  ONE_DONE_SCRIPT: %s' % (SIMICS_WORKSPACE, os.getenv('ONE_DONE_SCRIPT')))
        RESIM_INI = os.getenv('RESIM_INI')
        self.config = ConfigParser.ConfigParser()
        config_command = None
        #self.config = ConfigParser.RawConfigParser()
        self.config.optionxform = str
        if not RESIM_INI.endswith('.ini'):
            ini_file = '%s.ini' % RESIM_INI
        else:
            ini_file = RESIM_INI
        cfg_file = os.path.join(SIMICS_WORKSPACE, ini_file)
        if not os.path.isfile(ini_file):
            print('File not found: %s' % ini_file)
            exit(1)
        try:
            self.config.read(cfg_file)
        except Exception as e:
            print(e)
            run_command('quit')
        SIMICS_BASE = os.getenv('SIMICS')
        parent = os.path.dirname(SIMICS_BASE)
        print('SIMICS dir is %s' % parent) 
        lgr.debug('SIMICS dir is %s' % parent) 
        #run_command('add-directory -prepend %s/simics-qsp-arm-6.02' % parent)        
        #run_command('add-directory -prepend %s/simics-x86-x58-ich10-6.0.30/targets/x58-ich10/images' % parent)        
        #this does not work.  simics broken?
        cmd = 'add-directory -prepend %s/simics/simicsScripts' % RESIM_REPO
        run_command(cmd)
        run_command('add-directory -prepend %s/simics/monitorCore' % RESIM_REPO)
        run_command('add-directory -prepend %s' % SIMICS_WORKSPACE)

        # hack around broken simics for armv8a
        resim_targets = os.path.join(RESIM_REPO, 'simics', 'simicsScripts', 'targets')
        cmd = '$resim_targets=%s' % resim_targets 
        run_command(cmd)
        #sys_include = os.path.join(resim_targets, 'armv8a', 'fvp-system.include')
        #setup_include = os.path.join(resim_targets, 'armv8a', 'fvp-linux-setup.include')
        #cmd = '$sys_include=%s' % sys_include 
        #run_command(cmd)
        #cmd = '$setup_include=%s' % setup_include 
        #run_command(cmd)
        
        RESIM_TARGET = 'NONE'
        DRIVER_WAIT = False
        #print('assign ENV variables')
        lgr.debug('assign ENV variables')
        for name, value in self.config.items('ENV'):
            value = expandValue(value)
            os.environ[name] = value
            if name == 'RESIM_TARGET':
                RESIM_TARGET = value
            elif name == 'DRIVER_WAIT' and (value.lower() == 'true' or value.lower() == 'yes'):
                print('DRIVER WILL WAIT')
                DRIVER_WAIT = True
            elif name == 'CONFIG_COMMAND':
                config_command = value
            elif name == 'QUANTUM':
                cmd = 'set-time-quantum %s' % value
                lgr.debug('Run command %s' % cmd)
                run_command(cmd)
            #print('assigned %s to %s' % (name, value))

        CREATE_RESIM_PARAMS = os.getenv('CREATE_RESIM_PARAMS')
        ''' hack around simics bug generating rafts of x11 traffic '''
        resim_display = os.getenv('RESIM_DISPLAY')
        if resim_display is not None:
            os.environ['DISPLAY'] = resim_display
        
        RUN_FROM_SNAP = os.getenv('RUN_FROM_SNAP')
        ADD_FROM_SNAP = os.getenv('ADD_FROM_SNAP')
        INIT_FROM_SNAP = os.getenv('INIT_FROM_SNAP')
        self.SIMICS_VER = resimSimicsUtils.version()
        if self.SIMICS_VER is not None:
            cmd = "$simics_version=%s" % (self.SIMICS_VER)
            #print('cmd is %s' % cmd)
            run_command(cmd)
            lgr.debug('SIMICS_VER is %s' % self.SIMICS_VER)
        
        self.not_a_target=['ENV', 'driver']
        
        self.comp_dict = createDict(self.config, self.not_a_target, lgr)
        self.link_dict = {}
        if ADD_FROM_SNAP is not None:
            print('add from snapshot %s' % ADD_FROM_SNAP)
            run_command('read-configuration %s' % ADD_FROM_SNAP)

        if RUN_FROM_SNAP is None and INIT_FROM_SNAP is None:
            print('will create switches')
            run_command('run-command-file ./targets/x86-x58-ich10/create_switches.simics')
            # seems needed by simics7 ?
            print('instantiate them')
            run_command('instantiate-components')
            print('did instantiate')
            checkVLAN(self.config)
            if CREATE_RESIM_PARAMS is not None and CREATE_RESIM_PARAMS.upper() == 'YES':
                print('Will create RESim parameters')
            # TBD check this
            run_command('set-min-latency min-latency = 0.01')
            interact = None
            if self.config.has_section('driver'):
                cmd = '$machine_name="driver"' 
                run_command (cmd)
                run_command('$eth_dev=i82543gc')
                for name in self.comp_dict['driver']:
                    value = self.comp_dict['driver'][name]
                    if name.startswith('$'):
                        cmd = "%s=%s" % (name, value)
                        run_command(cmd)
                    elif name == 'INTERACT_SCRIPT':
                        interact = self.comp_dict['driver'][name]

                run_command('$create_network=FALSE')
        
                driver_script = self.getSimicsScript('driver',lgr)
                if os.path.isfile('./driver-script.sh'):
                    print('Start the %s using %s' % (self.config.get('driver', '$host_name'), driver_script))
                    lgr.debug('Start the %s using %s' % (self.config.get('driver', '$host_name'), driver_script))
                else:
                    print('WARNING, starting driver but missing driver-script.sh script! *****************************')
                    lgr.debug('WARNING, starting driver but missing driver-script.sh script! *****************************')
                lgr.debug('Start the %s using %s' % (self.config.get('driver', '$host_name'), driver_script))
                run_command('run-command-file ./targets/%s' % driver_script)
                run_command('start-agent-manager')
                run_command('driver.mb.log-level 0 -r')

                done = False
                count = 0
                if interact is not None:
                    print('Will run interact %s' % interact)
                    if interact.endswith('.simics'):
                        run_command('run-command-file %s' % interact)
                    elif interact.endswith('.py'):
                        run_command('run-python-file %s' % interact)
                    else:
                        lgr.error('Did not know what to do with INTERACT_SCRIPT %s' % interact)
                        return
                while not done and not DRIVER_WAIT and not RESIM_TARGET.lower() == 'none':
                    #print('***RUN SOME **')
                    #run_command('c 50000000000')
                    run_command('c 500000000')
                    if os.path.isfile('driver-ready.flag'):
                        #print('GOT DRIVER READY')
                        done = True 
                    count += 1
                    #print(count)
                lgr.debug('assign link names and create map for driver')
                self.link_dict['driver'] = assignLinkNames('driver', self.comp_dict['driver'], lgr)
                switch_map = linkSwitches('driver', self.comp_dict['driver'], self.link_dict['driver'], lgr)
                addSwitchLinkNames('driver', self.comp_dict['driver'], self.link_dict['driver'], switch_map, lgr)
                if DRIVER_WAIT:
                    print('DRIVER_WAIT -- will continue.  Use @resim.go to monitor')
            ''' NOTE RETURN ABOVE '''
            if not DRIVER_WAIT:
                self.doSections(lgr) 
            lgr.debug('check config_command %s' % config_command)
            if config_command is not None:
                run_command(config_command)
        else:
            if RUN_FROM_SNAP is not None:
                print('run from checkpoint %s' % RUN_FROM_SNAP)
                run_command('read-configuration %s' % RUN_FROM_SNAP)
                #run_command('run-script ./targets/x86-x58-ich10/switches.simics')
            elif INIT_FROM_SNAP is not None:
                print('init from checkpoint %s (hold the pickles)' % INIT_FROM_SNAP)
                run_command('read-configuration %s' % INIT_FROM_SNAP)
        self.doAlways()
        run_command('log-level 0 -all')
        ''' dummy logging object to support script branches for automated tests '''
        try:
            SIM_create_object('dummy_comp', 'RESim_log', [])
        except:
            pass
        SIM_run_command('RESim_log.log-level 1')
        
        try:
            # in case a dhcp service node was created, keep it off the network TBD make a param
            SIM_run_command('dhcp_service_node.disable-real-dns')
        except:
            pass
        '''
        Either launch monitor, or generate kernel parameter file depending on CREATE_RESIM_PARAMS
        '''
        MONITOR = os.getenv('MONITOR')
        if MONITOR is None or MONITOR.lower() != 'no':
            if RESIM_TARGET.lower() != 'none':
                if CREATE_RESIM_PARAMS is not None and CREATE_RESIM_PARAMS.upper() == 'YES':
                    gkp = getKernelParams.GetKernelParams(conf, self.comp_dict, RUN_FROM_SNAP)
                else:
                    print('genMonitor for target %s' % RESIM_TARGET)
                    lgr.debug('genMonitor for target %s' % RESIM_TARGET)
                    cgc = genMonitor.GenMonitor(self.comp_dict, self.link_dict, cfg_file, conf=conf)
                    cgc.doInit()
    
    def getSimicsScript(self, section, lgr):    
        script = self.config.get(section,'SIMICS_SCRIPT')
        lgr.debug('getSimicsScript got %s' % script)
        if 'genx86' in script:
            if self.SIMICS_VER.startswith('5'):
                script = script.replace('genx86.simics', 'genx86_5.simics')
                lgr.debug('Simics 5 Modified SIMICS_SCRIPT to be %s' % script)
            elif self.SIMICS_VER.startswith('6'):
                script = script.replace('genx86.simics', 'genx86_6.simics')
                lgr.debug('Simics 6 Modified SIMICS_SCRIPT to be %s' % script)
            elif self.SIMICS_VER.startswith('7'):
                script = script.replace('x86-x58-ich10/genx86_6.simics', 'resim-x86/resim-x86.simics')
                script = script.replace('x86-x58-ich10/genx86.simics', 'resim-x86/resim-x86.simics')
                lgr.debug('Simics 7 Modified SIMICS_SCRIPT to be %s' % script)
        return script
          
    def doSections(self, lgr):
        CREATE_RESIM_PARAMS = os.getenv('CREATE_RESIM_PARAMS')
        for section in self.config.sections():
            if section in self.not_a_target:
                continue
            platform = None
            if 'PLATFORM' in self.comp_dict[section]:
                platform = self.comp_dict[section]['PLATFORM'] 
            #print('assign %s CLI variables' % section)
            ''' hack defaults, Simics CLI has no undefine operation '''
            if platform is None or not platform.startswith('arm'):
                run_command('$eth_dev=i82543gc')
                run_command('$mac_address_3=None')
            
            cmd = '$machine_name="%s"' % section
            run_command (cmd)
            params=''
            script = self.getSimicsScript(section,lgr)
            did_net_create = False
            #if 'PLATFORM' in self.comp_dict[section] and self.comp_dict[section]['PLATFORM'].startswith('arm'):
            #sim7_params = ['disk0_image'] 
            if platform in ['arm', 'arm5']:
                ''' special handling for arm platforms to get host name set properly '''
                params = params+' default_system_info=%s' % self.comp_dict[section]['$host_name']
                params = params+' board_name=%s' % self.comp_dict[section]['$host_name']
                
                for name in self.comp_dict[section]:
                    if name.startswith('$'):
                        value = self.comp_dict[section][name]
                        cmd = '%s=%s' % (name[1:], value)
                        params = params + " "+cmd
            elif platform == 'ppc32':
                params = params+' default_system_info=%s' % self.comp_dict[section]['$host_name']
                params = params+' board_name=%s' % self.comp_dict[section]['$host_name']
                for name in self.comp_dict[section]:
                    if name.startswith('$'):
                        value = self.comp_dict[section][name]
                        cmd = '%s=%s' % (name, value)
                        run_command(cmd)
            else:
                for name in self.comp_dict[section]:
                    if name.startswith('$'):
                        value = self.comp_dict[section][name]
                        #if self.SIMICS_VER.startswith('7'):
                        #    if name[1:] in sim7_params:
                        #        cmd = '%s=%s' % (name, value)
                        #        run_command(cmd)
                        if platform is None or not platform.startswith('arm'):
                            if 'create_network' in name:
                                did_net_create = True
                                cmd = 'create_network=TRUE eth_link=%s' % value
                            else:     
                                if False and self.SIMICS_VER.startswith('7') and name[1:] == 'disk_image':
                                    cmd = 'disk0_image=%s' % (value)
                                else: 
                                    cmd = '%s=%s' % (name[1:], value)
                            params = params + " "+cmd
                            if self.SIMICS_VER.startswith('4'):
                               run_command('$'+cmd)
                        else:
                            cmd = '%s=%s' % (name, value)
                            run_command(cmd)
                            #print('cmd is %s' % cmd)
                if 'genx86' in script and not did_net_create:
                    params = params+" "+'create_network=FALSE'

            if did_net_create:
                self.comp_dict[section]['ETH0_SWITCH'] = 'NONE' 
                       
            if script.lower() != 'none': 
                if self.SIMICS_VER.startswith('4'):
                    cmd='run-command-file "./targets/%s"' % (script)
                else:
                    cmd='run-command-file "targets/%s" %s' % (script, params)
                #print('cmd is %s' % cmd)
                lgr.debug('cmd is %s' % cmd)
                run_command(cmd)
            #print('assign eth link names')
            lgr.debug('Assign link names for section %s' % section)
            
            self.link_dict[section] = assignLinkNames(section, self.comp_dict[section], lgr)
            #print('link the switches')
            switch_map = linkSwitches(section, self.comp_dict[section], self.link_dict[section], lgr)
            #print('assign switch link names')
            addSwitchLinkNames(section, self.comp_dict[section], self.link_dict[section], switch_map, lgr)

            for name in self.comp_dict[section]:
                if name == 'INTERACT_SCRIPT':
                    interact = self.comp_dict[section][name]
                    print('Will run interact %s for target %s' % (interact, section))
                    if interact.endswith('.simics'):
                        run_command('run-command-file %s' % interact)
                    elif interact.endswith('.py'):
                        run_command('run-python-file %s' % interact)
                    else:
                        lgr.error('Did not know what to do with INTERACT_SCRIPT %s' % interact)
                        return
            PRE_INIT_SCRIPT = os.getenv('PRE_INIT_SCRIPT')
            if CREATE_RESIM_PARAMS is not None and CREATE_RESIM_PARAMS.upper() == 'YES' and PRE_INIT_SCRIPT is not None:
                print('Will create resim params, run pre_init_script %s' % PRE_INIT_SCRIPT)
                cmd = 'run-command-file %s' % PRE_INIT_SCRIPT
                run_command(cmd)
 
    def doAlways(self):
        ''' scripts to run regardless of whether starting from a snapshot'''
        for section in self.config.sections():
            if section in self.not_a_target:
                continue
            for name in self.comp_dict[section]:
                if name == 'ALWAYS_SCRIPT':
                    always = self.comp_dict[section][name]
                    print('Will run always %s for target %s' % (always, section))
                    if always.endswith('.simics'):
                        run_command('run-command-file %s' % always)
                    elif always.endswith('.py'):
                        run_command('run-python-file %s' % always)
                    else:
                        lgr.error('Did not know what to do with ALWAYS_SCRIPT %s' % always)
                        return
if __name__ == '__main__':
    global cgc
    cgc = None 
    resim = LaunchRESim()
