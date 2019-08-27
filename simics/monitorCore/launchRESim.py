import os
import ConfigParser
RESIM_REPO = os.getenv('RESIM')
CORE = os.path.join(RESIM_REPO, 'simics/monitorCore')
if CORE not in sys.path:
    print("using CORE of %s" % CORE)
    sys.path.append(CORE)
import genMonitor
import getKernelParams
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

class LinkObject():
    def __init__(self, name):
        self.name = name
        cmd = '%s' % name
        self.obj = SIM_run_command(cmd)
        #print('self.name is %s self.obj is %s' % (self.name, self.obj))

def doEthLink(target, eth):
    name = '$%s_%s' % (target, eth)
    cmd = '%s = $%s' % (name, eth)
    print('doEthLinc cmd %s' % cmd)
    run_command(cmd)
    link_object = LinkObject(name)
    if link_object.obj == 'None':
        return None
    return link_object
    
def doSwitch(target, switch):
    return None
    name = '$%s_%s' % (target, switch)
    cmd = '%s = $%s_con' % (name, switch)
    run_command(cmd)
    link_object = LinkObject(name)
    return link_object
    
def assignLinkNames(target, comp_dict):
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
            continue
        if comp_dict[link.mac] != 'None':
            obj = doEthLink(target, link.eth)
            if obj is not None: 
                link_names[link.eth] = obj
    for link in links:
        if link.mac not in comp_dict:
            continue
        obj = doSwitch(target, link.sw)
        if obj is not None: 
            link_names[link.sw] = obj
    return link_names

def doConnect(switch, eth):
    print('do connect switch %s eth %s' % (switch, eth))
    cmd = '$%s' % eth
    dog = run_command(cmd)
    print('dog is %s' % dog)
    if switch.startswith('v'):
        cmd = '%s.get-free-trunk-connector 2' % switch
    else:
        cmd = '%s.get-free-connector' % switch
    con  = run_command(cmd)
    cmd = 'connect $%s cnt1 = %s' % (eth, con)
    print cmd
    run_command(cmd)

def linkSwitches(target, comp_dict, link_names):
    if comp_dict['ETH0_SWITCH'] != 'NONE' and 'eth0' in link_names:
        doConnect(comp_dict['ETH0_SWITCH'], 'eth0')
    if comp_dict['ETH1_SWITCH'] != 'NONE' and 'eth1' in link_names:
        doConnect(comp_dict['ETH1_SWITCH'], 'eth1')
    if comp_dict['ETH2_SWITCH'] != 'NONE' and 'eth2' in link_names:
        doConnect(comp_dict['ETH2_SWITCH'], 'eth2')
    if comp_dict['ETH3_SWITCH'] != 'NONE' and 'eth3' in link_names:
        doConnect(comp_dict['ETH3_SWITCH'], 'eth3')
 
   
def createDict(config): 
    comp_dict = {}
    if config.has_section('driver'):
        comp_dict['driver'] = {}
        for name, value in config.items('driver'):
            comp_dict['driver'][name] = value
    for section in config.sections():
        if section in not_a_target and section != 'driver':
            continue
        comp_dict[section] = {}
        print('assign %s CLI variables' % section)
        ''' hack defaults, Simics CLI has no undefine operation '''
        comp_dict[section]['ETH0_SWITCH'] = 'switch0'
        comp_dict[section]['ETH1_SWITCH'] = 'switch1'
        comp_dict[section]['ETH2_SWITCH'] = 'switch2'
        comp_dict[section]['ETH3_SWITCH'] = 'switch3'
        for name, value in config.items(section):
            comp_dict[section][name] = value
    return comp_dict

def checkVLAN(config):
    for name, value in config.items('ENV'):
        if name.startswith('VLAN_'):
            num = int(name.split('_')[1])
            cmd = 'create-ethernet-vlan-switch vswitch%d' % num
            run_command(cmd)
            cmd = 'vswitch%d.add-vlan 2' % num
            run_command(cmd)

print('Launch RESim')
SIMICS_WORKSPACE = os.getenv('SIMICS_WORKSPACE')
RESIM_INI = os.getenv('RESIM_INI')
config = ConfigParser.ConfigParser()
config.optionxform = str
if not RESIM_INI.endswith('.ini'):
    ini_file = '%s.ini' % RESIM_INI
else:
    ini_file = RESIM_INI
cfg_file = os.path.join(SIMICS_WORKSPACE, ini_file)
config.read(cfg_file)



run_command('add-directory -prepend %s/simics/simicsScripts' % RESIM_REPO)
run_command('add-directory -prepend %s/simics/monitorCore' % RESIM_REPO)
run_command('add-directory -prepend %s' % SIMICS_WORKSPACE)

RESIM_TARGET = 'NONE'
print('assign ENV variables')
for name, value in config.items('ENV'):
    os.environ[name] = value
    if name == 'RESIM_TARGET':
        RESIM_TARGET = value
    #print('assigned %s to %s' % (name, value))

RUN_FROM_SNAP = os.getenv('RUN_FROM_SNAP')
SIMICS_VER = os.getenv('SIMICS_VER')
if SIMICS_VER is not None:
    cmd = "$simics_version=%s" % (SIMICS_VER)
    #print('cmd is %s' % cmd)
    run_command(cmd)

not_a_target=['ENV', 'driver']

comp_dict = createDict(config)
link_dict = {}
if RUN_FROM_SNAP is None:
    run_command('run-command-file ./targets/x86-x58-ich10/create_switches.simics')
    checkVLAN(config)
    run_command('set-min-latency min-latency = 0.01')
    if config.has_section('driver'):
        run_command('$eth_dev=i82543gc')
        for name in comp_dict['driver']:
            value = comp_dict['driver'][name]
            if name.startswith('$'):
                cmd = "%s=%s" % (name, value)
                run_command(cmd)

        print('Start the %s' % config.get('driver', '$host_name'))
        run_command('run-command-file ./targets/%s' % config.get('driver','SIMICS_SCRIPT'))
        run_command('start-agent-manager')
        done = False
        count = 0
        while not done: 
            run_command('c 50000000000')
            if os.path.isfile('driver-ready.flag'):
                done = True 
            count += 1
            #print count
        link_dict['driver'] = assignLinkNames('driver', comp_dict['driver'])
        linkSwitches('driver', comp_dict['driver'], link_dict['driver'])

    for section in config.sections():
        if section in not_a_target:
            continue
        print('assign %s CLI variables' % section)
        ''' hack defaults, Simics CLI has no undefine operation '''
        run_command('$eth_dev=i82543gc')
        run_command('$mac_address_3=None')
        
        params=''
        for name in comp_dict[section]:
            value = comp_dict[section][name]
            if name.startswith('$'):
                cmd = "%s=%s" % (name, value)
                run_command(cmd)
                #params=params+(' %s' % cmd[1:])
        script = config.get(section,'SIMICS_SCRIPT')
        if 'PLATFORM' in comp_dict[section] and comp_dict[section]['PLATFORM']=='arm':
            params = params+' default_system_info=%s' % comp_dict[section]['$host_name']
            params = params+' board_name=%s' % comp_dict[section]['$host_name']
            '''
            params = params+' root_disk_image=%s' % comp_dict[section]['$root_disk_image']
            params = params+' root_disk_size=%s' % comp_dict[section]['$root_disk_size']
            params = params+' user_disk_image=%s' % comp_dict[section]['$user_disk_image']
            params = params+' user_disk_size=%s' % comp_dict[section]['$user_disk_size']
            '''
            for name in comp_dict[section]:
                if name.startswith('$'):
                    cmd = '%s=%s' % (name[1:], name)
                    params = params + " "+cmd
        else:
            for name in comp_dict[section]:
                if name.startswith('$'):
                    cmd = '%s=%s' % (name[1:], name)
                    params = params + " "+cmd

        if SIMICS_VER.startswith('4'):
            cmd='run-command-file "./targets/%s"' % (script)
        else:
            cmd='run-command-file "./targets/%s" %s' % (script, params)
        print('cmd is %s' % cmd)
        run_command(cmd)
        link_dict[section] = assignLinkNames(section, comp_dict[section])
        linkSwitches(section, comp_dict[section], link_dict[section])
else:
    print('run from checkpoint %s' % RUN_FROM_SNAP)
    run_command('read-configuration %s' % RUN_FROM_SNAP)
    #run_command('run-command-file ./targets/x86-x58-ich10/switches.simics')
run_command('log-level 0 -all')
'''
Either launch monitor, or generate kernel parameter file depending on CREATE_RESIM_PARAMS
'''
CREATE_RESIM_PARAMS = os.getenv('CREATE_RESIM_PARAMS')
if RESIM_TARGET.lower() != 'none':
    if CREATE_RESIM_PARAMS is not None and CREATE_RESIM_PARAMS.upper() == 'YES':
        gkp = getKernelParams.GetKernelParams(comp_dict)
    else:
        print('genMonitor for target %s' % RESIM_TARGET)
        cgc = genMonitor.GenMonitor(comp_dict, link_dict)
        cgc.doInit()

