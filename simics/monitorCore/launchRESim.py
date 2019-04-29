import os
import ConfigParser
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
The workspace must contain a configuration file named $RESIM_TARGET.ini
That ini file must include and ENV section and a section for each
component in the simulation.  
'''

print('Launch RESim')
SIMICS_WORKSPACE = os.getenv('SIMICS_WORKSPACE')
RESIM_TARGET = os.getenv('RESIM_TARGET')
RESIM_REPO = os.getenv('RESIM')
config = ConfigParser.ConfigParser()
config.optionxform = str
ini_file = '%s.ini' % RESIM_TARGET
cfg_file = os.path.join(SIMICS_WORKSPACE, ini_file)
config.read(cfg_file)

CORE = os.path.join(RESIM_REPO, 'simics/monitorCore')
if CORE not in sys.path:
    print("using CORE of %s" % CORE)
    sys.path.append(CORE)


run_command('add-directory -prepend %s/simics/simicsScripts' % RESIM_REPO)
run_command('add-directory -prepend %s/simics/monitorCore' % RESIM_REPO)
run_command('add-directory -prepend %s' % SIMICS_WORKSPACE)

print('assign ENV variables')
for name, value in config.items('ENV'):
    os.environ[name] = value
    #print('assigned %s to %s' % (name, value))

RUN_FROM_SNAP = os.getenv('RUN_FROM_SNAP')

not_a_target=['ENV', 'driver']

if RUN_FROM_SNAP is None:
    run_command('run-command-file ./targets/x86-x58-ich10/create_switches.simics')
    run_command('set-min-latency min-latency = 0.01')
    if config.has_section('driver'):
        for name, value in config.items('driver'):
            cmd = "$%s=%s" % (name, value)
            run_command(cmd)
        print('Start the %s' % config.get('driver', 'host_name'))
        run_command('run-command-file ./targets/%s' % config.get('driver','SIMICS_SCRIPT'))
        run_command('start-agent-manager')
        done = False
        count = 0
        while not done: 
            run_command('c 50000000000')
            if os.path.isfile('driver-ready.flag'):
                done = True 
            count += 1
            print count
    for section in config.sections():
        if section in not_a_target:
            continue
        print('assign %s CLI variables' % section)
        for name, value in config.items(section):
            cmd = "$%s=%s" % (name, value)
            run_command(cmd)
        print('Start the %s' % section)  
        run_command('run-command-file ./targets/%s' % config.get(section,'SIMICS_SCRIPT'))
else:
    print('run from checkpoint %s' % RUN_FROM_SNAP)
    run_command('read-configuration %s' % RUN_FROM_SNAP)
    #run_command('run-command-file ./targets/x86-x58-ich10/switches.simics')
run_command('log-level 0 -all')
CREATE_RESIM_PARAMS = os.getenv('CREATE_RESIM_PARAMS')
if CREATE_RESIM_PARAMS is not None and CREATE_RESIM_PARAMS.upper() == 'YES':
    run_command('run-python-file getKernelParams.py')
else:
    run_command('run-python-file genMonitor.py')

