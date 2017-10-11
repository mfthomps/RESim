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

import time
import datetime
import sys
import commands
import shutil
import signal
import ConfigParser
import subprocess
import socket
'''
Set up directory paths and launch the cgcMonitor.
First write IP and instance values to file to be found by the target
This script runs in the Simics context.
'''
MY_LOG = os.getenv('my_log')
if MY_LOG is not None:
    sys.stdout = open(MY_LOG, 'w')
    sys.stderr = open(MY_LOG, 'w')
INSTANCE = os.getenv('INSTANCE')
print "launchMonitor BEGIN, instance %s" % INSTANCE 
os.umask(0000)
DEVEL = os.getenv('CGC_DEVEL')
'''
    LAUNCH_PARAM environment variable set in tools such as monitorDev.sh
    no_monitor -- run simulation without monitoring
    no_provision -- do not provision the target systems
    gen_params -- generate linux parameters and quit
    make_snapshot -- Create a checkpoint after initial provisioning (does not include cgc packages)
    get_bsd_symbols -- boot the image and extract the kernel symbols into the appropriate shared map directory
    get_bsd64_symbols -- boot the image and extract the kernel symbols into the appropriate shared map directory
    get_linux_symbols -- boot the image and extract the kernel symbols into the appropriate shared map directory
    get_linux64_symbols -- boot the image and extract the kernel symbols into the appropriate shared map directory
'''
LAUNCH_PARAM = os.getenv('LAUNCH_PARAM')
ONE_BOX = os.getenv('ONE_BOX')
OS_TYPE = os.getenv('CGC_OS_TYPE')
RUN_FROM_SNAP = os.getenv('RUN_FROM_SNAP')
MULTI_PROCESSOR = os.getenv('MULTI_PROCESSOR')
PY_SHARED = '/usr/share/pyshared'
CORE = None
if DEVEL is not None and DEVEL == 'YES':
    CORE = '/mnt/cgcsvn/cgc/trunk/cgc-monitor/simics/monitorCore'
else:
    CORE = os.path.join(PY_SHARED, 'monitorCore')
if CORE not in sys.path:
    print("using CORE of %s" % CORE)
    sys.path.append(CORE)
if PY_SHARED not in sys.path:
    sys.path.append(PY_SHARED)
import cellConfig
import osUtils
#def signal_handler(signal, frame):
#     print 'in signal handler'
#     exit(1)
  
#signal.signal(signal.SIGINT, signal_handler)
#signal.signal(signal.SIGTERM, signal_handler)
def getSymbols(OS_TYPE, mapfile):
    got_symbols = False
    while not got_symbols:
        print('run a bit then test if we got the symbols')
        SIM_continue(90000000000)
        if os.path.isfile(ack_file):
            got_symbols = True
    if OS_TYPE.startswith(osUtils.FREE_BSD):
        shutil.copyfile('/tmp/kernel_maps/bsd-kernel.map', mapfile)
        print('copied bsd kernel-map to %s' % mapfile)
    elif OS_TYPE.startswith(osUtils.LINUX):
        shutil.copyfile('/tmp/kernel_maps/linux-kernel.map', mapfile)
        print('copied linux kernel-map to %s' % mapfile)
    else:
        print('could not getSymbols for os type %s' % OS_TYPE)
        
def doSnapshot(ONE_BOX, OS_TYPE):
            ready_to_freeze = False
            snapshot_name = 'cgc3_snapshot.ckpt'
            if ONE_BOX == 'YES':
                if OS_TYPE == osUtils.FREE_BSD:
                    snapshot_name = 'cgc1_bsd_snapshot.ckpt'
                if OS_TYPE == osUtils.FREE_BSD64:
                    snapshot_name = 'cgc1_bsd64_snapshot.ckpt'
                else:
                    snapshot_name = 'cgc1_snapshot.ckpt'
            else:
                if OS_TYPE == osUtils.FREE_BSD:
                    snapshot_name = 'cgc3_bsd_snapshot.ckpt'
                elif OS_TYPE == osUtils.LINUX:
                    snapshot_name = 'cgc3_snapshot.ckpt'
                elif OS_TYPE == osUtils.MIXED_KLK:
                    snapshot_name = 'cgc3_mixed_klk_snapshot.ckpt'
                elif OS_TYPE == osUtils.MIXED_KLK64:
                    snapshot_name = 'cgc3_mixed_klk64_snapshot.ckpt'
                elif OS_TYPE == osUtils.MIXED_DLD:
                    snapshot_name = 'cgc3_mixed_dld_snapshot.ckpt'
                elif OS_TYPE == osUtils.FREE_BSD64:
                    snapshot_name = 'cgc3_bsd64_snapshot.ckpt'
                else:
                    print('launchMonitor doSnapshot, unknown os type %s' % OS_TYPE)
                    exit(1)
            while not ready_to_freeze:
                print('run a bit then test if ready to make snapshot')
                SIM_continue(90000000000)
                if os.path.isfile(ack_file):
                    ready_to_freeze = True
            print('back, now make snapshot')
            ip = 100
            switch_num = 0
            for cell_name in cell_config.ssh_port:
                run_command('disconnect-real-network-port-in ethernet-link = switch0x%d target-ip = 10.10.0.%d target-port = 22' % (switch_num, ip))
                ip += 1
                switch_num += 1
          
            run_command('write-configuration %s' % snapshot_name)
            print('snapshot saved in %s.ckpt' % snapshot_name)
            tar_file = snapshot_name+'.tar'
            subprocess.Popen(['/bin/tar', '-cf', tar_file, snapshot_name])
            print('created tar file %s' % tar_file)
            run_command('quit')

def getKSections(fname, num_boxes, cmd=None):
    wait_count = 9000000000 * num_boxes
    got_ksections = False
    count = 0
    real_trigger = 5
    while not got_ksections:
       kconfig = None
       if os.path.isfile(fname):
           # make sure the file is populated
           kconfig = ConfigParser.ConfigParser()
           try:
               kconfig.read(fname)
               sections = kconfig.sections()
               if sections is not None and len(sections)>0:
                   print 'able to load ksections from %s' % fname
                   got_ksections = True
           except:
               print 'cannot yet read %s, wait' % fname
       else:
           if (count % 100) == 0:
               print 'no %s, %d wait' % (fname, count)
           count += 1
           #if count == real_trigger:
           #    SIM_run_command('enable-real-time-mode')
           #    print('real time  mode enabled, trying sshing to the sick puppy')
       if not got_ksections:
           #run_command('mtprof.cellstat')
           SIM_continue(wait_count)
           if cmd is not None and kconfig is not None and not os.path.isfile(fname):
               print('did not get actual sections, repeat command %s' % cmd)
               SIM_run_command(cmd)

def doWhiteList(cpu):
    address = 0xfd70405c
    cpu.outside_memory_whitelist.append([address, 0x3ff])
    address = 0xfd74405c
    cpu.outside_memory_whitelist.append([address, 0x3ff])
    address = 0xfd72405c
    cpu.outside_memory_whitelist.append([address, 0x3ff])

def doAgents(cell_config):
    am = SIM_run_command('start-agent-manager')
    am = SIM_run_command('agent_manager.enable')
    for cell_name in cell_config.ssh_port:
        cmd = 'agent_manager.connect-to-agent name="%s_agent" identifier="%s"' % (cell_name, cell_name)
        agent = SIM_run_command(cmd)
        print('agent is %s' % agent)
    # supress simics error that only displays when running w/ hypervisor
    run_command('magic_pipe->legacy_share_hap = 4')
      
no_monitor=False
provision=True
gen_params=False
provision_bsd=False
make_snapshot="NO"
get_symbols="NO"
if LAUNCH_PARAM is not None and len(LAUNCH_PARAM)>0:
    if LAUNCH_PARAM == 'no_monitor':
        no_monitor=True
        print('NO MONITIOR')
    elif LAUNCH_PARAM == 'no_provision':
        print('NO PROVISIONING')
        provision = False
    elif LAUNCH_PARAM == 'gen_params':
        print('Generate parameters and stop')
        gen_params = True
    elif LAUNCH_PARAM == 'make_snapshot':
        print('make a snapshot')
        make_snapshot = 'YES'
    elif LAUNCH_PARAM == 'get_bsd_symbols' or LAUNCH_PARAM == 'get_linux_symbols' or LAUNCH_PARAM == 'get_linux64_symbols' or LAUNCH_PARAM == 'get_bsd64_symbols':
        print('get the kernel symbols')
        get_symbols = 'YES'
        ONE_BOX = 'YES'
        no_monitor=True
        RUN_FROM_SNAP = None
        if LAUNCH_PARAM == 'get_bsd_symbols':
            OS_TYPE = osUtils.FREE_BSD
        elif LAUNCH_PARAM == 'get_bsd64_symbols':
            OS_TYPE = osUtils.FREE_BSD64
        elif LAUNCH_PARAM == 'get_linux_symbols':
            OS_TYPE = osUtils.LINUX
        else:
            OS_TYPE = osUtils.LINUX64
    elif LAUNCH_PARAM.startswith('provision_bsd'):
        print('provision a new bsd CRAFF')
        provision_bsd = 'YES'
        no_monitor=True
        ONE_BOX = 'YES'
        if LAUNCH_PARAM == 'provision_bsd':
            OS_TYPE = osUtils.FREE_BSD
        else:
            OS_TYPE = osUtils.FREE_BSD64
        RUN_FROM_SNAP = None
    else:
        print('UNKNOWN PARAMETER %s' % LAUNCH_PARAM)
        exit(1)
else:
    print('will monitor')
print('os type: %s, one box: %s' % (OS_TYPE, ONE_BOX))
num_boxes = 3
if ONE_BOX == 'YES':
    num_boxes = 1   
elif ONE_BOX == 'TWO':
    num_boxes = 2
cell_config = cellConfig.cellConfig(num_boxes, OS_TYPE)
PY_SHARED = '/usr/share/pyshared'
if DEVEL is not None and DEVEL == 'YES':
    CORE = '/mnt/cgcsvn/cgc/trunk/cgc-monitor/simics/monitorCore'
else:
    CORE = os.path.join(PY_SHARED, 'monitorCore')
if CORE not in sys.path:
    print("using CORE of %s" % CORE)
    sys.path.append(CORE)
if PY_SHARED not in sys.path:
    sys.path.append(PY_SHARED)
from monitorLibs import configMgr
print('init configMgr')
cfg = configMgr.configMgr(cell_config.os_type)
# env variable overrides cfg value
ZSIM = os.getenv('ZSIM')
if ZSIM is None and cfg.use_z_sim:
    print('cfg.use_zsim is true')
    ZSIM = 'YES'

SIMICS_VER = os.getenv('SIMICS_VER')
#SIM_SCRIPTS = '/mnt/cgc/simics/simicsScripts'
USE_VIPER = os.getenv('USE_VIPER')

#if SIM_SCRIPTS not in sys.path:
#    sys.path.append(SIM_SCRIPTS)

import delayUntilBoot

print 'instance is '+INSTANCE
# delete player offset file (used to indicate offset of code signifying start of user data consumption
try:
    os.remove('playerOffset.txt')
except:
    pass
# set up python paths based on whether we are a development system or a target
if DEVEL is not None and (DEVEL == 'YES'):
    run_command('add-directory -prepend /mnt/cgcsvn/cgc/trunk/cgc-monitor/simics/simicsScripts')
    run_command('add-directory -prepend /mnt/cgcsvn/cgc/trunk/cgc-monitor/simics/monitorCore')
else:
    run_command('add-directory -prepend /usr/share/pyshared/simicsScripts')
    run_command('add-directory -prepend /usr/share/pyshared/monitorCore')


date = datetime.date.today()
time = datetime.time(1,2,3)
cmd = '$rtc_time = "%s %s UTC"' % (date, time)
print "time is %s" % cmd
run_command(cmd)

if MULTI_PROCESSOR == 'YES':
    print('using MULTI_PROCESSOR, may be slow')
    run_command('$cpu_class       = "core-i7"')

if SIMICS_VER == '4.8' or USE_VIPER == 'YES':
    if RUN_FROM_SNAP is not None and make_snapshot is not "YES":
        run_command('add-directory -prepend /mnt/simics/simicsWorkspace')
        run_command('add-directory -prepend /mnt/simics/simicsWorkspace'+INSTANCE)
        print('run from checkpoint %s' % RUN_FROM_SNAP)
        run_command('read-configuration %s' % RUN_FROM_SNAP)
        if ONE_BOX != 'YES':
            # TBD this mess needs to match up with the .simics script that created the instance.
            i=0
            ip = 100
            for cell_name in cell_config.ssh_port:
                #run_command('disconnect-real-network-port-in ethernet-link = switch0 target-ip = 10.10.0.%d target-port = 22' % ip)
                p = cell_config.ssh_port[cell_name] + int(INSTANCE)
                cmd = 'connect-real-network-port-in ethernet-link = switch0x%d target-ip = 10.10.0.%d target-port = 22 host-port = %d' % (i, ip, p)
                i += 1
                print('reconnect, cmd is %s' % cmd)
                run_command(cmd)
                ip += 1
    else:

        run_command('$OS_TYPE = "%s"' % OS_TYPE)
        if ZSIM == 'YES':
            print 'using ZSIM'
            run_command('$USE_ZSIM = "yes"')
        else:
            print 'Using std viper'
        #run_command('run-command-file ./targets/x86-x58-ich10/viper-debian.simics')
        i=0
        for cell_name in cell_config.ssh_port:
            i += 1
            p = cell_config.ssh_port[cell_name] + int(INSTANCE)
            cmd='$port%d = %d' % (i, p)
            print cmd
            run_command(cmd)
        if ONE_BOX == 'YES':
            if OS_TYPE.startswith(osUtils.FREE_BSD):
                print('start bsd emulation')
                if provision_bsd == "YES":
                    run_command('$provision_bsd = "YES"')
                else:
                    run_command('$provision_bsd = "NO"')
                #run_command('run-command-file ./targets/x86-x58-ich10/bsd1.simics')
                run_command('run-command-file ./targets/x86-x58-ich10/cmb1.simics')
            else:
                print('start linux emulation')
                run_command('run-command-file ./targets/x86-x58-ich10/cmb1.simics')
                #run_command('run-command-file ./targets/x86-x58-ich10/cfe1.simics')
        elif ONE_BOX == 'TWO':
            print('start two box emulation')
            run_command('run-command-file ./targets/x86-x58-ich10/cfe2.simics')
        else:
            print('start emulation os type is %s ********************' % OS_TYPE)
            run_command('run-command-file ./targets/x86-x58-ich10/cmb3.simics')
    
    for cell_name in cell_config.os_type:
        if cell_config.os_type[cell_name].startswith(osUtils.FREE_BSD): 
            print('do whitelist for %s ' % cell_name)
            cmd = '%s.get-processor-list' % cell_name
            try:
                proclist = SIM_run_command(cmd)
            except:
                continue
            cpu = SIM_get_object(proclist[0])

            doWhiteList(cpu)
        run_command('log-level 0 -all')
        #run_command('system-perfmeter -mips -cpu-exec-mode')
  
else:
    run_command('run-command-file targets/x86-440bx/dredd-one.simics')

cell_config.loadCellObjects()
# get this hosts IP and put it into a file that the simulated host will grab and use for its name
myip = commands.getoutput("/sbin/ifconfig").split("\n")[1].split()[1][5:]
f = open('targetStage/myip.txt', 'w')
f.write('%s %s' % (myip, INSTANCE))
f.close()

# clear out any old challenge set artifacts.
try:
    shutil.rmtree('./targetStage/repo/CBs')
except:
    pass

# if replay.log exist, move it.  TBD save more than one?
if os.path.isfile('./replay.log'):
    os.rename('./replay.log', 'replay.log.old')
#msg = run_command('connect-real-network')
#print('from connect-real-network got %s' % msg)
#status = run_command('run-python-file delayUntilBoot.py')
#run_command('enable-mtprof')
run_command('disable-multithreading')
delay_ok = False
if provision:
    # targets scp this to us to let us know when to make snapshot
    ack_file = './targetStage/ack.txt'
    try:
        os.remove(ack_file)
    except:
        pass
    #  tell targets if a snapshot is being made
    fname = "./targetStage/freezeOrGo.txt"
    try:
        os.remove(fname)
    except:
        pass
    fhandle = open(fname, 'w')
    if make_snapshot == "YES":
        fhandle.write("Freeze")
    else:
        fhandle.write("Go")
    fhandle.flush()    
    fhandle.close()    
    POV = 'NO'
    if OS_TYPE.startswith(osUtils.MIXED_KLK) or OS_TYPE == osUtils.MIXED_DLD:
        ''' this indicates whether a negotiator should be created on the IDS '''
        POV = 'YES'
    if RUN_FROM_SNAP is None or make_snapshot == 'YES':
        run_command('set-min-latency min-latency = %s' % cfg.min_latency)
        print('$$$$$$ latency %s $$$$$$$' % cfg.min_latency)
    for cell_name in cell_config.ssh_port:
        dub = delayUntilBoot.delayUntilBoot(OS_TYPE, ONE_BOX)
        print('do delay for cell: %s' % cell_name)
        if dub.doDelay(cell_config.cpuFromCell(cell_name), 'sshd') != 0:
            print 'trouble running delay, exit'
            break
        print '%s should be booted, configure decree vm as a target' % cell_name
        delay_ok = True
        ip_address = cell_config.ip_address[cell_name]
        fname = 'ksections-%s.cfg' % ip_address
        try:
            os.remove(fname)
        except:
            pass
        port = cell_config.ssh_port[cell_name] + int(INSTANCE)
        cmd = 'ssh-keygen -f "~/.ssh/known_hosts" -R [localhost]:%d' % port
        os.system(cmd)

        #run_command('enable-real-time-mode')
        if OS_TYPE.startswith(osUtils.FREE_BSD) and provision_bsd:
            subprocess.Popen(['/usr/bin/noTxcsum', 'em0'])
            print('did noTxsum for %s' % cell_name) 
            SIM_continue(190000000000)
            print('back from continue')
            run_command('stop')
            run_command('save-persistent-state bsd-provision-state')
            print('back from save state')
            run_command('quit')
        elif get_symbols == "YES":
            shutil.rmtree("/tmp/kernel_maps", ignore_errors=True)
            os.mkdir("/tmp/kernel_maps", 0777)
            subprocess.Popen(['/usr/bin/getKernelSymbols', OS_TYPE])
        elif RUN_FROM_SNAP is None or make_snapshot == 'YES':
            p=subprocess.Popen(['/usr/bin/cpToVagrant', str(port), ONE_BOX, cell_config.os_type[cell_name], POV])
            print 'Booting from image, started cp to Vagrant %s' % cell_name
        else:
            subprocess.Popen(['/usr/bin/startServiceOnTargets', str(port), ONE_BOX, cell_config.os_type[cell_name], POV])
            print('Running from snapshot, started startServiceOnTargets %s pov: %s' % (cell_name, POV))
    if delay_ok:
        if make_snapshot == 'YES':
            doAgents(cell_config)
            doSnapshot(ONE_BOX, OS_TYPE)
            exit(0) 
        if get_symbols == 'YES':
            # assuming just one box for this operation  TBD get thrower name from cellConfig
            doAgents(cell_config)
            mapfile = cfg.system_map['thrower']
            getSymbols(OS_TYPE, mapfile)
            exit(0) 

        if gen_params:
            cmd = '%s.software.linux-autodetect-settings' % cell_config.ssh_port[0]
            run_command(cmd)
            run_command('quit')
        else:
            doAgents(cell_config)
            for cell_name in cell_config.ssh_port:
                #if cell_config.os_type[cell_name] == osUtils.FREE_BSD: 
                #    cmd = '%s_agent.run " sudo /sbin/ifconfig ifconfig em0 -txcsum -rxcsum"' % (cell_name)
                #    result=SIM_run_command(cmd)
                #    print('result of ifconfig to disable bsd txcsum is %s' % result)
                # Delete the ksections.cfg file so we get a fresh one based on the kernel's loaded modules
                ip_address = cell_config.ip_address[cell_name]
                fname = 'ksections-%s.cfg' % ip_address
                print 'wait until we have ksections in %s' % fname
                cmd=None
                    
                getKSections(fname, num_boxes, cmd)
                #run_command('disable-real-time-mode')
            done_set = {'server':'service_master', 'thrower':'replay_master', 'ids':'service_master'}
            for cell_name in cell_config.ssh_port:
                if dub.waitUntilGone(cell_config.cpuFromCell(cell_name), 'simics-agent') != 0:
                    print 'trouble waiting for simics-agent to end, exit**************************'
                    break
                if cell_name in done_set:
                    if dub.doDelay(cell_config.cpuFromCell(cell_name), done_set[cell_name]) != 0:
                        print 'trouble running delay for %s, exit**************************' % cell_name
                        break
                    print('must have found %s on %s' % (done_set[cell_name], cell_name))

            print 'got all ksections, load cgcMonitor'
            #run_command('disable-real-time-mode')
            run_command('agent_manager.info')
            if not no_monitor:
                ready4monitor = 'ready4monitor.ckpt'
                shutil.rmtree(ready4monitor, ignore_errors=True)
                run_command('write-configuration %s' % ready4monitor)
                run_command('run-python-file cgcMonitor.py')
                #run_command('log-level 0')
                run_command('@cgc.checkLogStatus()')
                print 'monitor initialized, now run forever'
            else:
                print 'Not monitoring, just continue'
        #am = SIM_run_command('agent_manager.disable')
        #print('disabled agent_manager')
        SIM_continue(0)
else:
    run_command('set-min-latency min-latency = %s' % cfg.min_latency)
    print('$$$$$$ latency %s $$$$$$$' % cfg.min_latency)
#f = open('simics.stdin', 'a')
#f.write('c\n');
#f.close()
#### TBD get ksection data into master (or other) config file here
#run_command('@cgc.continueSimulation()')
#print 'back from continueSimulation'
#SIM_continue(0)
