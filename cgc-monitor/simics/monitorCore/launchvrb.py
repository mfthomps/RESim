import os
CORE = '/mnt/cgc-monitor/cgc-monitor/simics/monitorCore'
ZK = '/mnt/cgc-monitor/cgc-monitor/zk/monitorLibs'
if CORE not in sys.path:
    print("using CORE of %s" % CORE)
    sys.path.append(CORE)
if ZK not in sys.path:
    print("using ZK of %s" % ZK)
    sys.path.append(ZK)
RUN_FROM_SNAP = os.getenv('RUN_FROM_SNAP')
run_command('add-directory -prepend /mnt/cgc-monitor/cgc-monitor/simics/simicsScripts')
run_command('add-directory -prepend /mnt/cgc-monitor/cgc-monitor/simics/monitorCore')
run_command('add-directory -prepend /mnt/cgc-monitor/cgc-monitor/zk/monitorLibs')
run_command('add-directory -prepend /mnt/simics/eemsWorkspace')
if RUN_FROM_SNAP is None:
    #run_command('run-command-file ./targets/x86-x58-ich10/vdr2.simics')
    run_command('run-command-file ./targets/x86-x58-ich10/mft-ubuntu.simics')
    run_command('start-agent-manager')
    done = False
    count = 0
    while not done: 
        run_command('c 50000000000')
        if os.path.isfile('driver-ready.flag'):
            done = True 
        count += 1
        print count
    print('NOW run the vdr')  
    run_command('run-command-file ./targets/x86-x58-ich10/mft-vdr.simics')
else:
    print('run from checkpoint %s' % RUN_FROM_SNAP)
    run_command('read-configuration %s' % RUN_FROM_SNAP)
run_command('run-python-file genMonitor.py')

