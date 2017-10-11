#!/bin/bash
export CGC_DEVEL=YES
export SIMICS_VER=4.8
export INSTANCE=0
export SIMICS=/mnt/simics/simics-4.8/simics-4.8.75

echo CGC_DEVEL set to $CGC_DEVEL version $SIMICS_VER
/mnt/cgcsvn/cgc/users/mft/simics/slaveInstall/checkVMX.sh
/mnt/cgcsvn/cgc/users/mft/zk/py/putReplayCfg.py $INSTANCE

./simics -p /mnt/cgcsvn/cgc/users/mft/simics/simicsScripts/launchMonitor.py
