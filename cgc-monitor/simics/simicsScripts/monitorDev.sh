#!/bin/bash
:<<'END_COMMENT'
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
END_COMMENT

#
# Launch one instance of the monitor, intended for
# development and debugging.
# monitorDev.sh [option]
#    no_monitor -- run simulation without monitoring
#    no_provision -- do not provision the target systems
#    gen_params -- generate linux parameters and quit
#    make_snapshot -- Create a checkpoint after initial provisioning (does not include cgc packages)
#    provision_bsd -- make a new cgc-freebsd.craff with intel nic rxcsum/txcsum off
#    provision_bsd64 -- make a new cgc-freebsd.craff with intel nic rxcsum/txcsum off
#    get_bsd_symbols -- boot the image and extract the kernel symbols into the appropriate shared map directory
#    get_bsd64_symbols -- boot the image and extract the kernel symbols into the appropriate shared map directory
#    get_linux_symbols -- boot the image and extract the kernel symbols into the appropriate shared map directory
#    get_linux64_symbols -- boot the image and extract the kernel symbols into the appropriate shared map directory
#
export CGC_DEVEL=YES
export SIMICS_VER=4.8
export ZSIM=YES
export ONE_BOX=NO
export MULTI_PROCESSOR=NO
#export RUN_FROM_SNAP=cgc1_snapshot.ckpt
#export RUN_FROM_SNAP=cgc1_bsd_snapshot.ckpt
#export RUN_FROM_SNAP=cgc3_bsd_snapshot.ckpt
#export RUN_FROM_SNAP=cgc3_mixed_klk_snapshot.ckpt
#export RUN_FROM_SNAP=cgc3_mixed_klk64_snapshot.ckpt
#export RUN_FROM_SNAP=cgc3_mixed_dld_snapshot.ckpt
#export RUN_FROM_SNAP=cgc3_mixed_llk_snapshot.ckpt
#export RUN_FROM_SNAP=cgc3_mixed_snapshot.ckpt
#export CGC_OS_TYPE=freeBSD
#export CGC_OS_TYPE=freeBSD64
#export CGC_OS_TYPE=linux
#export CGC_OS_TYPE=linux64
#export CGC_OS_TYPE=mixed_llk
#export CGC_OS_TYPE=mixed_klk
#export CGC_OS_TYPE=mixed_klk64
export RUN_FROM_SNAP=cgc3_bsd64_snapshot.ckpt
export CGC_OS_TYPE=freeBSD64

#export CGC_OS_TYPE=mixed_dld
#export CGC_OS_TYPE=mixed_lld
#export CGC_OS_TYPE=mixed
here=`pwd`
export INSTANCE=`echo $here | sed 's/[^0-9]//g'`
echo "INSTANCE is $INSTANCE"
export SIMICS=/mnt/simics/simics-4.8/simics-4.8.145
PY_MODS='/usr/share/pyshared/monitorCore'
if [ $CGC_DEVEL = "YES" ]; then
    PY_MODS='/mnt/cgcsvn/cgc/trunk/cgc-monitor/simics/monitorCore'
fi
echo CGC_DEVEL set to $CGC_DEVEL version $SIMICS_VER
echo "getting python from $PY_MODS"
killPortListeners 5022
killPortListeners 6022
killPortListeners 7022
# update the replay_master cfg node from config file
checkVMX
putReplayCfg $INSTANCE
clearPackages $INSTANCE
# gather packages, etc needed by the target
echo "collect4TargetStage"
collect4TargetStage
# update all config nodes from config files
# NO would require sql on slaves
#updateAllMasterCfgs
# ensure target/monitor nodes exist for this host
echo "check targetIP"
targetIP
cd ./targetStage
rm -f zk_hosts.txt
ln -s /mnt/simics/simicsWorkspace/targetStage/targetBin.tar
ln -s /mnt/cgc/zk_hosts.txt
cd ../
echo "param given: $1"
export LAUNCH_PARAM=$1
echo "Start simics"
mkfifo simics.stdin
hackStdIn.sh &
 
#./simics -no-win -p $PY_MODS/launchMonitor.py
#./simics -p $PY_MODS/launchMonitor.py < simics.stdin 
./simics -p $PY_MODS/launchMonitor.py 
if [ "$1" == "provision_bsd" ]; then
    if ./do_merge.sh bsd-provision-state/ bsd-provision-merge; then
       mv cgc-freebsd.craff cgc-freebsd.craff.bu
       mv bsd-provision-merge/thrower.disk.hd_image.craff cgc-freebsd.craff
       rm -r bsd-provision-state bsd-provision-merge
       echo "done provisioning bsd to disable txcsum, old version in cgc-freebsd.craff.bu"
    fi
fi
if [ "$1" == "provision_bsd64" ]; then
    if ./do_merge.sh bsd-provision-state/ bsd-provision-merge; then
       mv cgc-freebsd64.craff cgc-freebsd64.craff.bu
       mv bsd-provision-merge/thrower.disk.hd_image.craff cgc-freebsd64.craff
       rm -r bsd-provision-state bsd-provision-merge
       echo "done provisioning bsd to disable txcsum, old version in cgc-freebsd64.craff.bu"
    fi
fi
echo "back from launchMonitor"
