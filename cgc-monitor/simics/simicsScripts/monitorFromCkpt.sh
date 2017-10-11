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

export CGC_DEVEL=YES
export SIMICS_VER=4.8
export ZSIM=NO
#export SIMICS_VER=4.6
export INSTANCE=0
#export SIMICS=/mnt/simics/simics-4.8/simics-4.8.61
export SIMICS=/mnt/simics/simics-4.8/simics-4.8.145
#export SIMICS=/mnt/simics/simics-4.6/simics-4.6.84
export RUN_FROM_SNAP=mftx2.ckpt

PY_MODS='/usr/share/pyshared/monitorCore'
if [ $CGC_DEVEL = "YES" ]; then
    PY_MODS='/mnt/cgcsvn/cgc/branches/cqe/cgc-monitor/simics/monitorCore'
fi
echo CGC_DEVEL set to $CGC_DEVEL version $SIMICS_VER
echo "getting python from $PY_MODS"
CGC=/mnt/cgc
$CGC/simics/slaveInstall/checkVMX.sh
collect4TargetStage
cp $CGC/zk/py/replay_master.xml .

putReplayCfg $INSTANCE
putServiceCfg $INSTANCE
updateMasterCfg

#./simics -no-gui -no-win -p /mnt/cgcsvn/cgc/users/mft/simics/simicsScripts/launchMonitor.py
#./simics -batch-mode -p /mnt/cgcsvn/cgc/users/mft/simics/simicsScripts/launchMonitor.py 
#./simics -p $CGC/simics/simicsScripts/launchMonitor.py 
./simics -p $PY_MODS/launchMonitor.py
