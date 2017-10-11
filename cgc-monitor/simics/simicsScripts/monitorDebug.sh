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
# Start a cgc monitor for use with the Ida Client or the autoAnalysis module
# Optional argument identifies the debug client to which this montitor
# will be dedicated.
#
auto_arg=""
if [ ! -z $1 ]; then
    if [ "$1" == "auto" ];then
       package_arg=""
       auto_arg=$1
    else
       package_arg=$1
    fi
fi
export CGC_DEVEL=NO
export SIMICS_VER=4.8
export ONE_BOX=NO
export RUN_FROM_SNAP=cgc3_bsd64_snapshot.ckpt
export CGC_OS_TYPE=freeBSD64
export ZSIM=YES
export CGC_DEVEL=NO
export SIMICS_VER=4.8
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
# update the replay_master cfg node from config file
checkVMX
putReplayCfg $INSTANCE
putServiceCfg $INSTANCE
clearPackages $INSTANCE
putPackages $INSTANCE debug $package_arg &
# gather packages, etc needed by the target
collect4TargetStage
# update all config nodes from config files
# NO would require sql on slaves
#updateAllMasterCfgs
# ensure target/monitor nodes exist for this host
targetIP
cd ./targetStage
#rm -f zk_hosts.txt
ln -s /mnt/simics/simicsWorkspace/targetStage/targetBin.tar
#ln -s /mnt/cgc/zk_hosts.txt
cd ../

#
# use a fifo as stdin for the simics instance
# create a shell to keep the fifo open
# other functinos will write the fifo to
# stop simics & to close out a failed debug session
#
rm -f simics.stdin
rm -f simics.stdout
autoClient.py $auto_arg &
sleep 1
./simics -p $PY_MODS/launchMonitor.py < simics.stdin > simics.stdout
rm simics.stdin
PROC=$(ps | grep '[h]ackStdIn' | grep -v tail | awk '{print $1}')
if [ -z "$PROC" ]; then
    echo no hackStdIn
else
    echo "hackStdIn running as $PROC"
    kill -9 $PROC
fi
PROC=$(ps | grep '[p]utPackages $INSTANCE' | grep -v tail | awk '{print $1}')
if [ -z "$PROC" ]; then
    echo no putPackages
    echo "PROC=$(ps | grep '[p]utPackages $INSTANCE' | grep -v tail | awk '{print $1}')"
else
    echo "putPackages running as $PROC"
    kill -9 $PROC
fi

