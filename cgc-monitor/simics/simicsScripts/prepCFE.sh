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

# run on each host to prep simics environment for CFE
#
here=`pwd`
cd /mnt/simics/simics-4.8
sudo tar -xf /mnt/vmLib/bigstuff/simics-4.8.tar.gz
cp /usr/share/cgc-monitor/vagrant_insecure_key ~/.ssh/
chmod 0600 ~/.ssh/vagrant_insecure_key
HAS_VAGRANT=$(grep 'vagrant' ~/.ssh/config)
if [ -z "$HAS_VAGRANT" ]; then
    echo no vagrant entry
    cat /usr/share/cgc-monitor/ssh-config-add >>~/.ssh/config
else
    echo already has vagrant entry
fi
SIMICS_RUN_BASE=/mnt/simics/simicsWorkspace
SLAVE_COUNT=11
i="0"
while [ $i -lt $SLAVE_COUNT ]
do
    SIMICS_RUN=$SIMICS_RUN_BASE$i
    mkdir -p $SIMICS_RUN
    chmod 777 $SIMICS_RUN
    cd $SIMICS_RUN
    updateWorkspace.sh
    mkdir -p ./targetStage
    chmod 777 ./targetStage
    ln -s $SIMICS_RUN_BASE/linux64
    cd ./targetStage
    ln -s $SIMICS_RUN_BASE/targetStage/targetBin.tar
    cd ../
    putReplayCfg $i
    putServiceCfg $i
    i=$[$i+1]

done
# cd to someplace not a work directory or lmgrd gets stupid[er]
cd /mnt/simics/simics-4.8
source `which getMyLicenses`
echo "wait for lmgrbage to start"
sleep 5
# read the eula
i="0"
SIMICS_RUN=$SIMICS_RUN_BASE$i
cd $SIMICS_RUN
expectSim.sh
