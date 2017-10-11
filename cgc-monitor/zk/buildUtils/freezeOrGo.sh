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

done=False
sudo rm  -f ./freezeOrGo.txt
nohost="-o StrictHostKeyChecking=no"
while [ $done == "False" ]; do
    #scp $nohost $hostIP:/mnt/simics/simicsWorkspace$instance/targetStage/freezeOrGo.txt .
    echo "/tmp/simics-agent --download /mnt/simics/simicsWorkspace$instance/targetStage/freezeOrGo.txt"
    #echo "scp $nohost $hostIP:/mnt/simics/simicsWorkspace$instance/targetStage/freezeOrGo.txt ."
    /tmp/simics-agent --download /mnt/simics/simicsWorkspace$instance/targetStage/freezeOrGo.txt 
    if [ "$?" -eq 0 ] && [ -f freezeOrGo.txt ]; then 
       echo "found freezeOrGo.txt"
       done=True
    else
       echo "no freezeOrGo.txt file wait 2"
       sleep 2
    fi
done
value=`cat freezeOrGo.txt`
echo "freezeOrGo.txt value is $value"
if [ $value != "Go" ]; then
    echo "not told to go, told $value, bye"
    echo "ready" >ack.txt
    #scp $nohost ack.txt $hostIP:/mnt/simics/simicsWorkspace$instance/targetStage/
    #echo "scp $nohost ack.txt $hostIP:/mnt/simics/simicsWorkspace$instance/targetStage/"
    /tmp/simics-agent --upload ack.txt --to /mnt/simics/simicsWorkspace$instance/targetStage/
    echo "/tmp/simics-agent --upload ack.txt --to /mnt/simics/simicsWorkspace$instance/targetStage/"
    exit 1
fi

