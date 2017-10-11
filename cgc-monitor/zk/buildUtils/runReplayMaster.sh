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
# Bootstrap script for simulated targets.  Get the IP of the 
# Simics host, 
#
exec >> /tmp/runReplayMaster.log 2>&1
uname=`/tmp/getUname.sh`
echo "runReplayMaster.sh, uname is $uname"
mkdir -p ~/replay
cd ~/replay
mkdir -p /tmp/tmpReplays
read hostIP instance < /tmp/host_ip.txt
export hostIP
export instance
echo host is $hostIP instance: $instance
#/tmp/dodate.sh $hostIP
#echo "did date"
export nohost="-o StrictHostKeyChecking=no"
/tmp/freezeOrGo.sh
if [ "$?" -ne 0 ]; then 
    echo "must have been an exit after freeze, bye"
    exit 1
fi
date
#scp $nohost $hostIP:/mnt/simics/simicsWorkspace/targetStage/targetBin_$uname.tar .
/tmp/simics-agent --download /mnt/simics/simicsWorkspace/targetStage/targetBin_$uname.tar 
#if [ "$?" -ne 0 ]; then 
#     echo "scp failed, try adding route"
#     sudo route add default gw 10.10.0.1
#     scp $nohost $hostIP:/mnt/simics/simicsWorkspace/targetStage/targetBin_$uname.tar .
#     if [ "$?" -ne 0 ]; then 
#          echo "scp failed"; exit 1; fi
#fi
echo "did scp of tar"
date
#doTFTP.sh targetStage/targetBin.tar
tar -xvf targetBin_$uname.tar
echo "did tar"
POV=""
if [ $uname != "FreeBSD" ] && [ "$uname" != "FreeBSD64" ]; then
    #tar -xvf cfe-pk.tar.gz
    sudo dpkg -i *.deb
    if [ $uname == "Linux64" ]; then
        sudo cp cfe-poll* /usr/bin
        sudo mkdir -p /usr/share/cgc-docs/
        sudo cp replay.dtd /usr/share/cgc-docs/
    else
        POV="POV"
    fi
    #sudo ethtool -K eth0 tx off rx off
    #sudo ethtool -K eth1 tx off rx off
    myIP_eth0=`/tmp/getMyIp eth0`
    myIP_eth1=`/tmp/getMyIp eth1`
else
    #myIP_eth0=`/tmp/getMyIp bge0`
    myIP_eth0=`/tmp/getMyIp em0`
    myIP_eth1=172.16.128.200
    #sudo ifconfig bge0 -txcsum -rxcsum
    #sudo ifconfig bge1 $myIP_eth1 -txcsum -rxcsum
    sudo ifconfig em1 $myIP_eth1 -txcsum -rxcsum
    #sudo ifconfig em2 -txcsum -rxcsum
    sudo mkdir -p /usr/share/cgc-monitoring
    sudo mkdir -p /usr/share/cgc-docs/
    sudo cp replay.dtd /usr/share/cgc-docs/
    sudo tar -xvf ./cgc-monitor-target-services.tar -C /usr/bin replay_master
    sudo tar -xvf ./cgc-monitor-target-services.tar -C /usr/share/cgc-monitoring/ replay_master.dtd
    sudo PATH=/usr/local/bin:$PATH dpkg -i *.deb
    POV="POV"
fi
echo "my ip_eth0 is $myIP_eth0"
echo "my ip_eth1 is $myIP_eth1"
/tmp/simics-agent --download /mnt/cgc/zk_hosts.txt
k_file=ksections-$myIP_eth0.cfg
if [ $uname != "FreeBSD" ] && [ "$uname" != "FreeBSD64" ]; then
    /tmp/ksections.py $uname > /tmp/$k_file.tmp
    mv /tmp/$k_file.tmp /tmp/$k_file
    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
else
    /tmp/bsdKSections.sh > /tmp/$k_file.tmp
    mv /tmp/$k_file.tmp /tmp/$k_file
fi
#scp $nohost /tmp/$k_file $hostIP:/mnt/simics/simicsWorkspace$instance
/tmp/simics-agent --upload /tmp/$k_file 
if [ "$?" -ne 0 ]; then 
     echo "scp of /tmp/$k_file to host failed"
     exit 1
fi
echo "did copy of ksections"
#scp $nohost $hostIP:/mnt/cgc/zk_hosts.txt .
#cfe-pov-negotiator -i 127.0.0.1 -p 20000 >negotiate.txt 2>&1 &
echo "replay_master $hostIP $instance $myIP_eth1 9999 $POV &"
replay_master $hostIP $instance $myIP_eth1 9999 $POV &
#replay_wrapper.sh $hostIP $instance $myIP_eth1 9999 $POV &
