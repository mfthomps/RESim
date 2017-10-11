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
exec >> /tmp/runIDS.log 2>&1
uname=`/tmp/getUname.sh`
POV=$1
echo "runIDS uname is $uname POV is $POV"
mkdir -p ~/replay
cd ~/replay
mkdir -p /tmp/tmpReplays
read hostIP instance < /tmp/host_ip.txt
export hostIP
export instance
echo host is $hostIP
/tmp/freezeOrGo.sh
if [ "$?" -ne 0 ]; then 
    echo "must have been an exit after freeze, bye"
    exit 1
fi
#/tmp/dodate.sh $hostIP
echo "did date"
nohost="-o StrictHostKeyChecking=no"
/tmp/simics-agent --download /mnt/simics/simicsWorkspace/targetStage/targetBin_$uname.tar 
#scp $nohost $hostIP:/mnt/simics/simicsWorkspace/targetStage/targetBin_$uname.tar .
#if [ "$?" -ne 0 ]; then 
#     echo "scp failed, try adding route"
#     sudo route add default gw 10.10.0.1
#     scp $nohost $hostIP:/mnt/simics/simicsWorkspace/targetStage/targetBin_$uname.tar .
#     if [ "$?" -ne 0 ]; then 
#          echo "scp of tar failed"; exit 1; fi
#fi
echo "did scp of deb"
tar -xvf targetBin_$uname.tar
echo "did tar"
if [ "$uname" != "FreeBSD" ] && [ "$uname" != "FreeBSD64" ]; then
    #tar -xvf cfe-pk.tar.gz
    sudo dpkg -i *.deb
    #sudo ethtool -K eth1 tx off rx off
    #sudo ethtool -K eth2 tx off rx off
    myIP_eth0=`/tmp/getMyIp eth0`
    myIP_eth1=`/tmp/getMyIp eth1`
    if [ $uname == "Linux64" ]; then
        sudo cp cfe-poll* /usr/bin
        sudo mkdir -p /usr/share/cgc-docs/
        sudo cp replay.dtd /usr/share/cgc-docs/
    fi
else
    #myIP_eth0=`/tmp/getMyIp bge0`
    myIP_eth0=`/tmp/getMyIp em0`
    myIP_eth1=172.16.128.1
    sudo ifconfig em1 $myIP_eth1 -txcsum -rxcsum
    myIP_eth2=172.16.0.2
    sudo ifconfig em2 $myIP_eth2 -rxcsum -txcsum
    sudo mkdir -p /usr/share/cgc-monitoring
    sudo tar -xvf ./cgc-monitor-target-services.tar -C /usr/bin service_master
    sudo tar -xvf ./cgc-monitor-target-services.tar -C /usr/bin replay_master
    sudo tar -xvf ./cgc-monitor-target-services.tar -C /usr/share/cgc-monitoring/ service_master.dtd
    sudo tar -xvf ./cgc-monitor-target-services.tar -C /usr/share/cgc-monitoring/ replay_master.dtd

fi
echo "my ip_eth0 is $myIP_eth0"
echo "my ip_eth1 is $myIP_eth1"
/tmp/simics-agent --download /mnt/cgc/zk_hosts.txt
k_file=ksections-$myIP_eth0.cfg
if [ "$uname" != "FreeBSD" ] && [ "$uname" != "FreeBSD64" ]; then
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
#cb-proxy --host 172.16.0.1 --port 9999
echo " " > /tmp/tmpReplays/no_filter.rules
echo "service_master $hostIP $instance $myIP_eth1 9999 -ids 9999 $POV &"
service_master $hostIP $instance $myIP_eth1 9999 -ids 9999 $POV &
replay_master $hostIP $instance $myIP_eth1 9999 &
