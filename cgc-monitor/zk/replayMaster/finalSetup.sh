#!/bin/bash
#
#  Update replay and the monitor replay master.
#  Run the ksections.py to get kernel code text and sizes (the libs of which change
#  between boots.  Put the results into the workspace of the host running simics.
#  Also get the offset in the player at which user data is consumed, and put that
#  to the host workspace as well.
# 
sudo route add default gw 10.10.0.1
exec >> ./finalSetup.log 2>&1

echo in final setup
replay=`ls cgc-replay*.deb`
master=`ls cgc-monitor*.deb`
echo using replay package: $replay
echo using replay master package: $master

#sudo apt-get install openssh-server

ksections.py > ksections.cfg
putTFTP.sh ksections.cfg
echo ran ksections

read hostIP instance < myip.txt
echo myip is $hostIP
dodate.sh $hostIP
echo set date to `date`	
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

doTFTP.sh targetStage/zk_hosts.txt

sudo /etc/init.d/ssh restart
mkdir -p ./tmpReplays
LOG=replay.log-$instance
rm -f ./$LOG
exec >> $LOG 2>&1
replay_master $hostIP $instance
