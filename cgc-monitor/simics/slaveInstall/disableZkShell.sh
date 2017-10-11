#!/bin/bash
exec 1<&-
exec 2<&-
exec 1<>/tmp/disableZkShell.log
exec 2>&1
# stop and disable zookeeper shell as a service
here=`pwd`
#cd /mnt/cgc/zk
#tar -xvf /mnt/vmLib/cgcForensicsRepo/zkShell.tar
sudo dpkg --purge cgc-monitor-zk-shell
sudo pkill java
if [ -f "/etc/init.d/zkShellService" ]
then
    sudo /etc/init.d/zkShellService stop
fi
cd /mnt/cgc/zk/zkShell
sudo update-rc.d zkShellService disable
sudo rm /etc/init.d/zkShellService
cd $here
