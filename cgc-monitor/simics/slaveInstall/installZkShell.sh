#!/bin/bash
exec 1<&-
exec 2<&-
exec 1<>/tmp/installZkShell.log
exec 2>&1
# Install the zookeeper shell as a service
if [ -f "/etc/init.d/zkShellService" ]
then
    sudo /etc/init.d/zkShellService stop
fi
sudo dpkg -i /mnt/vmLib/cgcForensicsRepo/monitorPackages_cfe/cgc-monitor-zk-shell*.deb
sudo update-rc.d zkShellService defaults
sudo update-rc.d zkShellService enable
sudo /etc/init.d/zkShellService start
