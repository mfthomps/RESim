#!/bin/bash
exec 1<&-
exec 2<&-
exec 1<>/tmp/installZkService.log
exec 2>&1
# Install the zookeeper shell as a service
here=`pwd`
#cd /mnt/cgc/zk
if [ -f "/etc/init.d/zookeeperService" ]
then
    sudo /etc/init.d/zookeeperService stop
fi
cd /mnt/cgc/simics/masterInstall
sudo cp zookeeperService /etc/init.d/
sudo chmod +x /etc/init.d/zookeeperService
sudo chown root:root /etc/init.d/zookeeperService
sudo update-rc.d zookeeperService defaults
sudo update-rc.d zookeeperService enable
sudo /etc/init.d/zookeeperService start
cd $here
