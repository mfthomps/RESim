#!/bin/bash
#install Simics on a deployable
exec 1<&-
exec 2<&-
exec 1<>/tmp/installSimics.log
exec 2>&1
REPO=/mnt/vmLib/bigstuff
ME=`whoami`
sudo mkdir -p /mnt/cgc
sudo mkdir -p /mnt/cgc/simics
sudo chmod -R a+rwx /mnt/cgc
sudo chown -R $ME:$ME /mnt/cgc
sudo mkdir -p /mnt/simics
sudo mkdir -p /mnt/simics/simicsWorkspace
sudo chmod -R a+rwx /mnt/simics
sudo chown -R $ME:$ME /mnt/simics
here=`pwd`
cd /mnt/simics
tar -xvf $REPO/simics-4.8.tar.gz 
/mnt/cgc/simics/slaveInstall/getMyLicenses.sh
cd /mnt/simics/simicsWorkspace
/mnt/simics/simics-4.8/simics-4.8.75/bin/workspace-setup --ignore-existing-files

cd $here
