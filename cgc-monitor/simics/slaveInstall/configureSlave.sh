#
#In slave bios / security / System Security / VTx enabled / VTd-d enabled

#Install Ubuntu 14.04

#visudo and change the sudo entry to:
#    %sudo  ALL=(ALL) NOPASSWD:ALL
# MANUALLY copy /mnt/vmLib/cgcForensicsRepo/slaveLinuxConfig/sudoers to /etc/sudoers

export ME=`whoami`
FORENSICS_REPO=/mnt/vmLib/cgcForensicsRepo
install_working_dir=`pwd`

# Update the hosts file to include the other hosts
grep master /etc/hosts
greprc=$?
if [[ $greprc -eq 0 ]] ; then
    echo host already has master entry
else
    cat ./hosts-add | sudo tee --append /etc/hosts
fi
# work around Simics lmgrd license manager bug
sudo ln -s /lib64/ld-linux-x86-64.so.2 /lib64/ld-lsb-x86-64.so.3
sudo apt-get update
sudo apt-get -y install nfs-common

# mount vmLib via nfs, note the installrepo
# will be later overridden by the repo_master in 
# the configMgr
sudo mkdir -p /mnt/vmLib
sudo chmod a+rwx /mnt/vmLib
sudo chown $ME:$ME /mnt/vmLib
./nfsMount.sh installrepo

sudo ntpdate -u installrepo

sudo cp $FORENSICS_REPO/slaveLinuxConfig/sources.list /etc/apt/

#linux packages
source ./installSlaveApts.sh

source ./installZkShell.sh

#On the development machine, make sure the sources and
#runtime data are up to date.  From the development
#machine run:
#/mnt/cgcsvn/cgc/users/mft/simics/simicsWorkspace/collectSlaveRepo.sh
sudo mkdir -p /mnt/cgc
sudo chmod a+rwx /mnt/cgc
sudo chown $ME:$ME /mnt/cgc
sudo mkdir -p /mnt/simics
sudo chmod a+rwx /mnt/simics
sudo chown $ME:$ME /mnt/simics
cd /mnt/cgc
cp $FORENSICS_REPO/monitor.tar .
tar -xvf monitor.tar
cp /mnt/cgc/simics/slaveInstall/monitorSlaveBootstrap.sh .
cp /mnt/cgc/simics/slaveInstall/waitnet.sh .
mkdir -p /mnt/simics/simicsWorkspace
cd /mnt/simics/simicsWorkspace
#cp $FORENSICS_REPO/runtimeData.tar .
#tar -xvf runtimeData.tar
cp -r /mnt/cgc/simics/simicsScripts/targets .
#cp /mnt/vmLib/bigstuff/dredd-debian.craff .
if test "/mnt/vmLib/bigstuff/vp.craff" -nt "./vp.craff"
then
   echo Copy the .craff... will take a while
   cp -p /mnt/vmLib/bigstuff/vp.craff tmp.craff
   mv tmp.craff vp.craff
else
   echo vp.craff up to date already
fi

#cd /mnt/cgc/simics/slaveInstall
cd $install_working_dir
sudo cp monitorSlaveService /etc/init.d/
sudo chmod +x /etc/init.d/monitorSlaveService
sudo chown root:root /etc/init.d/monitorSlaveService
sudo update-rc.d monitorSlaveService defaults
sudo update-rc.d monitorSlaveService enable

# install java jars into /usr/lib
./installJavaLibJars.sh
#Get the public key of the target and add it to the slave's authorized keys.
grep cgc@debian-target ~/.ssh/authorized_keys
greprc=$?
if [[ $greprc -eq 0 ]] ; then
   echo pub key already in authorized_keys
else
   cat /mnt/cgc/simics/rebuild/id_rsa.pub | sudo tee --append ~/.ssh/authorized_keys
fi
./installSimics.sh

# start the lmgrd and build the workspaces
./monitorSlaveBootstrap.sh none
# accept the eula
cd /mnt/simics/simicsWorkspace
$install_working_dir/expectSim.sh

