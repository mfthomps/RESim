#!/bin/bash
#
# copy and execute the forensics monitor slave installation scripts
# NOTE: the last step will start simics lmgrd, which needs network devices
# to be named eth0.  So first use the fixNetwork.sh
./mikessh.sh "rm -fr /tmp/slaveInstall"
pscp -h hosts.txt -l mike --recursive /mnt/cgcsvn/cgc/users/mft/simics/slaveInstall /tmp/
pscp -h hosts.txt  -l mike doSlave.sh ~/
./cpZkHosts.sh
./mikessh.sh "chmod a+x /tmp/slaveInstall/*"
./mikessh.sh "sudo cp /tmp/slaveInstall/sources.list /etc/apt/"
./mikessh.sh "./doSlave.sh"

