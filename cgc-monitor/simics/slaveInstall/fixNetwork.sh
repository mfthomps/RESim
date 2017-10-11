#!/bin/bash
# fix the network interface names from em1 to eth0
pscp -h hosts.txt -l mike /mnt/cgcsvn/cgc/users/mft/simics/slaveInstall/doGrub.sh ~/
pscp -h hosts.txt -l mike /mnt/cgcsvn/cgc/users/mft/simics/slaveInstall/grub ~/
pscp -h hosts.txt -l mike /mnt/cgcsvn/cgc/users/mft/simics/slaveInstall/interfaces ~/
./mikessh.sh "chmod a+x ./doGrub.sh"
./mikessh.sh "./doGrub.sh"

