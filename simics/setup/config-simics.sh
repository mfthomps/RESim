#!/bin/bash
#
# Configure Simics license for a server.  Run this after configuring the server
# for RESim and configuring a user for RESim.
#
myMAC=`/sbin/ifconfig | grep eth0 | awk '{print toupper($5);}' | sed s/://g`
myFile=$myMAC.lic
licensepath=/mnt/simics/simics-4.8/simics-4.8.75/licenses/$myFile
echo "Close Simics after it starts"
cd ~/workspace
./simics-gui -license-file $licensepath
sudo bin/vmp-kernel-install
sudo /mnt/simics/simics-4.8/simics-4.8.170/scripts/../vmxmon/scripts/install

