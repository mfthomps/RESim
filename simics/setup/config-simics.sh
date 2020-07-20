#!/bin/bash
#
# Configure Simics license for a server.  Run this after configuring the server
# for RESim and configuring a user for RESim.
#
cp lmgrdFix /usr/bin/
cp lmgrdFixService /etc/init.d/
sudo update-rd.d lmgrdFixService defaults
sudo service lmgrdFixService start
cd ~/workspace
sudo bin/vmp-kernel-install
sudo /mnt/simics/simics-4.8/simics-4.8.170/scripts/../vmxmon/scripts/install

