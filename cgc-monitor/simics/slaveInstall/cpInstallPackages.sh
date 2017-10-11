#!/bin/bash
#
# copy and install each monitor package to the set of 
# pss hosts.  Note, only intended to run once.  Thereafter,
# package updates are retrieved from the /mnt/vmLib on each 
# start of the monitor
#
packages=`ls /mnt/vmLib/cgcForensicsRepo/monitorPackages/*.deb`
for pack in $packages
do
    base_name=$(basename $pack)
    echo "installing $base_name"
    pscp -h hosts.txt -l mike $pack /tmp/$base_name
    ./mikessh.sh "sudo dpkg -i /tmp/$base_name"
done
