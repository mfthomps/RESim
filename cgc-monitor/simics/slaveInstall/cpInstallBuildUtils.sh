#!/bin/bash
#
# Install debian package collection/update scripts on a target.
# Needed to update general mechanism of collectPackages / updatePackages
#
build_utils=`ls /mnt/vmLib/cgcForensicsRepo/monitorPackages_cfe/*build-utils*.deb`
base_name=$(basename $build_utils)
pscp -h hosts.txt -l mike $build_utils /tmp/$base_name
./mikessh.sh "sudo dpkg -i /tmp/$base_name"
