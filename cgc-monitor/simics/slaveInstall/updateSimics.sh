#!/bin/bash
# update Simics on a deployable
# assumes the "expectSim.sh" script was put into /tmp,
# to page through the simics license agreement
exec 1<&-
exec 2<&-
exec 1<>/tmp/updateSimics.log
exec 2>&1
export REPO=/mnt/vmLib/bigstuff
here=`pwd`
cd /mnt/simics
tar -xvf $REPO/simics-4.8.tar.gz 
mkdir -p /mnt/simics/simicsWorkspace
cd /mnt/simics/simicsWorkspace
/mnt/simics/simics-4.8/simics-4.8.75/bin/workspace-setup --ignore-existing-files
getMyLicenses
/tmp/expectSim.sh

cd $here
