#!/bin/bash
#
#  Define path to the local RESim repo
#
if [[ -z "$RESIM" ]]; then
    export RESIM=/mnt/cgc-monitor/RESim
fi

if [ "$#" -ne 1 ]; then
    echo "usage: ./monitor.sh <target>"
    echo "   Where <target> is the base name of a RESim ini file"
    exit
fi
export SIMICS_VER=4.8
export RESIM_INI=$1
export RESIM_TARGET=$1
export SIMICS_WORKSPACE=`pwd`
export SIMICS=/mnt/simics/simics-4.8/simics-4.8.145
#
#  For use with driver components
#
rm -f driver-ready.flag
#
# Launch RESim
#
./simics -p $RESIM/simics/monitorCore/launchRESim.py -L $SIMICS_WORKSPACE
