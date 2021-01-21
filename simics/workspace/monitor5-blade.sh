#!/bin/bash
#
#  Define path to the local RESim repo
#
echo "RESIM starts as $RESIM"
if [[ -z $RESIM ]]; then
    export RESIM=$HOME/git/RESim
fi
echo "RESIM is $RESIM"

if [ "$#" -ne 1 ]; then
    echo "usage: ./monitor.sh <target>"
    echo "   Where <target> is the base name of a RESim ini file"
    exit
fi
export SIMICS_VER=5
export RESIM_INI=$1
export SIMICS_WORKSPACE=`pwd`
export SIMICS=/mnt/re_images/simics5/install/simics-5/simics-5.0.181
#
#  For use with driver components
#
rm -f driver-ready.flag
#
# Launch RESim
#
./simics -p $RESIM/simics/monitorCore/launchRESim.py -L $SIMICS_WORKSPACE
