#!/bin/bash
#
# Create a prep inject using the commence option
#
if [ "$#" -ne 4 ]; then
    echo "Create a prep inject snapshot"
    echo "Usage: next_prep.sh ini FD commence next_snap"
    exit
fi
inifile=$1
FD=$2
commence=$3
next_snap=$4
cmd="$RESIM_DIR/simics/fuzz_bin/next_prep_commence.simics FD=$FD commence=$commence snap_name=$next_snap"
resim $inifile -c "$cmd"
