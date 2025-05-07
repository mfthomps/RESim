#!/bin/bash
#
# Create a prep inject using the count option.
#
if [ "$#" -ne 4 ]; then
    echo "Create a prep inject snapshot"
    echo "Usage: next_prep.sh ini FD count next_snap"
    exit
fi
inifile=$1
FD=$2
count=$3
next_snap=$4
cmd="$RESIM_DIR/simics/fuzz_bin/next_prep.simics FD=$FD count=$count snap_name=$next_snap"
resim $inifile -c "$cmd"
