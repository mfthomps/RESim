#!/bin/bash
#
#
#
if [ "$#" -lt 2 ]; then
    echo "driverReport.sh <ini> <FD> [backstop_cycles]"
    echo "Creates watch marks; syscall trace and coverage file from a checkpoint created with drive driver."
    exit
fi
rm /tmp/tri.*
ini=$1
export RESIM_FD=$2
if [ "$#" -eq 3 ]; then
    export BACKSTOP_CYCLES=$3
else
    export BACKSTOP_CYCLES=0
fi
if [ "$#" -eq 4 ]; then
    export RUN_CYCLES=$4
else
    export RUN_CYCLES=1000000000
fi
resim $1 -c $RESIM_DIR/simics/simicsScripts/msc/wm-driver.simics
#echo "START TRACE"
#resim $1 -c $RESIM_DIR/simics/simicsScripts/msc/trace-driver.simics
#echo "DONE TRACE"
#resim $1 -c $RESIM_DIR/simics/simicsScripts/msc/cover-driver.simics
#echo "Output in /tmp/tri.wm; tri.trace; tri.cover"
#wmMerge.py /tmp/tri.wm /tmp/tri.trace -c /tmp/tri.hits
