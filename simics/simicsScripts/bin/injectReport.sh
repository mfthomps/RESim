#!/bin/bash
if [ "$#" -lt 2 ]; then
    echo "injectReport.sh <ini> <file> "
    echo "Creates watch marks; syscall trace and coverage file from a checkpoint created with prepInject."
    exit
fi
rm /tmp/tri.*
ini=$1
cp $2 /tmp/tri.io
rm -f logs/sys*txt
resim $1 -c $RESIM_DIR/simics/simicsScripts/msc/wm-inject.simics
resim $1 -c $RESIM_DIR/simics/simicsScripts/msc/trace-inject.simics
cp logs/sys*txt /tmp/tri.trace || exit
resim $1 -c $RESIM_DIR/simics/simicsScripts/msc/cover-inject.simics
cp /tmp/playAFL.hits /tmp/tri.hits
echo "Output in /tmp/tri.wm; tri.trace; tri.cover"
wmMerge.py /tmp/tri.wm /tmp/tri.trace -c /tmp/playAFL.coverage
