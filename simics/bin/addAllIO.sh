#!/bin/bash
#
# add all .io files from a named directory to the given AFL target
#
if [ "$#" -ne 2 ]; then
    echo "addAllIO.sh <directory> <target>"
    echo "   Add all .io files from a named directory to a named AFL target"
    exit
fi
direct=$1
target=$2
flist=$(ls $direct/*.io)
for f in $flist; do
    echo $f
    base=$(basename -- $f)
    echo "would call addInput.py $f $base"
    addInput.py $f $base
     
    
done
