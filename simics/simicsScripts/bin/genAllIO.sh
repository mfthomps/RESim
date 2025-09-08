#!/bin/bash
#
# Use createNewIOFiles to generate new input files for each file in the queue
# subdirectory of each subdirectory of a given level directory.  The output will be beneath a "next_level/<name>"
# subdirectory of the given directory where <name> is the basename of the each input file.
#
echo "Begin genAllIO.sh"
if [ "$#" -lt 1 ]; then
    echo "genIO.sh directory"
    exit 1
fi
level_dir=$1
dlist=$(ls $level_dir)
for d in $dlist; do
    path="$level_dir"/"$d"
    if [ -d $path ]; then
        echo "call genIO.py for $path"
        genIO.py $path
        #echo "genIO.sh $path"
    fi
done
