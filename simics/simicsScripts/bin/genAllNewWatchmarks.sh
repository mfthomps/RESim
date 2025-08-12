#!/bin/bash
#
# Use genNewWatchmarks.sh to generate watch marks for each io file found in each subdirectory
# of a given level directory
#
echo "Begin genAllNewWatchmarks.sh"
if [ "$#" -lt 4 ]; then
    echo "genAllNewWatchmarks.sh <ini> <level_dir> <target> <targetFD>"
    echo "Calls genNewWatchmarks.sh for each subdirectory of a given level directory."
    exit
fi
#
#
ini_file=$1
level_dir=$2
target=$3
target_fd=$4

dlist=$(ls $level_dir)
for d in $dlist; do
    path="$level_dir"/"$d"
    if [ -d $path ]; then
        io_dir="$path"/queue
        genNewWatchmarks.sh $ini_file $io_dir $target $target_fd
    fi
done
