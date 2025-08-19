#!/bin/bash
#
# Use injectTarget.sh to generate watch marks for each io file found in a given directory
#
echo "Begin genNewWatchmarks.sh"
if [ "$#" -lt 4 ]; then
    echo "genNewWatchmarks.sh <ini> <io_dir> <target> <targetFD>"
    echo "Creates watch marks for all input files in a given directory, putting results in trackio at same directory level."
    exit
fi
#
#  Assumes the given io_dir is a queue dir.  Results will go in the trackio directory at the same level as the queue
#
ini_file=$1
iodir=$2
target=$3
target_fd=$4

queue_parent=$(dirname $iodir)
wmdir="$queue_parent"/trackio
if [ -f $wmdir ]; then
    echo "$wmdir already exists"
fi
mkdir -p $wmdir
abs_wm=$(realpath $wmdir)
io_list=$(ls $iodir)
for file in $io_list; do
    wm_out="$abs_wm"/"$file"
    io_file="$iodir"/"$file"
    injectTarget.sh $ini_file $io_file $target $target_fd $wm_out
    echo "done $file"
done
