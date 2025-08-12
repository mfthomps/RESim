#!/bin/bash
#
# Given an io file, create the first level of 
# newio files including the first watchmark json
# and then the new queue files found by createNewIOFiles.
#
echo "begin startNewIO.sh"
top_dir=~/newio
ini=$1
first_io=$2
target_prog=$3
target_fd=$4
here=$(pwd)
target=$(basename $here)
if [ "$#" -lt 4 ]; then
    echo "startNewIO.sh ini first_io target_prog target_fd"
    exit 1
fi
if [ ! -f $first_io ];then
    echo "$first_io not found"
    exit 1
fi
target_dir="$top_dir"/"$target"
mkdir -p $target_dir
mkdir -p "$target_dir"/queue
wm_dir="$target_dir"/trackio
mkdir -p $wm_dir
queue_dir="$target_dir"/queue/
cp $first_io $queue_dir
no_ext="${first_io%.*}" 
wm_file="$wm_dir"/"$first_io"
injectTarget.sh $ini $first_io $target_prog $target_fd $wm_file
playTarget.sh $ini $queue_dir $target_prog $target_fd
next_level_dir="$target_dir"/next_level
mkdir -p $next_level_dir
new_io_dir="$next_level_dir"/"$no_ext"
mkdir -p $new_io_dir
new_queue="$new_io_dir"/queue
createNewIOFiles.py $first_io $wm_file -o $new_queue
playTarget.sh $ini $new_queue $target_prog $target_fd
