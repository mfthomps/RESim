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
trace_dir="$target_dir"/traces
mkdir -p $wm_dir
mkdir -p $trace_dir
queue_dir="$target_dir"/queue/
cp $first_io $queue_dir
#no_ext="${first_io%.*}" 
wm_file="$wm_dir"/"$first_io"
trace_file="$trace_dir"/"$first_io"
echo "<><><><><>startNewIOi.sh Injecting $first_io"
injectTarget.sh $ini $first_io $target_prog $target_fd $wm_file
echo "<><><><><>startNewIOi.sh Injecting trace $first_io"
injectTrace.sh $ini $first_io $trace_file
echo "<><><><><><>startNewIO.sh Playing $first_io"
playTarget.sh $ini $queue_dir $target_prog $target_fd
next_level_dir="$target_dir"/next_level
mkdir -p $next_level_dir
new_io_dir="$next_level_dir"/"$first_io"
mkdir -p $new_io_dir
new_queue="$new_io_dir"/queue
echo "<><><><><><>startNewIO.sh call genIO.py with $target_dir"
#createNewIOFiles.py $first_io $wm_file -o $new_queue || exit
genIO.py $target_dir
echo "Playing target"
playAllTarget.sh $ini $next_level_dir $target_prog $target_fd || exit
echo "<><><><><><>startNewIO.sh Generating new watch marks"
genAllNewWatchmarks.sh $ini $next_level_dir $target_prog $target_fd || exit
echo "<><><><><><>startNewIO.sh call genAllIO.sh"
genAllIO.sh "$next_level_dir" || exit
playAllTarget.sh $ini $next_level_dir $target_prog $target_fd || exit
#playAllTarget.sh $ini "$next_level_dir"/file/next_level $target_prog $target_fd || exit
