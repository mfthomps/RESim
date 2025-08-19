#!/bin/bash
#
# Use createNewIOFiles to generate new input files derived from each file in the queue
# subdirectory of the given directory and its correpsonding trackio file.  
# The output will be beneath a "next_level/<name>" subdirectory of the given 
# directory where <name> is the basename of the each input file.
#
echo "Begin genIO.sh"
if [ "$#" -lt 1 ]; then
    echo "genIO.sh directory"
    exit 1
fi
input_dir=$1
queue_dir="$input_dir"/queue
if [ ! -d $queue_dir ]; then
    echo "$queue_dir not found"
    exit
fi
abs_queue_dir=$(realpath $queue_dir)
echo "Input files in $abs_queue_dir"
wm_dir="$input_dir"/trackio
if [ ! -d $wm_dir ]; then
    echo "$wm_dir not found"
    exit
fi
abs_wm_dir=$(realpath $wm_dir)
echo "Input trackio watchmarks in $abs_wm_dir"
next_level_dir="$input_dir"/next_level
mkdir -p $next_level_dir
cd $next_level_dir
flist=$(ls $abs_queue_dir)
for file in $flist; do
    wm_file="$abs_wm_dir"/"$file"
    in_file="$abs_queue_dir"/"$file"
    if [ ! -f $wm_file ]; then
        echo "did not find $wm_file, bail"
        exit
    fi
    new_dir_name="$next_level_dir"/"${file%.*}"/queue
    mkdir -p $new_dir_name
    echo "new dir $new_dir_name"
    createNewIOFiles.py $in_file $wm_file -o $new_dir_name
done
