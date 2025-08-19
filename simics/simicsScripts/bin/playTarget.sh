#!/bin/bash
echo "Begin playTarget.sh"
if [ "$#" -lt 2 ]; then
    echo "playTarget.sh <ini> <io_dir> <target> <target_fd> "
    echo "Runs playAFL for all files in a given queue directory for a target program and FD"
    exit
fi
INI_FILE=$1
export RESIM_IO_DIR=$2
export RESIM_TARGET_PROG=$3
export RESIM_TARGET_FD=$4
export RESIM_WM_FILE=$5
resim $INI_FILE -c $RESIM_DIR/simics/simicsScripts/new_inputs/play_dir_target.simics
