#!/bin/bash
if [ "$#" -lt 2 ]; then
    echo "injectTarget.sh <ini> <io_file> <target> <target_fd> "
    echo "Runs injectIO for a target program and FD"
    exit
fi
INI_FILE=$1
export RESIM_IO_FILE=$2
export RESIM_TARGET_PROG=$3
export RESIM_TARGET_FD=$4
export RESIM_WM_FILE=$5
resim $INI_FILE -c $RESIM_DIR/simics/simicsScripts/new_inputs/inject_target.simics
