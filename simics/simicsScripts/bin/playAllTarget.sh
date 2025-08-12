#!/bin/bash
echo "Begin playAllTarget.sh"
if [ "$#" -lt 2 ]; then
    echo "playAllTarget.sh <ini> <level_dir> <target> <target_fd> "
    echo "Runs playAFL for all queue directories beneath a given level directory for a target program and FD"
    exit
fi
INI_FILE=$1
export LEVEL_DIR=$2
export RESIM_TARGET_PROG=$3
export RESIM_TARGET_FD=$4
dlist=$(ls $LEVEL_DIR)
for d in $dlist; do
    path="$LEVEL_DIR"/"$d"
    if [ -d $path ]; then
        export RESIM_IO_DIR="$path"/queue
        echo "Begin playAFL for $RESIM_IO_DIR"
        resim $INI_FILE -c $RESIM_DIR/simics/simicsScripts/new_inputs/play_dir_target.simics
        next_level="$path"/next_level
        if [ -d next_level ]; then
            playAllTarget.sh $INI_FILE $next_level $RESIM_TARGET_PROG $RESIM_TARGET_FD 
        fi
    fi
done
