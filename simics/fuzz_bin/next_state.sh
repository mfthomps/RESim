#!/bin/bash
#
# Run the next_state.simics to create a new checkpoint 
# after consuming a queue file
#
if [ "$#" -ne 3 ]; then
    echo "Drive to next state by ingesting a queue file"
    echo " usage: next_state.sh ini next_snap queue_file"
    echo "got params $@"
    exit
fi
# name of ini file
inifile=$1
# name of new snaphsot
next_snap=$2
# name of queue file
qfile=$3
echo "queue file is $qfile"
sed "s%REPLACE_THIS%$qfile%" next_state.directive > tmp.directive
cmd="$RESIM_DIR/simics/fuzz_bin/next_state.simics snap_name=$next_snap"
resim $inifile -c "$cmd"
