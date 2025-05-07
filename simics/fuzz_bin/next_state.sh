#!/bin/bash
#
# Run the next_state.simics to create a new checkpoint 
# after consuming a queue file
#
if [ "$#" -ne 4 ]; then
    echo "Drive to next state by ingesting a queue file"
    echo " usage: next_state.sh ini next_snap queue_file FD"
    echo "got params $@"
    exit
fi
# name of ini file
inifile=$1
# name of new snaphsot
next_snap=$2
# name of queue file
qfile=$3
# FD for runToIO to ensure we've read data before doing coverage
FD=$4
echo "queue file is $qfile"
echo "next_snap is $next_snap"
echo "FD is $FD"
sed "s%REPLACE_THIS%$qfile%" next_state.directive > tmp.directive
cmd="$RESIM_DIR/simics/fuzz_bin/next_state.simics snap_name=$next_snap FD=$FD"
resim $inifile -c "$cmd"
exit 1
