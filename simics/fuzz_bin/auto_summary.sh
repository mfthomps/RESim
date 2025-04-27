#!/bin/bash
#
#
#
if [ "$#" -ne 1 ]; then
    echo "Print a summary of the auto fuzzing status."
    echo "Usage: auto_summary.sh target"
    exit
fi
starting_ws=$1
ls -lrt ~/afl/output | grep next_ws
ws_list=$(ls ~/afl/output | grep next_ws)
for ws in $ws_list; do
    echo "ws is $ws"
    diffCoverage.py $starting_ws $ws | grep hit
    fuzz-summary.py $ws
done


