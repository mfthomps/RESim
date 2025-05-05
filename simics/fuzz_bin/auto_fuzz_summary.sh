#!/bin/bash
#
# Look for hangs or crashes in fuzz sessions named by targets in the auto_ws directory
#
ws_list=$(ls auto_ws)
for ws in $ws_list; do
    crashes=$(fuzz-summary.py $ws | grep crashes | awk '{print $1}')
    if [[ $crashes != "0" ]]; then
        echo $ws $crashes
    fi
    hangs=$(fuzz-summary.py $ws | grep hangs | awk '{print $1}')
    if [[ $hangs != "0" ]]; then
        echo $ws $hangs
    fi
done
