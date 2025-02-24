#!/bin/bash
echo "testDedupe begin"
dedupCoverage.py ubuntu_driver.ini cadet-tst
ufile=$HOME/afl/output/cadet-tst/cadet-tst.unique
if [ -f $ufile ]; then
    num_paths=$(grep -o coverage /home/mike/afl/output/cadet-tst/cadet-tst.unique | wc -l)
    if [ "$num_paths" != "3" ] && [ "$num_paths" != "4" ]; then
        echo "testDedupe failed to find value in $ufile"
        exit 1
    else
        echo "testDedupe passed"
    fi
else
    echo "testDedup failed to create file at $ufile"
    exit 1
fi
