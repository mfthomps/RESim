#!/bin/bash
dedupCoverage.py ubuntu_driver.ini cadet-tst
ufile=$HOME/afl/output/cadet-tst/cadet-tst.unique
if [ -f $ufile ]; then
    gotit=$( grep "id:000000,orig" $ufile )
    if [ -z "$gotit" ]; then
        echo "testDedupe failed to find value in $ufile"
        exit 1
    else
        echo "testDedupe passed"
    fi
else
    echo "testDedup failed to create file at $ufile"
    exit 1
fi
