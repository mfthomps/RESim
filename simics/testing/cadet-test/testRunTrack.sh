#!/bin/bash
rm /tmp/runTrack*log
runTrack ubuntu_driver.ini cadet-tst
sleep 10
tfile=$HOME/afl/output/cadet-tst/wer-7910_resim_1/trackio/id:000000,orig:seed.io
if [ -f $tfile ]; then
    gotit=$( grep 0x8048a08 $tfile )
    if [ -z "$gotit" ]; then
        echo "runTrack failed to find value in $tfile"
        exit 1
    else
        echo "runTrack passed"
    fi 
else
    echo "runTrack failed to create file at $tfile"
    exit 1
fi
