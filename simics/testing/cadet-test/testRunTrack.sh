#!/bin/bash
echo "testRunTrack begin"
rm /tmp/runTrack*log
runTrack ubuntu_driver.ini -w cadet-tst
sleep 10
#tfile=$HOME/afl/output/cadet-tst/*_resim_1/trackio/id:000000,orig:seed.io
value=0x8048a08
gotit=$(grep 0x8048a08 $HOME/afl/output/cadet-tst/*_resim_*/trackio/*)
if [ -z "$gotit" ]; then
    echo "runTrack failed to find value $value"
    exit 1
else
    echo "runTrack passed"
fi 
