#!/bin/bash
#
# test_track
#
# create a json to inject via drive-driver
genJsonIO.py -n baseline.io -o baseline.json -w
# start from uhttp running (though not scheduled)
sed -i 's/RUN_FROM_SNAP.*$/RUN_FROM_SNAP=uhttpd_400/' fvp.ini
resim fvp.ini -c test_track.simics
line=$(grep "Copy 102 bytes from" my.wm)
if [ -z "$line" ]; then
    echo "test_track failed to find Copy 102 bytes"
    exit 1
else
    echo "test track passed"
fi
