#!/bin/bash
if [ ! -f drones.txt ]; then
   echo "No drones.txt file found"
   exit
fi
flist=$(cat drones.txt)
for f in $flist; do
    echo "Setting time server on $f"
    now=$(date)
    echo "time is $now"
    ssh $USER@$f "sudo date --set=\"$now\""
    scp $RESIM_DIR/simics/bin/fixtime.sh $USER@$f:/tmp/
    ssh $USER@$f /tmp/fixtime.sh
done
