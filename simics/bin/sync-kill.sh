#!/bin/bash
if [ ! -f drones.txt ]; then
   echo "No drones.txt file found"
   exit
fi
flist=$(cat drones.txt)
for f in $flist; do
    echo "Killing simics and afl on $f"
    scp $RESIM_DIR/simics/bin/kill-simics.sh $USER@$f:/tmp/
    ssh $USER@$f /tmp/kill-simics.sh
    scp $RESIM_DIR/simics/bin/kill-afl.sh $USER@$f:/tmp/
    ssh $USER@$f /tmp/kill-afl.sh
done
