#!/bin/bash
if [ ! -f drones.txt ]; then
   echo "No drones.txt file found"
   exit
fi
flist=$(cat drones.txt)
here=$(pwd)
base=$(basename $here)
aflout=$AFL_DATA/output/$base
seeds=$AFL_DATA/seeds/$base
echo "aflout is $aflseed"
for f in $flist; do
    if [ $f = $HOSTNAME ]; then
        echo "Um, your host is in the drones file?, skipping"
        continue
    fi
    echo "deleting afl output, seeds and logs on $f"
    ssh $USER@$f "rm -fr $aflout; rm -fr $seeds; rm -fr share; rm -f /tmp/resim.log; rm  -f /tmp/runAFL.log"
done
