#!/bin/bash
if [ ! -f drones.txt ]; then
   echo "No drones.txt file found"
   exit
fi
target=$1
flist=$(cat drones.txt)
here=$(pwd)
base=$(basename $here)
aflout=$AFL_DATA/output/$base
echo "aflout is $aflseed"
for f in $flist; do
    echo Stopping RESim on $f
    ssh  $USER@$f touch /tmp/resimdie.txt
done
