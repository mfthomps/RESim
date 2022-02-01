#!/bin/bash
if [ ! -f drones.txt ]; then
   echo "No drones.txt file found"
   exit
fi
flist=$(cat drones.txt)
echo $flist
here=$(pwd)
base=$(basename $here)
aflout=$AFL_DATA/output/$base
echo "aflout is $aflseed"
for f in $flist; do
    echo $f
    ssh $USER@$f rm -fr $aflout
    ssh $USER@$f rm -fr $here
done
