#!/bin/bash
if [ ! -f drones.txt ]; then
   echo "No drones.txt file found"
   exit
fi
flist=$(cat drones.txt)
here=$(pwd)
base=$(basename $here)
aflseed=$AFL_DATA/seeds/$base
for f in $flist; do
    echo "Syncing workspace and seeds with $f"
    rsync -a --exclude 'logs' $here/ $USER@$f:$here/
    ssh $USER@$f mkdir -p $aflseed
    rsync -a $aflseed/ $USER@$f:$aflseed/
done
