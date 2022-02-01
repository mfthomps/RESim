#!/bin/bash
if [ ! -f drones.txt ]; then
   echo "No drones.txt file found"
   exit
fi
flist=$(cat drones.txt)
echo $flist
here=$(pwd)
base=$(basename $here)
aflseed=$AFL_DATA/seeds/$base
echo "aflseed is $aflseed"
for f in $flist; do
    echo $f
    rsync -a --exclude 'logs' $here/ $USER@$f:$here/
    ssh $USER@$f mkdir -p $aflseed
    rsync -a $aflseed/ $USER@$f:$aflseed/
done
