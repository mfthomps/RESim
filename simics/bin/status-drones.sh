#!/bin/bash
if [ ! -f drones.txt ]; then
   echo "No drones.txt file found"
   exit
fi
flist=$(cat drones.txt)
here=$(pwd)
base=$(basename $here)
aflout=$AFL_DATA/output/$base
for f in $flist; do
    echo $f
    ssh -t $USER@$f bash -ic "cd $here;cd $here;pwd;source ~/.resimrc;$RESIM_DIR/simics/bin/fuzzhappening.py"
done
