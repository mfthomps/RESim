#!/bin/bash
if [ ! -f drones.txt ]; then
   echo "No drones.txt file found"
   exit
fi
target=$1
flist=$(cat drones.txt)
echo $flist
here=$(pwd)
base=$(basename $here)
aflout=$AFL_DATA/output/$base
echo "aflout is $aflseed"
for f in $flist; do
    echo $f
    ssh $USER@$f rm -f /tmp/resimdie.txt
    ssh -t $USER@$f bash -ic "echo 'here is $here';cd $here;pwd;source ~/.resimrc;echo \"resimdir is $RESIM_DIR\";$RESIM_DIR/simics/bin/runAFL $target -r" &
done
