#!/bin/bash
if [ ! -f drones.txt ]; then
   echo "No drones.txt file found"
   exit
fi
if [ "$#" -ne 1 ] || [ "$1" = "-h" ]; then
    echo "start-drones <target>"
    echo "   Start the drones named in drones.txt, and start a local AFL"
    exit
fi
target=$1
flist=$(cat drones.txt)
here=$(pwd)
base=$(basename $here)
aflout=$AFL_DATA/output/$base
rm -f /tmp/resimdie.txt
for f in $flist; do
    echo "Starting AFL on $f  target $target"
    ssh $USER@$f rm -f /tmp/resimdie.txt
    ssh -t $USER@$f bash -ic "'source ~/.resimrc';/usr/bin/nohup $RESIM_DIR/simics/bin/remoteAFL.sh $here $target" 
done
get-tars.sh 30 &
runAFL $target
echo "Back from runAFL"
touch /tmp/resimdie.txt
stop-drones.sh
pkill $(which get-tars.sh)
