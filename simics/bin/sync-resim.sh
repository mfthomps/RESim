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
    echo "Syncing RESim code with $f"
    rsync -a $RESIM_DIR/ $USER@$f:$RESIM_DIR/
    rsync -a $AFL_DIR/ $USER@$f:$AFL_DIR/
    rsync -a $HOME/.resimrc $USER@$f:$HOME/.resimrc
    # start the license manager
    ssh -t $USER@rb8 bash -ic "'cd /tmp/';nohup /usr/bin/lmgrdFix"
    # make sure the VMP kernel module is loaded
    ssh -t $USER@$f /bin/bash -ic "SIMICS_BASE_PACKAGE=\"/mnt/simics/simics-4.8/simics-4.8.170\";export SIMICS_BASE_PACKAGE;exec /mnt/simics/simics-4.8/simics-4.8.170/bin/vmp-kernel-load"
done
