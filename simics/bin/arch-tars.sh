#!/bin/bash
if [ ! -f drones.txt ]; then
   echo "No drones.txt file found"
   exit
fi
if [ "$#" -ne 1 ]; then
    echo "arch-tars.sh <project>"
    echo "   Archive workspace and sync folders to the resim_archive under a given project name"
    echo "   All data will be in a subdirectory having the workspace name."
    exit
fi
if [ ! -d .workspace-properties ]; then
    echo "This does not look like a Simics workspace."
    exit
fi
flist=$(cat drones.txt)
here=$(pwd)
base=$(basename $here)
aflout=$AFL_DATA/output/$base
fuzz_archive=/mnt/resim_archive/fuzz/$1/$base
destination=$fuzz_archive/afl/output
mkdir -p $destination
#
#  Sync each drone's queues into this master queue.
#
for f in $flist; do
    echo "Get sync dir from $f"
    ssh $USER@$f -o StrictHostKeyChecking=no bash -c "cd .;cd $aflout && tar -czf - $f_resim*/[qf]*" >/tmp/host_$f.tgz
    tar -C $aflout -xf /tmp/host_$f.tgz 
done
#
#  Then tar all the local queues to the archive
#
here=$(pwd)
cd $aflout
tar -czf $destination/sync_dirs.tgz *_resim_* 
cd $here
aflseed=$AFL_DATA/seeds/$base
seed_dest=$fuzz_archive/afl/seeds
mkdir -p $seed_dest
cp -a $aflseed/* $seed_dest/

workspace_dest=$fuzz_archive/workspace.tgz
tar -czf $workspace_dest . --exclude=logs --exclude='*.tgz'
