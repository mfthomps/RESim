#!/bin/bash
if [ ! -f drones.txt ]; then
   echo "No drones.txt file found"
   exit
fi
if [ "$#" -ne 1 ]; then
    echo "arch-tars.sh <destination>"
    echo "   Archive workspace and sync folders to the resim_archive under a given project name"
    echo "   All data will be in a subdirectory having the workspace name."
    exit
fi
if [ ! -d .workspace-properties ]; then
    echo "This does not look like a Simics workspace."
    exit
fi
flist=$(cat drones.txt)
flist=$flist" "$HOSTNAME
here=$(pwd)
base=$(basename $here)
fuzz_archive=/mnt/resim_archive/fuzz/$1/$base
destination=$fuzz_archive/afl/output
mkdir -p $destination
aflout=$AFL_DATA/output/$base
for f in $flist; do
    echo "Get sync dir from $f"
    ssh $USER@$f -o StrictHostKeyChecking=no bash -c "cd .;cd $aflout;tar -czf - $f_resim*/[qf]*" >$destination/host_$f.tgz
done

aflseed=$AFL_DATA/seeds/$base
seed_dest=$fuzz_archive/afl/seeds
mkdir -p $seed_dest
cp -a $aflseed/* $seed_dest/

workspace_dest=$fuzz_archive/workspace.tgz
tar -czf $workspace_dest . --exclude=logs --exclude='*.tgz'
