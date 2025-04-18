#!/bin/bash
#
#  Archive fuzzing artifacts and workspace files.
#
if [ -z "$RESIM_FUZZ_ARCHIVE" ]; then
    echo "RESIM_FUZZ_ARCHIVE is not defined."
    exit
fi
if [ ! -f drones.txt ]; then
   echo "No drones.txt file found, archiving local finds."
   flist=""
else
   flist=$(cat drones.txt)
fi
if [ "$#" -ne 1 ] || [ "$1" = "-h" ]; then
    echo "arch-tars.sh <project>"
    echo "   Archive workspace and sync folders to the resim_archive under a given project name"
    echo "   All data will be in a subdirectory having the workspace name."
    exit
fi
if [ ! -d .workspace-properties ] && [ ! -d .project-properties ]; then
    echo "This does not look like a Simics workspace."
    exit
fi
here=$(pwd)
base=$(basename $here)
aflout=$AFL_DATA/output/$base
fuzz_archive=$RESIM_FUZZ_ARCHIVE/$1/$base
destination=$fuzz_archive/afl/output
mkdir -p $destination
#
#  Sync each drone's queues into this master queue.
#
echo "do sync"
for f in $flist; do
    echo "Get sync dir from $f"
    #ssh $USER@$f -o StrictHostKeyChecking=no bash -c "cd .;cd $aflout && tar -czf - $f_resim*/[qf]*" >/tmp/host_$f.tgz
    ssh $USER@$f -o StrictHostKeyChecking=no bash -c "cd .;cd $aflout && tar -czf - $f_resim*/[qf]* $f_resim*/[cf]*" >/tmp/host_$f.tgz
    tar -C $aflout -xf /tmp/host_$f.tgz 
done
echo "done sync"
#
#  Then tar all the local queues to the archive
#
echo "create tar"
here=$(pwd)
cd $aflout
tar -czf $destination/sync_dirs.tgz *_resim_* manual_queue manual_coverage manual_trackio
echo "finished tar"
cd $here
aflseed=$AFL_DATA/seeds/$base
seed_dest=$fuzz_archive/afl/seeds
mkdir -p $seed_dest
cp -a $aflseed/* $seed_dest/

echo "archive workspace"
workspace_dest=$fuzz_archive/workspace.tar
tar --exclude=logs --exclude='*.tgz' ---exclude=linux64/doc-index -cvf /tmp/workspace.tar .
echo "tar done now copy"
cp /tmp/workspace.tar $workspace_dest
echo "done copy of archive to $workspace_dest"
