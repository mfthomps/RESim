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
do_workspace=YES
if [ "$#" -eq 2 ] && [ "$1" = "-n" ]; then
    do_workspace=NO
    echo "will skip workspace"
    shift 1
fi
if [ "$#" -ne 1 ] || [ "$1" = "-h" ]; then
    echo "arch-tars.sh [-n] <project>"
    echo "   Archive workspace and sync folders to the resim_archive under a given project name"
    echo "   All data will be in a subdirectory having the workspace name. "
    echo "   Use -n to skip archive of workspace itself."
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
unique=$base.unique
cp $aflout/$unique $destination/
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
echo "now in $(pwd)"
manual=$(ls | grep "manual_")
tar -czf $destination/sync_dirs.tgz *_resim_* $manual
echo "finished tar to $destination"
cd $here
aflseed=$AFL_DATA/seeds/$base
seed_dest=$fuzz_archive/afl/seeds
mkdir -p $seed_dest
cp -a $aflseed/* $seed_dest/

if [ "$do_workspace" = "YES" ]; then
    echo "archive workspace.  Note failure likely unless a merged checkpoint is referenced" 
    workspace_dest=$fuzz_archive/workspace.tar
    tar --exclude=linux64/doc-index --exclude=logs --exclude='*.tgz' -cvf /tmp/workspace.tar .
    echo "tar done now copy"
    #cp /tmp/workspace.tar $workspace_dest
    echo "done copy of archive to $workspace_dest"
fi
