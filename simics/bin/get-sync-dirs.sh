#!/bin/bash
if [ "$#" -ne 2 ]; then
    echo "get-sync-dirs.sh <project> <workspace>"
    echo "   Retrieve a RESim workspace and AFL sync files for a given project and workspace "
    echo "   Run this from an empty directory having the workspace name."
    exit
fi
project=$1
workspace=$2
here=$(pwd)
base=$(basename $here)
if [ $base != $workspace ]; then
    echo "Must run from a directory having the workspace name."
    exit
fi
aflout=$AFL_DATA/output/$base
fuzz_archive=/mnt/resim_archive/fuzz/$1/$base
archive=$fuzz_archive/afl/output/sync_dirs.tgz
mkdir -p $aflout
tar -C $aflout -xf $archive

workspace_dest=$fuzz_archive/workspace.tgz
tar -xf $workspace_dest
