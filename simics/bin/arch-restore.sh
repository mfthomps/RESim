#!/bin/bash
#
# restore an archived fuzzing artifact set and workspace (if archived)
#
if [ -z "$RESIM_FUZZ_ARCHIVE" ]; then
    echo "RESIM_FUZZ_ARCHIVE is not defined."
    exit
fi
if [ "$#" -ne 2 ]; then
    echo "arch-restore.sh <project> <workspace>"
    echo "   Restore a workspace and afl files from the resim archive"
    exit
fi
project=$1
workspace=$2
here=$(pwd)
base=$(basename $here)
afl_seed=$AFL_DATA/seeds/$base
afl_output=$AFL_DATA/output/$base
if [[ -d $afl_seed ]]; then
    echo "Seed directory exists at $afl_seed. Delete or move it before restoring."
    exit
fi
if [[ -d $afl_output ]]; then
    echo "Output directory exists at $afl_output. Delete or move it before restoring."
    exit
fi

fuzz_archive=$RESIM_FUZZ_ARCHIVE/$project/$workspace
tarfile=$fuzz_archive/workspace.tar
if [ -f $tarfile ]; then
    tar -xf $tarfile || exit
    echo "Extracted workspace."
fi
output_dir=$RESIM_FUZZ_ARCHIVE/$project/$workspace/afl/output
sync_dirs=$output_dir/sync_dirs.tgz
if [ ! -f $sync_dirs ]; then
    echo "No archive found at $sync_dirs"
    exit
fi
mkdir $afl_seed
mkdir $afl_output
cd $afl_output
cp $output_dir/$workspace.unique $base.unique
tar -xf $sync_dirs || exit
echo "Extracted sync dirs to $afl_output."
cd $afl_seed
seed_dir=$RESIM_FUZZ_ARCHIVE/$project/$workspace/afl/seeds
cp $seed_dir/* .
cd $here
echo "done."

