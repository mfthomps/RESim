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

fuzz_archive=/mnt/resim_archive/fuzz/$project/$workspace
tarfile=$fuzz_archive/workspace.tar
tar -xf $tarfile
echo "Extracted workspace."
mkdir $afl_seed
mkdir $afl_output
sync_dirs=/mnt/resim_archive/fuzz/$project/$workspace/afl/output/sync_dirs.tgz
cd $afl_output
tar -xf $sync_dirs
echo "Extracted sync dirs."
cd $afl_seed
seed_dir=/mnt/resim_archive/fuzz/$project/$workspace/afl/seeds
cp $seed_dir/* .
cd $here
echo "done."

