#!/bin/bash
#
# Create an image.itb containing the kernel, dtb and ram disk
#
set -e
if [ "$#" -ne 1 ]; then
    echo "mk_itb.sh ramdisk"
    exit
fi
initrd=$1
WORK_DIR=$(realpath ./fvp_foundation_workspace)
kernel=$WORK_DIR/output/Image
# Assumes renaming of dtb via build_kernel.sh
dtb=$WORK_DIR/output/foundation.dtb

tmpdir=/tmp/$USER/itb
echo "will work in $tmpdir"
rm -fr $tmpdir
mkdir -p $tmpdir

cp $initrd $tmpdir/initrd
cp $kernel $tmpdir/
cp $dtb $tmpdir/
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cp $SCRIPT_DIR/kernel.its $tmpdir/
cd $tmpdir
mkimage -f kernel.its image.itb
echo "Combined kernel/dtb/ramdisk in $tmpdir/image.itb"
