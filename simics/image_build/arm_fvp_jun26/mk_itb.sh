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
kernel=/eems_images/fvp_foundation_workspace/output/Image
# Assumes renaming of dtb via build_kernel.sh
dtb=/eems_images/fvp_foundation_workspace/output/foundation.dtb

tmpdir=/tmp/$USER/itb
echo "will work in $tmpdir"
rm -fr $tmpdir
mkdir -p $tmpdir

cp $initrd $tmpdir/
cp $kernel $tmpdir/
cp $dtb $tmpdir/
cp kernel.its $tmpdir/
cd $tmpdir
mkimage -f kernel.its image.itb
echo "Combined kernel/dtb/ramdisk in $tmpdir/image.itb"
