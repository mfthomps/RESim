#!/bin/bash
#
# Create an image.itb containing the kernel and dtb from
# RESIM_IMAGE and a given ram disk
# Run from directory into which you want the itb to be copied
#
set -e
if [ "$#" -ne 1 ]; then
    echo "re_mk_itb.sh ramdisk"
    exit
fi
here=$(pwd)
initrd=$1
IMAGE_DIR=$RESIM_IMAGE/fvp_arm_imagesJun26/
kernel=$IMAGE_DIR/Image
dtb=$IMAGE_DIR/foundation-v8-gicv3-psci.dtb

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
cp image.itb $here
echo "Combined kernel/dtb/ramdisk in $here/image.itb"
