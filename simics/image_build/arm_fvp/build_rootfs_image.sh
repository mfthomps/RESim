#!/bin/bash
fs_dir=$1
tmp_dir=/tmp/$USER/rootfs_images
sudo rm -fr $tmp_dir
mkdir -p $tmp_dir
cd $fs_dir
find . | sudo cpio -H newc -o > $tmp_dir/ramdisk.cpio
cd $tmp_dir
mkimage -A arm64 -T ramdisk -C none -a 0x84000000 -e 0x84000000 -n "RAMDisk Image" -d ramdisk.cpio ramdisk.img
echo "ram disk image at $tmp_dir/ramdisk.img"

