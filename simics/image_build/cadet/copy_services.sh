#!/bin/bash
source_dir=$RESIM_IMAGE/cgc-images/fs
workdir=/tmp/$USER/cgc
stagedir=$workdir/stage
rm -fr $workdir
mkdir -p $stagedir
cp -r $source_dir/usr $stagedir
mkdir $stagedir/etc
cp $source_dir/etc/services $stagedir/etc/
mkdir $stagedir/etc/xinetd.d
cp $source_dir/etc/xinetd.d/* $stagedir/etc/xinetd.d/
here=$(pwd)
cd $stagedir
tar czf $workdir/services.tar *
cd $here
scp -P 2222 $workdir/services.tar localhost:/tmp/
scp -P 2222 install_services.sh localhost:/tmp/
ssh -p 2222 localhost "sudo /tmp/install_services.sh"
