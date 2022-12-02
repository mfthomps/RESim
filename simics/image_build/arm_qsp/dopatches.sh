#!/bin/bash
export qspdir=$RESIM_DIR/simics/image_build/arm_qsp/arm_qsp_patches
dirlist=$(find $qspdir/package/* -type d)
cd package
for d in $dirlist; do
	base=$(basename $d)
	cp $qspdir/package/$base/* $base/
done
cd ..
cp $qspdir/board/* board/windriver/qsp-arm/
