qspdir=$RESIM_DIR/simics/image_build/ppc_qsp
cp $qspdir/qsp*.patch .
cp $qspdir/pkgconf.patch .
cp $qspdir/Config.patch .
cp $qspdir/dopatches.sh .
$qspdir/qsp_buildroot.sh
