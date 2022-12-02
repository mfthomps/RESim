PATCH=$qspdir/timeconst.patch
patch -p1 $PATCH || exit 1
echo "applied $PATCH"
