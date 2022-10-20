TARGET_ARCH=arm
PATCH=M4-1.4.17_glibc_2.28.patch
    git apply -p1 ../$PATCH
    echo Patched with $PATCH

