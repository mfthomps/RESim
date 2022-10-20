TARGET_ARCH=arm
PATCH=Bison-3.0.4_glibc_2.28.patch
    git apply -p1 ../$PATCH
    echo Patched with $PATCH

