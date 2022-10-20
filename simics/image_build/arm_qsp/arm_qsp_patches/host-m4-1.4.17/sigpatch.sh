TARGET_ARCH=arm
PATCH=0003-c-stack-stop-using-SIGSTKSZ.patch
    git apply -p1 ../$PATCH
    echo Patched with $PATCH

